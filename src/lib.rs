//! Fast, bounded signature searches in loaded Windows PE modules.
//!
//! The 0.3 API separates a module snapshot from a search query. A query does
//! not touch memory until `first()` or `all()` is called, so section and range
//! constraints are applied before the scanner starts.
//!
//! ```ignore
//! use sigmatch::{Result, Seeker};
//!
//! fn locate(seeker: &Seeker) -> Result<usize> {
//!     let hit = seeker
//!         .scan("48 8D 15 ?? ?? ?? ??")?
//!         .in_section(".text")
//!         .first()?;
//!     Ok(hit.address())
//! }
//! ```

#![warn(missing_docs)]

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
compile_error!("sigmatch supports only x86 and x86_64 targets");

use std::{collections::HashMap, fmt, ops::Range, ptr, sync::Arc};

#[cfg(target_arch = "x86")]
use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_NT_HEADERS32, IMAGE_NT_OPTIONAL_HDR32_MAGIC,
};
#[cfg(target_arch = "x86_64")]
use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR64_MAGIC,
};
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{FreeLibrary, HMODULE},
        System::{
            Diagnostics::Debug::IMAGE_SECTION_HEADER,
            LibraryLoader::{GetModuleHandleExW, GetModuleHandleW},
            Memory::{VirtualQuery, MEMORY_BASIC_INFORMATION},
            SystemInformation::{GetSystemInfo, SYSTEM_INFO},
            SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE},
        },
    },
};

mod error;
mod page_protection;

pub use error::{Error, Result};
use page_protection::region_is_readable;

/// Search direction. A backward query treats its start as the high end of the
/// inclusive scan window, which makes `backward_from(address)` useful when the
/// address is the end of an instruction or basic block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Search from low addresses to high.
    Forward,
    /// Search from high addresses to low.
    Backward,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Forward => f.write_str("forward"),
            Self::Backward => f.write_str("backward"),
        }
    }
}

/// A loaded PE section range. The end address is exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Section {
    /// Address of the first byte of the section in the loaded module.
    pub section_base: usize,
    /// Section length in bytes. The loader can map more than the raw data
    /// holds, so this is the larger of `VirtualSize` and `SizeOfRawData`.
    pub section_size: usize,
}

impl Section {
    /// End address, or `None` when base plus size overflows `usize`.
    pub fn end(self) -> Option<usize> {
        self.section_base.checked_add(self.section_size)
    }

    /// Section as `base..end`, or `None` when the end overflows.
    pub fn range(self) -> Option<Range<usize>> {
        Some(self.section_base..self.end()?)
    }

    /// True when `address` is inside the section.
    pub fn contains(self, address: usize) -> bool {
        self.end()
            .is_some_and(|end| address >= self.section_base && address < end)
    }

    /// True when the `length` bytes starting at `address` fit inside the
    /// section.
    pub fn contains_range(self, address: usize, length: usize) -> bool {
        address >= self.section_base
            && address
                .checked_add(length)
                .is_some_and(|end| end <= self.end().unwrap_or(0))
    }
}

/// A parsed byte pattern. `1` in the mask means an exact byte; `0` is a
/// wildcard. Patterns are immutable and can be reused by multiple queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    bytes: Arc<[u8]>,
    mask: Arc<[u8]>,
    anchor: Option<(usize, u8)>,
}

impl Pattern {
    /// Parse an IDA/x64dbg-style signature. `?` and `??` each represent one
    /// wildcard byte. Parsing is strict: malformed tokens are rejected.
    pub fn signature(signature: &str) -> Result<Self> {
        let mut bytes = Vec::new();
        let mut mask = Vec::new();
        for token in signature.split_whitespace() {
            if token == "?" || token == "??" {
                bytes.push(0);
                mask.push(0);
                continue;
            }
            if token.len() != 2 {
                return Err(Error::InvalidSignatureToken(token.to_string()));
            }
            let byte = u8::from_str_radix(token, 16)
                .map_err(|_| Error::InvalidSignatureToken(token.to_string()))?;
            bytes.push(byte);
            mask.push(1);
        }
        Self::from_parts(bytes, mask)
    }

    /// Build an exact byte pattern.
    pub fn bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_parts(bytes.to_vec(), vec![1; bytes.len()])
    }

    /// Build a C-style byte/mask pattern. `x` matches and `?` is a wildcard.
    pub fn masked(bytes: &[u8], mask: &str) -> Result<Self> {
        let mask: Vec<u8> = mask
            .chars()
            .map(|value| match value {
                'x' | 'X' => Ok(1),
                '?' => Ok(0),
                other => Err(Error::InvalidMaskCharacter(other)),
            })
            .collect::<Result<_>>()?;
        if bytes.len() != mask.len() {
            return Err(Error::InvalidPattern {
                pattern_len: bytes.len(),
                mask_len: mask.len(),
            });
        }
        Self::from_parts(bytes.to_vec(), mask)
    }

    /// Build a pattern from a bit mask. Bit `i` describes byte `i`.
    pub fn bitmap(bytes: &[u8], bitmap: usize) -> Result<Self> {
        if bytes.len() > usize::BITS as usize {
            return Err(Error::PatternExceedsBitmapSize(
                bytes.len(),
                usize::BITS as usize,
            ));
        }
        let mask = (0..bytes.len())
            .map(|index| u8::from(((bitmap >> index) & 1) != 0))
            .collect();
        Self::from_parts(bytes.to_vec(), mask)
    }

    /// Number of bytes in the pattern, wildcards included.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Always `false`. `from_parts` rejects empty patterns, so this only
    /// exists to satisfy `clippy::len_without_is_empty`.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn from_parts(bytes: Vec<u8>, mask: Vec<u8>) -> Result<Self> {
        if bytes.is_empty() || bytes.len() != mask.len() {
            return Err(Error::InvalidPattern {
                pattern_len: bytes.len(),
                mask_len: mask.len(),
            });
        }
        let anchor = mask
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, &exact)| (exact != 0).then_some((index, bytes[index])));
        Ok(Self {
            bytes: bytes.into(),
            mask: mask.into(),
            anchor,
        })
    }

    /// Compare at `address` without checking readability.
    ///
    /// # Safety
    /// `address..address + self.len()` must contain initialized, readable bytes
    /// that remain valid and are not concurrently modified during the call.
    unsafe fn compare(&self, address: usize) -> bool {
        if let Some((index, byte)) = self.anchor {
            let Some(anchor_address) = address.checked_add(index) else {
                return false;
            };
            let value = unsafe { ptr::read_unaligned(anchor_address as *const u8) };
            if value != byte {
                return false;
            }
        }
        self.bytes
            .iter()
            .zip(self.mask.iter())
            .enumerate()
            .all(|(index, (&byte, &exact))| {
                exact == 0
                    || address.checked_add(index).is_some_and(|address| unsafe {
                        ptr::read_unaligned(address as *const u8) == byte
                    })
            })
    }

    fn matches(&self, reader: &ReadContext, address: usize) -> bool {
        // SAFETY: The page cache validates the entire span before comparison;
        // the scan requires the underlying memory to remain valid.
        reader.range_readable(address, self.len()) && unsafe { self.compare(address) }
    }
}

/// Values accepted by `Seeker::scan` and `ReferenceQuery::matching`.
pub trait IntoPattern {
    /// Parse or convert the value. Each query calls this once.
    fn into_pattern(self) -> Result<Pattern>;
}

impl IntoPattern for Pattern {
    fn into_pattern(self) -> Result<Pattern> {
        Ok(self)
    }
}

impl IntoPattern for &Pattern {
    fn into_pattern(self) -> Result<Pattern> {
        Ok(self.clone())
    }
}

impl IntoPattern for &str {
    fn into_pattern(self) -> Result<Pattern> {
        Pattern::signature(self)
    }
}

impl IntoPattern for String {
    fn into_pattern(self) -> Result<Pattern> {
        Pattern::signature(&self)
    }
}

#[derive(Debug)]
struct ModuleLease {
    handle: HMODULE,
    owned: bool,
}

impl ModuleLease {
    fn acquire(name: &str) -> Result<Self> {
        if name == "main" {
            let handle = unsafe { GetModuleHandleW(PCWSTR::null()) }
                .map_err(|_| Error::GetModuleHandleFailed(name.to_string()))?;
            if handle.is_invalid() {
                return Err(Error::GetModuleHandleFailed(name.to_string()));
            }
            return Ok(Self {
                handle,
                owned: false,
            });
        }

        let wide = name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let module_name = PCWSTR(wide.as_ptr());
        let mut handle = HMODULE::default();
        unsafe { GetModuleHandleExW(0, module_name, &mut handle) }
            .map_err(|_| Error::GetModuleHandleFailed(name.to_string()))?;
        if handle.is_invalid() {
            return Err(Error::GetModuleHandleFailed(name.to_string()));
        }
        Ok(Self {
            handle,
            owned: true,
        })
    }

    fn base(&self) -> usize {
        self.handle.0 as usize
    }
}

impl Drop for ModuleLease {
    fn drop(&mut self) {
        if self.owned {
            let _ = unsafe { FreeLibrary(self.handle) };
        }
    }
}

#[derive(Debug)]
struct ModuleSnapshot {
    _lease: ModuleLease,
    name: String,
    base: usize,
    size: usize,
    end: usize,
    sections: HashMap<String, Section>,
}

/// Search entry point bound to one loaded module.
#[derive(Debug)]
pub struct Seeker {
    module: Option<ModuleSnapshot>,
    page_size: usize,
}

impl Seeker {
    /// Create a seeker with no module attached. Call `bind` or `with_name`
    /// before running a query.
    pub fn new() -> Self {
        Self {
            module: None,
            page_size: system_page_size(),
        }
    }

    /// Bind to a loaded module by name. `"main"` means the main executable.
    pub fn with_name(name: &str) -> Result<Self> {
        let mut seeker = Self::new();
        seeker.bind(name)?;
        Ok(seeker)
    }

    /// Rebind this seeker to a loaded module. Queries borrow the seeker, so a
    /// rebind cannot invalidate an active query.
    pub fn bind(&mut self, name: &str) -> Result<&mut Self> {
        let lease = ModuleLease::acquire(name)?;
        let base = lease.base();
        let (size, sections) = unsafe { parse_module(base, name) }?;
        let end = base
            .checked_add(size)
            .ok_or_else(|| Error::ModuleSizeZero(name.to_string()))?;
        if size == 0 {
            return Err(Error::ModuleSizeZero(name.to_string()));
        }
        self.module = Some(ModuleSnapshot {
            _lease: lease,
            name: name.to_string(),
            base,
            size,
            end,
            sections,
        });
        Ok(self)
    }

    /// Base address of the bound module, or 0 when nothing is bound.
    pub fn module_base(&self) -> usize {
        self.module.as_ref().map_or(0, |module| module.base)
    }

    /// Image size from the PE optional header, or 0 when nothing is bound.
    pub fn module_size(&self) -> usize {
        self.module.as_ref().map_or(0, |module| module.size)
    }

    /// Exclusive module end address.
    pub fn module_end(&self) -> usize {
        self.module.as_ref().map_or(0, |module| module.end)
    }

    /// Base and end of the bound module, or `None` when nothing is bound.
    pub fn module_range(&self) -> Option<Range<usize>> {
        self.module.as_ref().map(|module| module.base..module.end)
    }

    /// Name passed to `bind`, or an empty string when nothing is bound.
    pub fn module_name(&self) -> String {
        self.module
            .as_ref()
            .map_or_else(String::new, |module| module.name.clone())
    }

    /// Copy of the section table, keyed by the name in the PE header.
    pub fn sections(&self) -> HashMap<String, Section> {
        self.module
            .as_ref()
            .map_or_else(HashMap::new, |module| module.sections.clone())
    }

    /// Construct a lazy pattern query. No memory is read until a terminal
    /// method (`first` or `all`) is called.
    pub fn scan<P: IntoPattern>(&self, pattern: P) -> Result<Scan<'_>> {
        self.ensure_module()?;
        Ok(Scan {
            seeker: self,
            pattern: pattern.into_pattern()?,
            scope: Scope::Module,
            direction: Direction::Forward,
            start: None,
            within: None,
        })
    }

    /// One-shot section-bounded lookup for the common case.
    pub fn find_in<P: IntoPattern>(&self, section: &str, pattern: P) -> Result<Match> {
        self.scan(pattern)?.in_section(section).first()
    }

    /// Locate a NUL-terminated narrow string in one section.
    ///
    /// Returns the **first** occurrence. When the literal appears more than
    /// once, [`strings`](Self::strings) enumerates all of them.
    pub fn string(&self, value: &str, section: &str) -> Result<StringMatch<'_>> {
        self.strings(value, section)?
            .next()
            .ok_or(Error::PatternNotFound)
    }

    /// Locate every occurrence of a NUL-terminated narrow string in one
    /// section, in ascending address order.
    ///
    /// Anchoring the first occurrence is wrong whenever the referenced
    /// occurrence is not the first one, and that happens in practice: a data
    /// section can hold the same literal twice (a name string shared by two
    /// functions) while only one of them is the operand of the instruction
    /// being looked for. Iterating lets the caller pick the occurrence that
    /// matters and hand it to [`StringMatch::refs_in`].
    pub fn strings(&self, value: &str, section: &str) -> Result<StringMatches<'_>> {
        if value.as_bytes().contains(&0) {
            return Err(Error::InvalidString);
        }
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        let matches = self
            .scan(Pattern::bytes(&bytes)?)?
            .in_section(section)
            .all()?;
        Ok(StringMatches {
            seeker: self,
            matches,
        })
    }

    fn ensure_module(&self) -> Result<&ModuleSnapshot> {
        self.module.as_ref().ok_or(Error::Uninitialized)
    }
}

impl Default for Seeker {
    fn default() -> Self {
        Self::new()
    }
}

/// A lazy byte-pattern query. Configuration methods consume and return the
/// query, making it impossible for one query's range to leak into another.
pub struct Scan<'a> {
    seeker: &'a Seeker,
    pattern: Pattern,
    scope: Scope,
    direction: Direction,
    start: Option<usize>,
    within: Option<usize>,
}

#[derive(Debug, Clone)]
enum Scope {
    Module,
    Section(String),
}

impl<'a> Scan<'a> {
    /// Limit the query to one section. The name has to match the PE section
    /// header, and an unknown name makes the query fail with
    /// `SectionNotFound`.
    pub fn in_section(mut self, name: impl Into<String>) -> Self {
        self.scope = Scope::Section(name.into());
        self
    }

    /// Start at `start` and move toward higher addresses. Without this call a
    /// forward query starts at the section or module base.
    pub fn forward_from(mut self, start: usize) -> Self {
        self.direction = Direction::Forward;
        self.start = Some(start);
        self
    }

    /// `start` is the inclusive high end of the backward window. A pattern
    /// may therefore end exactly at `start`.
    pub fn backward_from(mut self, start: usize) -> Self {
        self.direction = Direction::Backward;
        self.start = Some(start);
        self
    }

    /// Restrict the scan window to this many bytes from the configured start.
    pub fn within(mut self, bytes: usize) -> Self {
        self.within = Some(bytes);
        self
    }

    /// Run the query and return the first match, or `PatternNotFound`.
    pub fn first(self) -> Result<Match> {
        let mut matches = self.all()?;
        matches.next().ok_or(Error::PatternNotFound)
    }

    /// Run the query and return every match in scan order.
    pub fn all(self) -> Result<Matches<'a>> {
        let prepared = self.prepare(self.pattern.len())?;
        Ok(Matches {
            pattern: self.pattern,
            iter: CandidateIter::new(prepared),
            _marker: std::marker::PhantomData,
        })
    }

    fn prepare(&self, required_len: usize) -> Result<PreparedScan> {
        if required_len == 0 {
            return Err(Error::InvalidPattern {
                pattern_len: 0,
                mask_len: 0,
            });
        }
        let module = self.seeker.ensure_module()?;
        let (source_low, source_high) = match &self.scope {
            Scope::Module => (module.base, module.end),
            Scope::Section(name) => {
                let section = module
                    .sections
                    .get(name)
                    .ok_or_else(|| Error::SectionNotFound(name.clone()))?;
                (
                    section.section_base,
                    section
                        .end()
                        .ok_or_else(|| Error::SectionOutOfBounds(name.clone()))?,
                )
            }
        };
        let range = resolve_bounds(
            source_low,
            source_high,
            self.direction,
            self.start,
            self.within,
            required_len,
        )?;
        let readable_high =
            range
                .high
                .checked_add(required_len)
                .ok_or(Error::SearchLengthTooShort {
                    length: 0,
                    pattern: required_len,
                })?;
        let reader = Arc::new(ReadContext::new(
            module.base,
            module.end,
            self.seeker.page_size,
            range.low,
            readable_high,
        )?);
        Ok(PreparedScan {
            runs: readable_runs(&reader, range.low, range.high).into(),
            direction: range.direction,
            reader,
        })
    }
}

/// A single byte-pattern match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Match {
    /// Address of the first byte of the match.
    pub address: usize,
}

impl Match {
    /// Address of the match.
    pub fn address(self) -> usize {
        self.address
    }
}

/// Iterator over every match. Results arrive in the order the query scans,
/// so a backward query yields descending addresses.
pub struct Matches<'a> {
    pattern: Pattern,
    iter: CandidateIter,
    _marker: std::marker::PhantomData<&'a Seeker>,
}

impl Iterator for Matches<'_> {
    type Item = Match;

    fn next(&mut self) -> Option<Self::Item> {
        let len = self.pattern.len();
        while let Some((address, run)) = self.iter.next_address() {
            let hit = if self.iter.span_is_readable(run, address, len) {
                // SAFETY: The candidate belongs to this readable run and its
                // entire pattern fits before the run's limit.
                unsafe { self.pattern.compare(address) }
            } else {
                self.pattern.matches(&self.iter.reader, address)
            };
            if hit {
                return Some(Match { address });
            }
        }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CandidateRange {
    low: usize,
    high: usize,
    direction: Direction,
}

fn resolve_bounds(
    source_low: usize,
    source_high: usize,
    direction: Direction,
    start: Option<usize>,
    within: Option<usize>,
    required_len: usize,
) -> Result<CandidateRange> {
    if source_low >= source_high {
        return Err(Error::SearchLengthTooShort {
            length: 0,
            pattern: required_len,
        });
    }
    let start = match direction {
        Direction::Forward => start.unwrap_or(source_low),
        Direction::Backward => start.unwrap_or(source_high - 1),
    };
    if start < source_low || start >= source_high {
        return Err(Error::SearchStartOutOfRange {
            start,
            low: source_low,
            high: source_high - 1,
            direction,
        });
    }

    let (window_low, window_high) = match direction {
        Direction::Forward => {
            let high = within
                .map(|bytes| start.saturating_add(bytes).min(source_high))
                .unwrap_or(source_high);
            (start, high)
        }
        Direction::Backward => {
            let low = within
                .map(|bytes| {
                    start
                        .saturating_add(1)
                        .saturating_sub(bytes)
                        .max(source_low)
                })
                .unwrap_or(source_low);
            (low, start + 1)
        }
    };
    let window_len = window_high.saturating_sub(window_low);
    if window_len < required_len {
        return Err(Error::SearchLengthTooShort {
            length: window_len,
            pattern: required_len,
        });
    }
    Ok(CandidateRange {
        low: window_low,
        high: window_high - required_len,
        direction,
    })
}

struct PreparedScan {
    runs: Arc<[Run]>,
    direction: Direction,
    reader: Arc<ReadContext>,
}

/// A stretch of candidate addresses whose bytes are readable, plus the first
/// address past the readable bytes. A pattern that ends at or before `limit`
/// can be compared without asking the page cache again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Run {
    low: usize,
    high: usize,
    limit: usize,
}

struct CandidateIter {
    current: Option<usize>,
    /// Bounds of the run holding `current`, copied out so the per-candidate
    /// check reads a register instead of going through the slice.
    run: Run,
    index: usize,
    runs: Arc<[Run]>,
    direction: Direction,
    reader: Arc<ReadContext>,
}

impl CandidateIter {
    fn new(prepared: PreparedScan) -> Self {
        let (index, run, current) = match prepared.direction {
            Direction::Forward => match prepared.runs.first() {
                Some(run) => (0, *run, Some(run.low)),
                None => (
                    0,
                    Run {
                        low: 0,
                        high: 0,
                        limit: 0,
                    },
                    None,
                ),
            },
            Direction::Backward => {
                let index = prepared.runs.len().saturating_sub(1);
                match prepared.runs.last() {
                    Some(run) => (index, *run, Some(run.high)),
                    None => (
                        0,
                        Run {
                            low: 0,
                            high: 0,
                            limit: 0,
                        },
                        None,
                    ),
                }
            }
        };
        Self {
            current,
            run,
            index,
            runs: prepared.runs,
            direction: prepared.direction,
            reader: prepared.reader,
        }
    }

    /// Yield the next candidate with the run it belongs to. The run travels
    /// with the address because stepping past the end of a run switches
    /// `self.run` before the call returns, and the span check must use the run
    /// that actually holds `address`.
    fn next_address(&mut self) -> Option<(usize, Run)> {
        let address = self.current?;
        let run = self.run;
        let at_end = match self.direction {
            Direction::Forward => address >= self.run.high,
            Direction::Backward => address <= self.run.low,
        };
        self.current = if at_end {
            match self.direction {
                Direction::Forward => {
                    self.index += 1;
                    self.runs.get(self.index).map(|run| {
                        self.run = *run;
                        run.low
                    })
                }
                Direction::Backward => {
                    if self.index == 0 {
                        None
                    } else {
                        self.index -= 1;
                        self.run = self.runs[self.index];
                        Some(self.run.high)
                    }
                }
            }
        } else {
            match self.direction {
                Direction::Forward => address.checked_add(1),
                Direction::Backward => address.checked_sub(1),
            }
        };
        Some((address, run))
    }

    /// True when `len` bytes starting at `address` stay inside the readable
    /// stretch of `run`.
    fn span_is_readable(&self, run: Run, address: usize, len: usize) -> bool {
        address.checked_add(len).is_some_and(|end| end <= run.limit)
    }
}

/// Group the candidate window into stretches of readable pages. `low` and
/// `high` are candidate addresses, so a run is clipped to them while `limit`
/// keeps the end of the last readable page, which is what the span check needs.
fn readable_runs(reader: &ReadContext, low: usize, high: usize) -> Vec<Run> {
    let mut runs = Vec::new();
    let mut open: Option<Run> = None;
    let mut page_low = align_down(low, reader.page_size);
    loop {
        let page_high = page_low.saturating_add(reader.page_size - 1);
        if reader.page_readable(page_low) {
            let run_low = page_low.max(low);
            let run_high = page_high.min(high);
            let limit = page_high.saturating_add(1);
            match open {
                Some(mut run) if run.high.checked_add(1) == Some(run_low) => {
                    run.high = run_high;
                    run.limit = limit;
                    open = Some(run);
                }
                _ => {
                    if let Some(run) = open.take() {
                        runs.push(run);
                    }
                    open = Some(Run {
                        low: run_low,
                        high: run_high,
                        limit,
                    });
                }
            }
        } else if let Some(run) = open.take() {
            runs.push(run);
        }
        match page_high.checked_add(1) {
            Some(next) if page_high < high => page_low = next,
            _ => break,
        }
    }
    if let Some(run) = open {
        runs.push(run);
    }
    runs
}

fn allocation_matches(info: &MEMORY_BASIC_INFORMATION, module_base: usize) -> bool {
    info.AllocationBase as usize == module_base
}

fn next_region_end(info: &MEMORY_BASIC_INFORMATION, current: usize) -> Option<usize> {
    let region_base = info.BaseAddress as usize;
    let region_end = region_base.checked_add(info.RegionSize)?;
    if current < region_base || region_end <= current {
        None
    } else {
        Some(region_end)
    }
}

fn query_region(address: usize) -> Option<MEMORY_BASIC_INFORMATION> {
    let mut info = MEMORY_BASIC_INFORMATION::default();
    let queried = unsafe {
        VirtualQuery(
            Some(address as *const _),
            &mut info,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if queried == 0 {
        None
    } else {
        Some(info)
    }
}

fn range_has_allocation(
    address: usize,
    length: usize,
    allocation_base: usize,
    require_readable: bool,
) -> bool {
    if length == 0 {
        return false;
    }
    let Some(end) = address.checked_add(length) else {
        return false;
    };
    let mut current = address;
    while current < end {
        let Some(info) = query_region(current) else {
            return false;
        };
        if !allocation_matches(&info, allocation_base)
            || (require_readable && !region_is_readable(&info))
        {
            return false;
        }
        let Some(region_end) = next_region_end(&info, current) else {
            return false;
        };
        if region_end >= end {
            return true;
        }
        current = region_end;
    }
    true
}

fn range_is_readable_in_allocation(address: usize, length: usize, allocation_base: usize) -> bool {
    range_has_allocation(address, length, allocation_base, true)
}

#[derive(Debug, Clone)]
struct ReadContext {
    module_base: usize,
    module_end: usize,
    page_base: usize,
    page_size: usize,
    page_shift: u32,
    readable: Arc<[bool]>,
}

impl ReadContext {
    fn new(
        module_base: usize,
        module_end: usize,
        requested_page_size: usize,
        range_low: usize,
        range_high: usize,
    ) -> Result<Self> {
        let page_size = if requested_page_size.is_power_of_two() && requested_page_size > 0 {
            requested_page_size
        } else {
            4096
        };
        let page_base = align_down(range_low, page_size);
        let count = page_count(range_low, range_high, page_size);
        // Page state is fully resolved before scanning starts. Never fall back
        // to VirtualQuery from the candidate iterator: that would turn a
        // linear byte scan into an OS-call-heavy operation.
        const MAX_CACHED_PAGES: usize = 1 << 20;
        if count > MAX_CACHED_PAGES {
            return Err(Error::SearchRangeTooLarge { pages: count });
        }
        let mut readable = vec![false; count];
        let mut index = 0usize;
        let mut current = page_base;
        while index < count {
            let Some(info) = query_region(current) else {
                break;
            };
            let Some(region_end) = next_region_end(&info, current) else {
                break;
            };
            let span = region_end.saturating_sub(page_base);
            let next_index = span
                .checked_div(page_size)
                .and_then(|pages| pages.checked_add(usize::from(span % page_size != 0)))
                .unwrap_or(count)
                .min(count)
                .max(index + 1);
            if region_is_readable(&info) {
                readable[index..next_index].fill(true);
            }
            index = next_index;
            current = region_end;
        }
        Ok(Self {
            module_base,
            module_end,
            page_base,
            page_size,
            page_shift: page_size.trailing_zeros(),
            readable: readable.into(),
        })
    }

    fn page_index(&self, address: usize) -> Option<usize> {
        let index = address.checked_sub(self.page_base)? >> self.page_shift;
        (index < self.readable.len()).then_some(index)
    }

    fn page_readable(&self, address: usize) -> bool {
        self.page_index(address)
            .and_then(|index| self.readable.get(index).copied())
            .unwrap_or(false)
    }

    fn range_readable(&self, address: usize, length: usize) -> bool {
        if length == 0 || address < self.module_base {
            return false;
        }
        let Some(end) = address.checked_add(length) else {
            return false;
        };
        if end > self.module_end {
            return false;
        }
        let first_page = align_down(address, self.page_size);
        let last_page = align_down(end - 1, self.page_size);
        let mut page = first_page;
        loop {
            if !self.page_readable(page) {
                return false;
            }
            if page == last_page {
                return true;
            }
            let Some(next) = page.checked_add(self.page_size) else {
                return false;
            };
            page = next;
        }
    }

    fn read_i32(&self, address: usize) -> Option<i32> {
        self.range_readable(address, 4)
            .then(|| unsafe { ptr::read_unaligned(address as *const i32) })
    }

    fn read_u32(&self, address: usize) -> Option<u32> {
        self.range_readable(address, 4)
            .then(|| unsafe { ptr::read_unaligned(address as *const u32) })
    }
}

fn align_down(address: usize, page_size: usize) -> usize {
    address & !(page_size - 1)
}

fn page_count(range_low: usize, range_high: usize, page_size: usize) -> usize {
    if page_size == 0 || range_low >= range_high {
        return 0;
    }
    let first_page = align_down(range_low, page_size);
    let last_page = align_down(range_high - 1, page_size);
    last_page
        .checked_sub(first_page)
        .and_then(|span| span.checked_div(page_size))
        .and_then(|pages| pages.checked_add(1))
        .unwrap_or(0)
}

/// How a matched instruction encodes its target address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceEncoding {
    /// x86-64 RIP-relative memory operand: next instruction + signed rel32.
    X64RipRel32 {
        /// Offset of the rel32 field from the start of the instruction.
        displacement_offset: usize,
        /// Length of the whole instruction in bytes.
        instruction_size: usize,
    },
    /// x86/x64 relative branch or call: next instruction + signed rel32.
    Rel32 {
        /// Offset of the rel32 field from the start of the instruction.
        displacement_offset: usize,
        /// Length of the whole instruction in bytes.
        instruction_size: usize,
    },
    /// x86 absolute 32-bit operand.
    X86Abs32 {
        /// Offset of the operand from the start of the instruction.
        operand_offset: usize,
    },
}

impl ReferenceEncoding {
    fn required_len(self, pattern_len: usize) -> Result<usize> {
        match self {
            Self::X64RipRel32 {
                displacement_offset,
                instruction_size,
            }
            | Self::Rel32 {
                displacement_offset,
                instruction_size,
            } => {
                let displacement_end =
                    displacement_offset
                        .checked_add(4)
                        .ok_or(Error::InvalidReferenceEncoding {
                            field_offset: displacement_offset,
                            instruction_size,
                        })?;
                if displacement_end > pattern_len || instruction_size < displacement_end {
                    return Err(Error::InvalidReferenceEncoding {
                        field_offset: displacement_offset,
                        instruction_size,
                    });
                }
                Ok(pattern_len.max(instruction_size))
            }
            Self::X86Abs32 { operand_offset } => {
                let operand_end =
                    operand_offset
                        .checked_add(4)
                        .ok_or(Error::InvalidReferenceEncoding {
                            field_offset: operand_offset,
                            instruction_size: 0,
                        })?;
                if operand_end > pattern_len {
                    return Err(Error::InvalidReferenceEncoding {
                        field_offset: operand_offset,
                        instruction_size: 0,
                    });
                }
                Ok(pattern_len)
            }
        }
    }

    fn resolve(self, address: usize, reader: &ReadContext) -> Option<usize> {
        match self {
            Self::X64RipRel32 {
                displacement_offset,
                instruction_size,
            }
            | Self::Rel32 {
                displacement_offset,
                instruction_size,
            } => {
                let displacement = reader.read_i32(address.checked_add(displacement_offset)?)?;
                relative_target(address, instruction_size, displacement)
            }
            Self::X86Abs32 { operand_offset } => reader
                .read_u32(address.checked_add(operand_offset)?)
                .map(|target| target as usize),
        }
    }
}

/// A string found in a data section. It can be used as the target of a
/// reference query without carrying mutable state in `Seeker`.
#[derive(Debug, Clone, Copy)]
pub struct StringMatch<'a> {
    seeker: &'a Seeker,
    address: usize,
}

impl<'a> StringMatch<'a> {
    /// Address of the matched string.
    pub fn address(self) -> usize {
        self.address
    }

    /// Search `section` for instructions whose operand points at this string.
    pub fn refs_in(self, section: &str) -> ReferenceQuery<'a> {
        ReferenceQuery {
            seeker: self.seeker,
            target: self.address,
            section: section.to_string(),
            pattern: None,
            encoding: None,
        }
    }
}

/// Every occurrence of a string in one section, in ascending address order.
/// Each item starts its own reference query.
pub struct StringMatches<'a> {
    seeker: &'a Seeker,
    matches: Matches<'a>,
}

impl<'a> Iterator for StringMatches<'a> {
    type Item = StringMatch<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let found = self.matches.next()?;
        Some(StringMatch {
            seeker: self.seeker,
            address: found.address(),
        })
    }
}

/// A reference search. It scans one section for instructions whose operand
/// resolves to a fixed target address.
pub struct ReferenceQuery<'a> {
    seeker: &'a Seeker,
    target: usize,
    section: String,
    pattern: Option<Result<Pattern>>,
    encoding: Option<ReferenceEncoding>,
}

impl<'a> ReferenceQuery<'a> {
    /// Configure the candidate instruction pattern. Parsing is deferred until
    /// `first()` or `all()` so configuration remains a fluent, lazy operation.
    pub fn matching<P: IntoPattern>(mut self, pattern: P) -> Self {
        self.pattern = Some(pattern.into_pattern());
        self
    }

    /// Set the decoder that turns a candidate instruction into a target
    /// address. A query without one fails with `MissingReferenceEncoding`.
    pub fn using(mut self, encoding: ReferenceEncoding) -> Self {
        self.encoding = Some(encoding);
        self
    }

    /// Run the query and return the first reference, or `PatternNotFound`.
    pub fn first(self) -> Result<Reference> {
        let mut refs = self.all()?;
        refs.next().ok_or(Error::PatternNotFound)
    }

    /// Run the query and return every reference that resolves to the target.
    pub fn all(self) -> Result<References<'a>> {
        let pattern = self.pattern.ok_or(Error::MissingReferencePattern)??;
        let encoding = self.encoding.ok_or(Error::MissingReferenceEncoding)?;
        let required_len = encoding.required_len(pattern.len())?;
        let scan = self.seeker.scan(pattern)?.in_section(self.section);
        let prepared = scan.prepare(required_len)?;
        Ok(References {
            matches: Matches {
                pattern: scan.pattern,
                iter: CandidateIter::new(prepared),
                _marker: std::marker::PhantomData,
            },
            target: self.target,
            encoding,
        })
    }
}

/// An instruction that points at the queried target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reference {
    /// Address of the instruction.
    pub address: usize,
    /// Address the instruction resolves to.
    pub target: usize,
}

impl Reference {
    /// Address of the instruction.
    pub fn address(self) -> usize {
        self.address
    }

    /// Address the instruction resolves to.
    pub fn target(self) -> usize {
        self.target
    }
}

/// Iterator over the references that matched the target.
pub struct References<'a> {
    matches: Matches<'a>,
    target: usize,
    encoding: ReferenceEncoding,
}

impl Iterator for References<'_> {
    type Item = Reference;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(candidate) = self.matches.next() {
            let Some(target) = self
                .encoding
                .resolve(candidate.address, &self.matches.iter.reader)
            else {
                continue;
            };
            if target == self.target {
                return Some(Reference {
                    address: candidate.address,
                    target,
                });
            }
        }
        None
    }
}

fn relative_target(address: usize, instruction_size: usize, displacement: i32) -> Option<usize> {
    let next = address.checked_add(instruction_size)?;
    if displacement >= 0 {
        next.checked_add(displacement as usize)
    } else {
        next.checked_sub((-(displacement as i64)) as usize)
    }
}

unsafe fn parse_module(base: usize, name: &str) -> Result<(usize, HashMap<String, Section>)> {
    if !range_is_readable_in_allocation(base, std::mem::size_of::<IMAGE_DOS_HEADER>(), base) {
        return Err(Error::InvalidDosHeader(name.to_string()));
    }
    let dos = base as *const IMAGE_DOS_HEADER;
    let dos_header = ptr::read_unaligned(dos);
    if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
        return Err(Error::InvalidDosHeader(name.to_string()));
    }
    let nt_offset = usize::try_from(dos_header.e_lfanew)
        .map_err(|_| Error::InvalidNtHeader(name.to_string()))?;

    #[cfg(target_arch = "x86_64")]
    type NtHeaders = IMAGE_NT_HEADERS64;
    #[cfg(target_arch = "x86")]
    type NtHeaders = IMAGE_NT_HEADERS32;

    let nt_address = base
        .checked_add(nt_offset)
        .ok_or_else(|| Error::InvalidNtHeader(name.to_string()))?;
    if !range_is_readable_in_allocation(nt_address, std::mem::size_of::<NtHeaders>(), base) {
        return Err(Error::InvalidNtHeader(name.to_string()));
    }
    let nt = nt_address as *const NtHeaders;
    let nt_headers = ptr::read_unaligned(nt);
    #[cfg(target_arch = "x86_64")]
    let expected_optional_magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    #[cfg(target_arch = "x86")]
    let expected_optional_magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    let optional_header_size =
        std::mem::size_of::<NtHeaders>() - std::mem::offset_of!(NtHeaders, OptionalHeader);
    if nt_headers.Signature != IMAGE_NT_SIGNATURE
        || nt_headers.OptionalHeader.Magic != expected_optional_magic
        || usize::from(nt_headers.FileHeader.SizeOfOptionalHeader) < optional_header_size
    {
        return Err(Error::InvalidNtHeader(name.to_string()));
    }
    let size = nt_headers.OptionalHeader.SizeOfImage as usize;
    if size == 0 {
        return Err(Error::ModuleSizeZero(name.to_string()));
    }
    let section_header_address = base
        .checked_add(nt_offset)
        .and_then(|value| value.checked_add(std::mem::offset_of!(NtHeaders, OptionalHeader)))
        .and_then(|value| value.checked_add(nt_headers.FileHeader.SizeOfOptionalHeader as usize))
        .ok_or_else(|| Error::SectionOutOfBounds(name.to_string()))?;
    let module_end = base
        .checked_add(size)
        .ok_or_else(|| Error::ModuleSizeZero(name.to_string()))?;
    if !range_has_allocation(base, size, base, false) {
        return Err(Error::InvalidNtHeader(name.to_string()));
    }
    let section_count = nt_headers.FileHeader.NumberOfSections as usize;
    let section_table_size = section_count
        .checked_mul(std::mem::size_of::<IMAGE_SECTION_HEADER>())
        .ok_or_else(|| Error::SectionOutOfBounds(name.to_string()))?;
    let section_table_end = section_header_address
        .checked_add(section_table_size)
        .ok_or_else(|| Error::SectionOutOfBounds(name.to_string()))?;
    let nt_end = nt_address
        .checked_add(std::mem::size_of::<NtHeaders>())
        .ok_or_else(|| Error::InvalidNtHeader(name.to_string()))?;
    if nt_address < base
        || nt_end > module_end
        || section_header_address < base
        || section_table_end > module_end
        || !range_is_readable_in_allocation(section_header_address, section_table_size, base)
    {
        return Err(Error::SectionOutOfBounds(name.to_string()));
    }
    let section_header = section_header_address as *const IMAGE_SECTION_HEADER;
    let mut sections = HashMap::new();
    for index in 0..section_count {
        let section = ptr::read_unaligned(section_header.add(index));
        let section_name = String::from_utf8_lossy(&section.Name)
            .trim_end_matches('\0')
            .to_string();
        let section_base = base
            .checked_add(section.VirtualAddress as usize)
            .ok_or_else(|| Error::SectionOutOfBounds(section_name.clone()))?;
        let virtual_size = section.Misc.VirtualSize as usize;
        let section_size = virtual_size.max(section.SizeOfRawData as usize);
        let section_end = section_base
            .checked_add(section_size)
            .ok_or_else(|| Error::SectionOutOfBounds(section_name.clone()))?;
        if section_base < base || section_end > module_end {
            return Err(Error::SectionOutOfBounds(section_name));
        }
        sections.insert(
            section_name,
            Section {
                section_base,
                section_size,
            },
        );
    }
    Ok((size, sections))
}

fn system_page_size() -> usize {
    let mut info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    unsafe { GetSystemInfo(&mut info) };
    let size = info.dwPageSize as usize;
    if size.is_power_of_two() && size > 0 {
        size
    } else {
        4096
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Memory::{
        VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
        PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
    };

    struct TestPages {
        base: usize,
        size: usize,
        page_size: usize,
        blocked: Vec<bool>,
    }

    impl TestPages {
        fn new(pages: usize) -> Self {
            let page_size = system_page_size();
            let size = page_size.checked_mul(pages).expect("test allocation size");
            let base = unsafe {
                VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) as usize
            };
            assert_ne!(base, 0, "VirtualAlloc failed");
            Self {
                base,
                size,
                page_size,
                blocked: vec![false; pages],
            }
        }

        fn fill_page(&mut self, index: usize, byte: u8) {
            assert!(index < self.size / self.page_size);
            assert!(!self.blocked[index], "cannot write to a blocked test page");
            // SAFETY: The owned page is in bounds and remains writable.
            unsafe {
                ptr::write_bytes(
                    (self.base + index * self.page_size) as *mut u8,
                    byte,
                    self.page_size,
                );
            }
        }

        fn write(&mut self, bytes: &[u8]) {
            assert_eq!(bytes.len(), self.size);
            assert!(self.blocked.iter().all(|&blocked| !blocked));
            // SAFETY: The source length matches the writable owned allocation.
            unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), self.base as *mut u8, self.size) };
        }

        fn block_page(&mut self, index: usize) {
            assert!(index < self.size / self.page_size);
            let mut previous = PAGE_PROTECTION_FLAGS(0);
            unsafe {
                VirtualProtect(
                    (self.base + index * self.page_size) as *const _,
                    self.page_size,
                    PAGE_NOACCESS,
                    &mut previous,
                )
            }
            .expect("protect test page");
            self.blocked[index] = true;
        }
    }

    impl Drop for TestPages {
        fn drop(&mut self) {
            // SAFETY: This is the base of the allocation owned by this guard.
            unsafe { VirtualFree(self.base as *mut _, 0, MEM_RELEASE) }
                .expect("release test pages");
        }
    }

    fn reader_for(bytes: &mut [u8]) -> ReadContext {
        let base = bytes.as_mut_ptr() as usize;
        let end = base + bytes.len();
        let page_size = 4096;
        let page_base = align_down(base, page_size);
        let count = page_count(base, end, page_size);
        ReadContext {
            module_base: base,
            module_end: end,
            page_base,
            page_size,
            page_shift: page_size.trailing_zeros(),
            readable: Arc::from(vec![true; count]),
        }
    }

    /// Layout of the fake module. `.text` starts at offset 0, `.rdata` at
    /// 2048, and each is 64 bytes. Both sit in one buffer, so they share one
    /// allocation and the same page attributes.
    const TEXT_LEN: usize = 64;
    const RDATA_OFFSET: usize = 2048;
    const RDATA_LEN: usize = 64;
    const MODULE_LEN: usize = RDATA_OFFSET + RDATA_LEN;

    /// Wrap a buffer in a `Seeker` so the range rules can be tested without
    /// loading a real target module.
    fn fake_module(bytes: &mut [u8; MODULE_LEN]) -> Seeker {
        let base = bytes.as_mut_ptr() as usize;
        let mut sections = HashMap::new();
        sections.insert(
            ".text".to_string(),
            Section {
                section_base: base,
                section_size: TEXT_LEN,
            },
        );
        sections.insert(
            ".rdata".to_string(),
            Section {
                section_base: base + RDATA_OFFSET,
                section_size: RDATA_LEN,
            },
        );
        Seeker {
            module: Some(ModuleSnapshot {
                _lease: ModuleLease {
                    handle: HMODULE::default(),
                    owned: false,
                },
                name: "test".to_string(),
                base,
                size: MODULE_LEN,
                end: base + MODULE_LEN,
                sections,
            }),
            page_size: 4096,
        }
    }

    #[test]
    fn signature_parser_is_strict_and_supports_both_wildcards() {
        let pattern = Pattern::signature("48 8D ? ?? FF").unwrap();
        assert_eq!(pattern.len(), 5);
        assert!(Pattern::signature("48 nope").is_err());
        assert!(Pattern::signature("").is_err());
    }

    #[test]
    fn raw_pattern_forms_have_explicit_masks() {
        let masked = Pattern::masked(&[1, 2, 3], "x??").unwrap();
        assert_eq!(masked.len(), 3);
        assert!(Pattern::masked(&[1], "xx").is_err());
        let bitmap = Pattern::bitmap(&[1, 2, 3], 0b101).unwrap();
        assert_eq!(bitmap.mask.as_ref(), &[1, 0, 1]);
    }

    #[test]
    fn pattern_matches_after_one_range_check() {
        let mut bytes = [0xAA, 0x10, 0xCC, 0xDD];
        let reader = reader_for(&mut bytes);
        let pattern = Pattern::signature("AA ?? CC").unwrap();
        assert!(pattern.matches(&reader, bytes.as_ptr() as usize));
        assert!(!pattern.matches(&reader, bytes.as_ptr() as usize + 1));
    }

    #[test]
    fn forward_and_backward_bounds_are_inclusive_at_the_expected_side() {
        assert_eq!(
            resolve_bounds(100, 200, Direction::Forward, Some(120), Some(10), 4).unwrap(),
            CandidateRange {
                low: 120,
                high: 126,
                direction: Direction::Forward
            }
        );
        assert_eq!(
            resolve_bounds(100, 200, Direction::Backward, Some(150), Some(10), 4).unwrap(),
            CandidateRange {
                low: 141,
                high: 147,
                direction: Direction::Backward
            }
        );
        assert!(matches!(
            resolve_bounds(100, 105, Direction::Forward, Some(100), None, 6),
            Err(Error::SearchLengthTooShort { .. })
        ));
        assert!(matches!(
            resolve_bounds(100, 105, Direction::Backward, Some(105), None, 1),
            Err(Error::SearchStartOutOfRange { .. })
        ));
        assert_eq!(
            resolve_bounds(100, 110, Direction::Forward, Some(103), Some(4), 4).unwrap(),
            CandidateRange {
                low: 103,
                high: 103,
                direction: Direction::Forward
            }
        );
        assert_eq!(
            resolve_bounds(100, 110, Direction::Backward, Some(106), Some(4), 4).unwrap(),
            CandidateRange {
                low: 103,
                high: 103,
                direction: Direction::Backward
            }
        );
        assert!(matches!(
            resolve_bounds(100, 110, Direction::Forward, Some(109), Some(1), 2),
            Err(Error::SearchLengthTooShort {
                length: 1,
                pattern: 2
            })
        ));
        assert!(matches!(
            resolve_bounds(100, 110, Direction::Forward, Some(99), None, 1),
            Err(Error::SearchStartOutOfRange { .. })
        ));
    }

    #[test]
    fn relative_target_handles_sign_and_overflow() {
        assert_eq!(relative_target(0x1000, 7, 0x20), Some(0x1027));
        assert_eq!(relative_target(0x1000, 7, -0x20), Some(0xFE7));
        assert_eq!(relative_target(usize::MAX - 2, 7, 0), None);
        assert_eq!(relative_target(0, 7, i32::MIN), None);
    }

    #[test]
    fn cross_page_ranges_are_rejected_before_bytes_are_read() {
        let mut bytes = vec![0u8; 32];
        bytes[15] = 0xAA;
        bytes[16] = 0xBB;
        let address = bytes.as_mut_ptr() as usize;
        let page_size = 16;
        let reader = ReadContext {
            module_base: address,
            module_end: address + bytes.len(),
            page_base: align_down(address, page_size),
            page_size,
            page_shift: page_size.trailing_zeros(),
            readable: Arc::from(vec![true, false]),
        };
        assert!(!reader.range_readable(address + 15, 2));
    }

    #[test]
    fn reference_encodings_use_explicit_offsets_and_sizes() {
        let mut bytes = vec![0u8; 64];
        let base = bytes.as_mut_ptr() as usize;
        let reader = reader_for(&mut bytes);

        let target = base + 32;
        let displacement = (target as isize - (base as isize + 7)) as i32;
        bytes[3..7].copy_from_slice(&displacement.to_le_bytes());
        let rip = ReferenceEncoding::X64RipRel32 {
            displacement_offset: 3,
            instruction_size: 7,
        };
        assert_eq!(rip.required_len(7).unwrap(), 7);
        assert_eq!(rip.resolve(base, &reader), Some(target));

        bytes[1..5].copy_from_slice(&(0x1234_u32).to_le_bytes());
        let absolute = ReferenceEncoding::X86Abs32 { operand_offset: 1 };
        assert_eq!(absolute.resolve(base, &reader), Some(0x1234));
        assert!(matches!(
            ReferenceEncoding::Rel32 {
                displacement_offset: 4,
                instruction_size: 8,
            }
            .required_len(7),
            Err(Error::InvalidReferenceEncoding { .. })
        ));
    }

    #[test]
    fn references_filter_targets_and_keep_query_state_explicit() {
        let mut bytes = [0x90u8; MODULE_LEN];
        let seeker = fake_module(&mut bytes);
        let base = seeker.module_base();
        let target = base + 40;
        let first_target = base + 30;
        let first_disp = (first_target as isize - (base as isize + 5)) as i32;
        bytes[0] = 0xE8;
        bytes[1..5].copy_from_slice(&first_disp.to_le_bytes());
        let target_disp = (target as isize - (base as isize + 15)) as i32;
        bytes[10] = 0xE8;
        bytes[11..15].copy_from_slice(&target_disp.to_le_bytes());

        let string = StringMatch {
            seeker: &seeker,
            address: target,
        };
        let pattern =
            string
                .refs_in(".text")
                .matching("E8 ?? ?? ?? ??")
                .using(ReferenceEncoding::Rel32 {
                    displacement_offset: 1,
                    instruction_size: 5,
                });
        let refs: Vec<_> = pattern.all().unwrap().collect();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].address(), base + 10);
        assert_eq!(refs[0].target(), target);
    }

    /// Every `call rel32` (`E8`) in `.text` whose target is `string`.
    fn calls_to(string: StringMatch<'_>) -> Vec<usize> {
        string
            .refs_in(".text")
            .matching("E8 ?? ?? ?? ??")
            .using(ReferenceEncoding::Rel32 {
                displacement_offset: 1,
                instruction_size: 5,
            })
            .all()
            .unwrap()
            .map(|reference| reference.address())
            .collect()
    }

    /// Both copies of the literal in `.rdata`, each including the trailing NUL.
    const LABEL: &[u8] = b"label\0";
    const FIRST_OFFSET: usize = 8;
    const SECOND_OFFSET: usize = 40;

    /// Write `LABEL` into both slots and return their addresses.
    fn write_labels(bytes: &mut [u8; MODULE_LEN], base: usize) -> (usize, usize) {
        let rdata = &mut bytes[RDATA_OFFSET..RDATA_OFFSET + RDATA_LEN];
        for offset in [FIRST_OFFSET, SECOND_OFFSET] {
            rdata[offset..offset + LABEL.len()].copy_from_slice(LABEL);
        }
        (
            base + RDATA_OFFSET + FIRST_OFFSET,
            base + RDATA_OFFSET + SECOND_OFFSET,
        )
    }

    /// `strings` returns both copies, `string` only the first.
    #[test]
    fn strings_enumerates_every_occurrence_in_order() {
        let mut bytes = [0x80u8; MODULE_LEN];
        let seeker = fake_module(&mut bytes);
        let (first, second) = write_labels(&mut bytes, seeker.module_base());

        let found: Vec<_> = seeker
            .strings("label", ".rdata")
            .unwrap()
            .map(StringMatch::address)
            .collect();
        assert_eq!(found, vec![first, second]);

        assert_eq!(seeker.string("label", ".rdata").unwrap().address(), first);
    }

    /// Why `strings` exists. The literal appears twice and only the second
    /// copy is referenced. `string` always anchors the first copy, so the
    /// reference query never hits: `refs_in` counts a match only when the
    /// target is exact, and the caller sees `PatternNotFound` while the real
    /// problem is the wrong copy.
    #[test]
    fn a_reference_query_can_anchor_a_later_occurrence() {
        let mut bytes = [0x80u8; MODULE_LEN];
        let seeker = fake_module(&mut bytes);
        let base = seeker.module_base();
        let (first, second) = write_labels(&mut bytes, base);

        // One `call rel32` to the second copy: an `E8` at `.text` offset 4.
        // Nothing references the first copy.
        let call_site = base + 4;
        let displacement = (second as isize - (call_site as isize + 5)) as i32;
        bytes[4] = 0xE8;
        bytes[5..9].copy_from_slice(&displacement.to_le_bytes());

        assert_eq!(seeker.string("label", ".rdata").unwrap().address(), first);
        assert!(calls_to(seeker.string("label", ".rdata").unwrap()).is_empty());

        let last = seeker.strings("label", ".rdata").unwrap().last().unwrap();
        assert_eq!(last.address(), second);
        assert_eq!(calls_to(last), vec![call_site]);
    }

    #[test]
    fn page_count_includes_the_last_partial_page_without_overflow() {
        assert_eq!(page_count(0x1001, 0x1FFF, 0x1000), 1);
        assert_eq!(page_count(0x1001, 0x2001, 0x1000), 2);
        assert_eq!(page_count(usize::MAX - 3, usize::MAX, 0x1000), 1);
        assert_eq!(page_count(10, 10, 0x1000), 0);
    }

    #[test]
    fn readable_protections_accept_only_readable_base_flags() {
        use windows::Win32::System::Memory::{
            PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
            PAGE_GUARD, PAGE_NOCACHE, PAGE_READONLY, PAGE_WRITECOPY,
        };

        let mut info = MEMORY_BASIC_INFORMATION {
            State: MEM_COMMIT,
            ..Default::default()
        };
        for protection in [
            PAGE_READONLY,
            PAGE_READWRITE,
            PAGE_WRITECOPY,
            PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE,
            PAGE_EXECUTE_WRITECOPY,
        ] {
            info.Protect = protection;
            assert!(region_is_readable(&info));
            info.Protect = protection | PAGE_NOCACHE;
            assert!(region_is_readable(&info));
            info.Protect = protection | PAGE_GUARD;
            assert!(!region_is_readable(&info));
        }
        for protection in [PAGE_NOACCESS, PAGE_EXECUTE, PAGE_PROTECTION_FLAGS(0)] {
            info.Protect = protection;
            assert!(!region_is_readable(&info));
        }
    }

    #[test]
    fn readable_regions_must_be_committed() {
        let mut info = MEMORY_BASIC_INFORMATION {
            State: MEM_RESERVE,
            Protect: PAGE_READWRITE,
            ..Default::default()
        };
        assert!(!region_is_readable(&info));
        info.State = MEM_COMMIT;
        assert!(region_is_readable(&info));
    }

    /// Address only, for tests that do not care which run it came from.
    fn next_candidate_address(iter: &mut CandidateIter) -> Option<usize> {
        iter.next_address().map(|(address, _)| address)
    }

    fn reader_with_pages(base: usize, page_size: usize, readable: Vec<bool>) -> ReadContext {
        ReadContext {
            module_base: base,
            module_end: base + page_size * readable.len(),
            page_base: base,
            page_size,
            page_shift: page_size.trailing_zeros(),
            readable: readable.into(),
        }
    }

    #[test]
    fn candidate_iterator_stops_at_the_last_valid_candidate() {
        let mut bytes = [0u8; 16];
        let reader = Arc::new(reader_for(&mut bytes));
        let runs: Arc<[Run]> = vec![Run {
            low: 10,
            high: 12,
            limit: 16,
        }]
        .into();
        let mut forward = CandidateIter::new(PreparedScan {
            runs: runs.clone(),
            direction: Direction::Forward,
            reader: reader.clone(),
        });
        assert_eq!(next_candidate_address(&mut forward), Some(10));
        assert_eq!(next_candidate_address(&mut forward), Some(11));
        assert_eq!(next_candidate_address(&mut forward), Some(12));
        assert_eq!(next_candidate_address(&mut forward), None);

        let mut backward = CandidateIter::new(PreparedScan {
            runs,
            direction: Direction::Backward,
            reader,
        });
        assert_eq!(next_candidate_address(&mut backward), Some(12));
        assert_eq!(next_candidate_address(&mut backward), Some(11));
        assert_eq!(next_candidate_address(&mut backward), Some(10));
        assert_eq!(next_candidate_address(&mut backward), None);
    }

    /// A blocked page sits between the two runs. Going forward the iterator
    /// has to resume on the first address of the next run, going backward on
    /// the last address of the previous one, or it drops a candidate.
    #[test]
    fn candidate_iterator_jumps_between_runs_without_dropping_one() {
        let mut bytes = [0u8; 16];
        let reader = Arc::new(reader_for(&mut bytes));
        let runs: Arc<[Run]> = vec![
            Run {
                low: 10,
                high: 12,
                limit: 16,
            },
            Run {
                low: 20,
                high: 21,
                limit: 32,
            },
        ]
        .into();

        let mut forward = CandidateIter::new(PreparedScan {
            runs: runs.clone(),
            direction: Direction::Forward,
            reader: reader.clone(),
        });
        let forward_addresses: Vec<_> =
            std::iter::from_fn(|| next_candidate_address(&mut forward)).collect();
        assert_eq!(forward_addresses, vec![10, 11, 12, 20, 21]);

        let mut backward = CandidateIter::new(PreparedScan {
            runs,
            direction: Direction::Backward,
            reader,
        });
        let backward_addresses: Vec<_> =
            std::iter::from_fn(|| next_candidate_address(&mut backward)).collect();
        assert_eq!(backward_addresses, vec![21, 20, 12, 11, 10]);
    }

    #[test]
    fn span_check_uses_the_end_of_the_last_readable_page() {
        let mut bytes = [0u8; 16];
        let reader = Arc::new(reader_for(&mut bytes));
        let run = Run {
            low: 10,
            high: 12,
            limit: 16,
        };
        let iter = CandidateIter::new(PreparedScan {
            runs: vec![run].into(),
            direction: Direction::Forward,
            reader,
        });
        // A four byte pattern still fits before the limit.
        assert!(iter.span_is_readable(run, 12, 4));
        // One more byte would cross it.
        assert!(!iter.span_is_readable(run, 12, 5));
    }

    /// The last candidate of a run is yielded together with that run, not with
    /// the run the iterator has already moved on to. Using the next run's limit
    /// here would let a pattern read across the blocked page in between.
    #[test]
    fn a_candidate_keeps_the_run_it_belongs_to() {
        let mut bytes = [0u8; 64];
        let reader = Arc::new(reader_for(&mut bytes));
        let first = Run {
            low: 10,
            high: 12,
            limit: 16,
        };
        let second = Run {
            low: 20,
            high: 21,
            limit: 64,
        };
        let mut iter = CandidateIter::new(PreparedScan {
            runs: vec![first, second].into(),
            direction: Direction::Forward,
            reader,
        });
        assert_eq!(iter.next_address(), Some((10, first)));
        assert_eq!(iter.next_address(), Some((11, first)));
        assert_eq!(iter.next_address(), Some((12, first)));
        assert_eq!(iter.next_address(), Some((20, second)));
        assert_eq!(iter.next_address(), Some((21, second)));
        assert_eq!(iter.next_address(), None);
    }

    /// Four pages, the middle two blocked, a start that is not page aligned and
    /// an end that stops inside the last page.
    #[test]
    fn readable_runs_clip_to_the_window_and_keep_the_page_limit() {
        let base = 0x1000;
        let reader = reader_with_pages(base, 16, vec![true, false, false, true]);
        let runs = readable_runs(&reader, base + 4, base + 3 * 16 + 5);
        assert_eq!(
            runs,
            vec![
                Run {
                    low: base + 4,
                    high: base + 15,
                    limit: base + 16
                },
                Run {
                    low: base + 3 * 16,
                    high: base + 3 * 16 + 5,
                    limit: base + 4 * 16
                },
            ]
        );
    }

    #[test]
    fn readable_runs_collapse_adjacent_readable_pages() {
        let base = 0x1000;
        let reader = reader_with_pages(base, 16, vec![true, true, true]);
        let runs = readable_runs(&reader, base + 1, base + 47);
        assert_eq!(
            runs,
            vec![Run {
                low: base + 1,
                high: base + 47,
                limit: base + 48
            }]
        );
    }

    /// Walks the same window with and without blocked pages and checks that
    /// the iterator yields exactly the candidates a brute-force walk would.
    #[test]
    fn iterator_yields_exactly_the_readable_candidates() {
        let base = 0x1000;
        let page = 16;
        let layout = vec![true, false, true, true, false, true];
        let reader = Arc::new(reader_with_pages(base, page, layout.clone()));
        let low = base + 3;
        let high = base + page * layout.len() - 5;
        let expected: Vec<usize> = (low..=high)
            .filter(|&address| reader.page_readable(address))
            .collect();

        let runs = readable_runs(&reader, low, high);
        let mut iter = CandidateIter::new(PreparedScan {
            runs: runs.into(),
            direction: Direction::Forward,
            reader: reader.clone(),
        });
        let forward: Vec<usize> =
            std::iter::from_fn(|| next_candidate_address(&mut iter)).collect();
        assert_eq!(forward, expected);

        let runs = readable_runs(&reader, low, high);
        let mut iter = CandidateIter::new(PreparedScan {
            runs: runs.into(),
            direction: Direction::Backward,
            reader,
        });
        let mut backward: Vec<usize> =
            std::iter::from_fn(|| next_candidate_address(&mut iter)).collect();
        backward.reverse();
        assert_eq!(backward, expected);
    }

    /// Four real pages, the second one PAGE_NOACCESS and filled with a byte
    /// that would match if anything read it. Reaching it faults the process,
    /// so this fails loudly rather than returning a wrong address.
    #[test]
    fn blocked_page_is_never_read() {
        let mut allocation = TestPages::new(4);
        let (base, size, page) = (allocation.base, allocation.size, allocation.page_size);
        allocation.fill_page(0, 0xAA);
        allocation.fill_page(1, 0xAA);
        allocation.fill_page(3, 0xAA);
        allocation.block_page(1);

        let reader = Arc::new(
            ReadContext::new(base, base + size, page, base, base + size)
                .expect("page cache for the buffer"),
        );
        let runs = readable_runs(&reader, base, base + size - 1);
        let mut matches = Matches {
            pattern: Pattern::bytes(&[0xAA]).unwrap(),
            iter: CandidateIter::new(PreparedScan {
                runs: runs.into(),
                direction: Direction::Forward,
                reader,
            }),
            _marker: std::marker::PhantomData,
        };
        let hits: Vec<usize> = std::iter::from_fn(|| matches.next().map(Match::address)).collect();

        assert_eq!(hits.len(), page * 2, "pages 0 and 3 are the only matches");
        assert!(hits
            .iter()
            .all(|&address| address < base + page || address >= base + 3 * page));
    }

    /// A pattern that starts near the end of a readable page must not be
    /// compared when its last byte would land in the blocked page behind it.
    #[test]
    fn a_span_crossing_into_a_blocked_page_is_rejected() {
        let mut allocation = TestPages::new(2);
        let (base, size, page) = (allocation.base, allocation.size, allocation.page_size);
        allocation.fill_page(0, 0xAA);
        allocation.block_page(1);

        let reader = Arc::new(
            ReadContext::new(base, base + size, page, base, base + size)
                .expect("page cache for the buffer"),
        );
        let runs = readable_runs(&reader, base, base + size - 1);
        let mut matches = Matches {
            pattern: Pattern::bytes(&[0xAA, 0xAA, 0xAA, 0xAA]).unwrap(),
            iter: CandidateIter::new(PreparedScan {
                runs: runs.into(),
                direction: Direction::Forward,
                reader,
            }),
            _marker: std::marker::PhantomData,
        };
        let hits: Vec<usize> = std::iter::from_fn(|| matches.next().map(Match::address)).collect();

        // Page 0 is solid `0xAA`, so every four-byte window that stays inside it
        // matches: starts `base ..= base + page - 4`.
        let last = base + page - 4;
        assert_eq!(
            hits.len(),
            page - 3,
            "every four-byte window in page 0 matches"
        );
        assert_eq!(hits.first().copied(), Some(base));
        assert_eq!(hits.last().copied(), Some(last));
        assert!(
            !hits.contains(&(last + 1)),
            "a start whose fourth byte lands in the blocked page must be rejected"
        );
    }

    /// The last candidate of the first run is followed by a second run whose
    /// limit sits much further away. The span check must use the first run's
    /// limit there, otherwise the compare reads the blocked page in between.
    #[test]
    fn a_match_never_reads_across_a_blocked_page_between_runs() {
        let mut allocation = TestPages::new(3);
        let (base, size, page) = (allocation.base, allocation.size, allocation.page_size);
        allocation.fill_page(0, 0xAA);
        allocation.fill_page(2, 0xAA);
        allocation.block_page(1);

        let reader = Arc::new(
            ReadContext::new(base, base + size, page, base, base + size)
                .expect("page cache for the buffer"),
        );
        let runs = readable_runs(&reader, base, base + size - 1);
        assert_eq!(
            runs.len(),
            2,
            "two readable stretches around the blocked page"
        );
        let mut matches = Matches {
            pattern: Pattern::bytes(&[0xAA, 0xAA, 0xAA, 0xAA]).unwrap(),
            iter: CandidateIter::new(PreparedScan {
                runs: runs.into(),
                direction: Direction::Forward,
                reader,
            }),
            _marker: std::marker::PhantomData,
        };
        let hits: Vec<usize> = std::iter::from_fn(|| matches.next().map(Match::address)).collect();

        assert_eq!(hits.len(), 2 * (page - 3), "both readable pages match");
        assert!(hits.iter().all(|&address| {
            (address + 4 <= base + page)
                || (address >= base + 2 * page && address + 4 <= base + size)
        }));
    }

    #[test]
    fn a_fully_blocked_window_yields_nothing() {
        let base = 0x1000;
        let reader = Arc::new(reader_with_pages(base, 16, vec![false, false]));
        let runs = readable_runs(&reader, base, base + 31);
        assert!(runs.is_empty());
        let mut iter = CandidateIter::new(PreparedScan {
            runs: runs.into(),
            direction: Direction::Forward,
            reader,
        });
        assert_eq!(next_candidate_address(&mut iter), None);
    }

    /// Deterministic pseudo-random generator, so the layout, the bytes and the
    /// pattern all move between rounds without pulling in a dependency.
    struct SmallRng(u64);

    impl SmallRng {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 33
        }

        fn below(&mut self, bound: usize) -> usize {
            (self.next() % bound as u64) as usize
        }
    }

    /// Randomized differential check over a real allocation: random readable
    /// layout, random bytes, random wildcard pattern, random window and both
    /// directions. The scanner must report exactly the true matches a
    /// brute-force walk finds, once each, in scan order.
    #[test]
    fn randomized_layouts_agree_with_a_brute_force_walk() {
        let mut rng = SmallRng(0x5EED_1234_ABCD_9876);
        for round in 0..32 {
            let pages = 3 + rng.below(4);
            let mut allocation = TestPages::new(pages);
            let (base, size, page) = (allocation.base, allocation.size, allocation.page_size);

            // A two-byte alphabet keeps exact patterns matching often enough
            // for a round to be interesting.
            let mut bytes = vec![0u8; size];
            for byte in bytes.iter_mut() {
                *byte = if rng.next() & 1 == 0 { 0xAA } else { 0xBB };
            }
            allocation.write(&bytes);

            let mut readable = vec![true; pages];
            let blocked = 1 + rng.below(pages / 2 + 1);
            let mut placed = 0;
            while placed < blocked {
                let index = rng.below(pages);
                if readable[index] {
                    readable[index] = false;
                    placed += 1;
                }
            }
            for (index, &open) in readable.iter().enumerate() {
                if open {
                    continue;
                }
                allocation.block_page(index);
            }

            let len = 1 + rng.below(6);
            let mut pattern_bytes = vec![0u8; len];
            let mut mask = String::with_capacity(len);
            for byte in pattern_bytes.iter_mut() {
                *byte = if rng.next() & 1 == 0 { 0xAA } else { 0xBB };
                mask.push(if rng.next().is_multiple_of(3) {
                    '?'
                } else {
                    'x'
                });
            }
            let pattern = Pattern::masked(&pattern_bytes, &mask).expect("valid mask");

            let low = base + rng.below(size - len + 1);
            let high = low + rng.below(base + size - len - low + 1);
            let reader = Arc::new(
                ReadContext::new(base, base + size, page, low, high + len)
                    .expect("page cache for the buffer"),
            );

            let expected: Vec<usize> = (low..=high)
                .filter(|&address| {
                    (0..len).all(|index| readable[(address - base + index) / page])
                        && (0..len).all(|index| {
                            mask.as_bytes()[index] == b'?'
                                || unsafe {
                                    *((address + index) as *const u8) == pattern_bytes[index]
                                }
                        })
                })
                .collect();

            for direction in [Direction::Forward, Direction::Backward] {
                let mut matches = Matches {
                    pattern: pattern.clone(),
                    iter: CandidateIter::new(PreparedScan {
                        runs: readable_runs(&reader, low, high).into(),
                        direction,
                        reader: reader.clone(),
                    }),
                    _marker: std::marker::PhantomData,
                };
                let hits: Vec<usize> =
                    std::iter::from_fn(|| matches.next().map(Match::address)).collect();
                let mut sorted = hits.clone();
                sorted.sort_unstable();
                assert_eq!(
                    sorted, expected,
                    "round {round}: {direction:?} over {low:#x}..={high:#x}, \
                     {blocked} blocked page(s), pattern {mask}"
                );
                let ordered = if direction == Direction::Forward {
                    hits.windows(2).all(|pair| pair[0] < pair[1])
                } else {
                    hits.windows(2).all(|pair| pair[0] > pair[1])
                };
                assert!(ordered, "round {round}: {direction:?} order");
            }
        }
    }

    #[test]
    fn long_patterns_respect_blocked_pages_and_cached_run_limits() {
        let mut allocation = TestPages::new(5);
        let (base, size, page) = (allocation.base, allocation.size, allocation.page_size);
        for index in 0..5 {
            allocation.fill_page(index, 0xAA);
        }
        allocation.block_page(2);

        for len in [page + 3, 2 * page + 1] {
            let pattern = Pattern::bytes(&vec![0xAA; len]).unwrap();
            for (low, high) in [
                (base + page - 8, base + page - 4),
                (base + page - 8, base + page + 8),
                (base + 3 * page - 4, base + 3 * page + 4),
            ] {
                if high + len > base + size {
                    continue;
                }
                let reader =
                    Arc::new(ReadContext::new(base, base + size, page, low, high + len).unwrap());
                let expected: Vec<_> = (low..=high)
                    .filter(|&address| {
                        let first = (address - base) / page;
                        let last = (address - base + len - 1) / page;
                        (first..=last).all(|index| !allocation.blocked[index])
                    })
                    .collect();
                for direction in [Direction::Forward, Direction::Backward] {
                    let matches = Matches {
                        pattern: pattern.clone(),
                        iter: CandidateIter::new(PreparedScan {
                            runs: readable_runs(&reader, low, high).into(),
                            direction,
                            reader: reader.clone(),
                        }),
                        _marker: std::marker::PhantomData,
                    };
                    let hits: Vec<_> = matches.map(Match::address).collect();
                    let mut expected = expected.clone();
                    if direction == Direction::Backward {
                        expected.reverse();
                    }
                    assert_eq!(
                        hits, expected,
                        "{direction:?}, len={len}, {low:#x}..={high:#x}"
                    );
                }
            }
        }
    }

    /// The same differential check against a real loaded section, so the page
    /// cache comes from the loader's layout instead of a hand-built one.
    #[test]
    fn text_section_scan_agrees_with_a_brute_force_walk() {
        let seeker = Seeker::with_name("main").expect("bind the test executable");
        let sections = seeker.sections();
        let text = sections.get(".text").expect("the executable has .text");
        let len = 6usize;
        assert!(text.section_size > len * 2, ".text must hold the probe");
        let probe = text.section_base + text.section_size / 2;
        let bytes = unsafe { std::slice::from_raw_parts(probe as *const u8, len) };
        let pattern = Pattern::bytes(bytes).expect("probe pattern");
        let hits: Vec<usize> = seeker
            .scan(&pattern)
            .expect("scan")
            .in_section(".text")
            .all()
            .expect("all")
            .map(Match::address)
            .collect();
        assert!(hits.contains(&probe), "the probe address must be reported");

        let module = seeker.ensure_module().expect("module");
        let reader = Arc::new(
            ReadContext::new(
                module.base,
                module.end,
                seeker.page_size,
                text.section_base,
                text.section_base + text.section_size,
            )
            .expect("page cache for .text"),
        );
        let high = text.section_base + text.section_size - len;
        let expected: Vec<usize> = (text.section_base..=high)
            .filter(|&address| {
                // SAFETY: The checked span is in the test executable's code,
                // which remains loaded and unchanged throughout this test.
                reader.range_readable(address, len) && unsafe { pattern.compare(address) }
            })
            .collect();
        assert_eq!(hits, expected);
    }

    /// Time candidate iteration over precomputed runs with synthetic page maps.
    /// This excludes run construction, page queries and pattern comparison.
    /// Run with `cargo test --release -- --ignored --nocapture blocked_pages`.
    #[test]
    #[ignore = "timing harness, prints numbers instead of asserting"]
    fn blocked_pages_reduce_candidate_iteration_work() {
        fn time(runs: Vec<Run>, reader: Arc<ReadContext>) -> (usize, std::time::Duration) {
            let mut iter = CandidateIter::new(PreparedScan {
                runs: runs.into(),
                direction: Direction::Forward,
                reader,
            });
            let start = std::time::Instant::now();
            let mut count = 0usize;
            while next_candidate_address(&mut iter).is_some() {
                count += 1;
            }
            (count, start.elapsed())
        }

        let page = 4096;
        let pages = 512;
        let base = 0x1000_0000usize;
        let low = base;
        let high = base + page * pages - 16;

        let reader = |readable: Vec<bool>| {
            Arc::new(ReadContext {
                module_base: base,
                module_end: base + page * pages,
                page_base: base,
                page_size: page,
                page_shift: page.trailing_zeros(),
                readable: readable.into(),
            })
        };

        let all_open = reader(vec![true; pages]);
        let (all_count, all_time) = time(readable_runs(&all_open, low, high), all_open);

        let mut half = vec![true; pages];
        for index in (0..pages).step_by(2) {
            half[index] = false;
        }
        let half_open = reader(half);
        let (half_count, half_time) = time(readable_runs(&half_open, low, high), half_open);

        println!(
            "all readable: {all_count} candidates in {all_time:?}
half blocked: {half_count} candidates in {half_time:?}"
        );
    }

    #[test]
    fn binds_current_process_module_with_valid_pe_sections() {
        let seeker = Seeker::with_name("main").expect("current process module should parse");
        assert!(seeker.module_size() > 0);
        assert!(seeker.sections().contains_key(".text"));
    }
}
