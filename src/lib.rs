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

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
compile_error!("sigmatch 0.3.1 supports only x86 and x86_64 targets");

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
            Memory::{
                VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READ,
                PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS,
                PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
            },
            SystemInformation::{GetSystemInfo, SYSTEM_INFO},
            SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE},
        },
    },
};

mod error;
pub use error::{Error, Result};

/// Search direction. A backward query treats its start as the high end of the
/// inclusive scan window, which makes `backward_from(address)` useful when the
/// address is the end of an instruction or basic block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Forward,
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
    pub section_base: usize,
    pub section_size: usize,
}

impl Section {
    pub fn end(self) -> Option<usize> {
        self.section_base.checked_add(self.section_size)
    }

    pub fn range(self) -> Option<Range<usize>> {
        Some(self.section_base..self.end()?)
    }

    pub fn contains(self, address: usize) -> bool {
        self.end()
            .is_some_and(|end| address >= self.section_base && address < end)
    }

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

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

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

    fn matches(&self, reader: &ReadContext, address: usize) -> bool {
        if !reader.range_readable(address, self.len()) {
            return false;
        }
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
}

/// Values accepted by `Seeker::scan` and `ReferenceQuery::matching`.
pub trait IntoPattern {
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
    pub fn new() -> Self {
        Self {
            module: None,
            page_size: system_page_size(),
        }
    }

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

    pub fn module_base(&self) -> usize {
        self.module.as_ref().map_or(0, |module| module.base)
    }

    pub fn module_size(&self) -> usize {
        self.module.as_ref().map_or(0, |module| module.size)
    }

    /// Exclusive module end address.
    pub fn module_end(&self) -> usize {
        self.module.as_ref().map_or(0, |module| module.end)
    }

    pub fn module_range(&self) -> Option<Range<usize>> {
        self.module.as_ref().map(|module| module.base..module.end)
    }

    pub fn module_name(&self) -> String {
        self.module
            .as_ref()
            .map_or_else(String::new, |module| module.name.clone())
    }

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
    pub fn string(&self, value: &str, section: &str) -> Result<StringMatch<'_>> {
        if value.as_bytes().contains(&0) {
            return Err(Error::InvalidString);
        }
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        let address = self
            .scan(Pattern::bytes(&bytes)?)?
            .in_section(section)
            .first()?
            .address();
        Ok(StringMatch {
            seeker: self,
            address,
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
    pub fn in_section(mut self, name: impl Into<String>) -> Self {
        self.scope = Scope::Section(name.into());
        self
    }

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

    pub fn first(self) -> Result<Match> {
        let mut matches = self.all()?;
        matches.next().ok_or(Error::PatternNotFound)
    }

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
            low: range.low,
            high: range.high,
            direction: range.direction,
            reader,
        })
    }
}

/// A single byte-pattern match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Match {
    pub address: usize,
}

impl Match {
    pub fn address(self) -> usize {
        self.address
    }
}

pub struct Matches<'a> {
    pattern: Pattern,
    iter: CandidateIter,
    _marker: std::marker::PhantomData<&'a Seeker>,
}

impl Iterator for Matches<'_> {
    type Item = Match;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(address) = self.iter.next_address() {
            if self.pattern.matches(&self.iter.reader, address) {
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
    low: usize,
    high: usize,
    direction: Direction,
    reader: Arc<ReadContext>,
}

struct CandidateIter {
    current: Option<usize>,
    high: usize,
    direction: Direction,
    reader: Arc<ReadContext>,
}

impl CandidateIter {
    fn new(prepared: PreparedScan) -> Self {
        let current = Some(match prepared.direction {
            Direction::Forward => prepared.low,
            Direction::Backward => prepared.high,
        });
        Self {
            current,
            high: match prepared.direction {
                Direction::Forward => prepared.high,
                Direction::Backward => prepared.low,
            },
            direction: prepared.direction,
            reader: prepared.reader,
        }
    }

    fn next_address(&mut self) -> Option<usize> {
        let address = self.current?;
        let at_end = match self.direction {
            Direction::Forward if address <= self.high => address == self.high,
            Direction::Backward if address >= self.high => address == self.high,
            _ => {
                self.current = None;
                return None;
            }
        };
        self.current = if at_end {
            None
        } else {
            match self.direction {
                Direction::Forward => address.checked_add(1),
                Direction::Backward => address.checked_sub(1),
            }
        };
        Some(address)
    }
}

fn allocation_matches(info: &MEMORY_BASIC_INFORMATION, module_base: usize) -> bool {
    info.AllocationBase as usize == module_base
}

fn region_is_readable(info: &MEMORY_BASIC_INFORMATION) -> bool {
    info.State == MEM_COMMIT && protection_is_readable(info.Protect)
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
            readable: readable.into(),
        })
    }

    fn page_index(&self, address: usize) -> Option<usize> {
        address
            .checked_sub(self.page_base)?
            .checked_div(self.page_size)
            .filter(|&index| index < self.readable.len())
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

fn protection_is_readable(
    protection: windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS,
) -> bool {
    if protection.contains(PAGE_GUARD) || protection.contains(PAGE_NOACCESS) {
        return false;
    }
    matches!(
        protection.0 & 0xff,
        value if value == PAGE_READONLY.0
            || value == PAGE_READWRITE.0
            || value == PAGE_WRITECOPY.0
            || value == PAGE_EXECUTE_READ.0
            || value == PAGE_EXECUTE_READWRITE.0
            || value == PAGE_EXECUTE_WRITECOPY.0
    )
}

/// How a matched instruction encodes its target address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceEncoding {
    /// x86-64 RIP-relative memory operand: next instruction + signed rel32.
    X64RipRel32 {
        displacement_offset: usize,
        instruction_size: usize,
    },
    /// x86/x64 relative branch or call: next instruction + signed rel32.
    Rel32 {
        displacement_offset: usize,
        instruction_size: usize,
    },
    /// x86 absolute 32-bit operand.
    X86Abs32 { operand_offset: usize },
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
    pub fn address(self) -> usize {
        self.address
    }

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

    pub fn using(mut self, encoding: ReferenceEncoding) -> Self {
        self.encoding = Some(encoding);
        self
    }

    pub fn first(self) -> Result<Reference> {
        let mut refs = self.all()?;
        refs.next().ok_or(Error::PatternNotFound)
    }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reference {
    pub address: usize,
    pub target: usize,
}

impl Reference {
    pub fn address(self) -> usize {
        self.address
    }

    pub fn target(self) -> usize {
        self.target
    }
}

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
            readable: Arc::from(vec![true; count]),
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
        let mut bytes = vec![0x90u8; 64];
        let base = bytes.as_mut_ptr() as usize;
        let target = base + 40;
        let first_target = base + 30;
        let first_disp = (first_target as isize - (base as isize + 5)) as i32;
        bytes[0] = 0xE8;
        bytes[1..5].copy_from_slice(&first_disp.to_le_bytes());
        let target_disp = (target as isize - (base as isize + 15)) as i32;
        bytes[10] = 0xE8;
        bytes[11..15].copy_from_slice(&target_disp.to_le_bytes());

        let mut sections = HashMap::new();
        sections.insert(
            ".text".to_string(),
            Section {
                section_base: base,
                section_size: bytes.len(),
            },
        );
        let seeker = Seeker {
            module: Some(ModuleSnapshot {
                _lease: ModuleLease {
                    handle: HMODULE::default(),
                    owned: false,
                },
                name: "test".to_string(),
                base,
                size: bytes.len(),
                end: base + bytes.len(),
                sections,
            }),
            page_size: 4096,
        };
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

    #[test]
    fn protection_flags_reject_guard_and_noaccess_pages() {
        assert!(protection_is_readable(PAGE_READONLY));
        assert!(!protection_is_readable(PAGE_NOACCESS));
        assert!(!protection_is_readable(PAGE_READWRITE | PAGE_GUARD));
    }

    #[test]
    fn page_count_includes_the_last_partial_page_without_overflow() {
        assert_eq!(page_count(0x1001, 0x1FFF, 0x1000), 1);
        assert_eq!(page_count(0x1001, 0x2001, 0x1000), 2);
        assert_eq!(page_count(usize::MAX - 3, usize::MAX, 0x1000), 1);
        assert_eq!(page_count(10, 10, 0x1000), 0);
    }

    #[test]
    fn candidate_iterator_stops_at_the_last_valid_candidate() {
        let mut bytes = [0u8; 16];
        let reader = Arc::new(reader_for(&mut bytes));
        let mut forward = CandidateIter::new(PreparedScan {
            low: 10,
            high: 12,
            direction: Direction::Forward,
            reader: reader.clone(),
        });
        assert_eq!(forward.next_address(), Some(10));
        assert_eq!(forward.next_address(), Some(11));
        assert_eq!(forward.next_address(), Some(12));
        assert_eq!(forward.next_address(), None);

        let mut backward = CandidateIter::new(PreparedScan {
            low: 10,
            high: 12,
            direction: Direction::Backward,
            reader,
        });
        assert_eq!(backward.next_address(), Some(12));
        assert_eq!(backward.next_address(), Some(11));
        assert_eq!(backward.next_address(), Some(10));
        assert_eq!(backward.next_address(), None);
    }

    #[test]
    fn binds_current_process_module_with_valid_pe_sections() {
        let seeker = Seeker::with_name("main").expect("current process module should parse");
        assert!(seeker.module_size() > 0);
        assert!(seeker.sections().contains_key(".text"));
    }
}
