//! a memory signature search library for the Windows platform written in Rust.
//!
//! It's a basic version migrated from another C++ project of mine, with more features coming soon!
//!
//! ## Quick Use
//! Assuming you've obtained the signatures via [IDA-Pro-SigMaker](https://github.com/A200K/IDA-Pro-SigMaker).
//!
//! # Usage in project
//!
//! ```toml
//! [dependencies]
//! sigmatch = "0.2"
//! ```
//!
//! ```ignore
//! use sigmatch::{Result, Seeker};
//!
//! fn example() -> Result<()> {
//!
//!     let sker = Seeker::with_name("main")?;
//!
//!     // Searching: forward search (push+mov+mov eax...)
//!     let addr = sker
//!         .search("6A ?? 89 E0 B8 ?? ?? ?? ?? C1 C0 05 05 ?? ?? ?? 90 90 90")?
//!         .addr()?;
//!
//!     // Reverse search from mov eax block
//!     let addr = sker
//!         .search("B8 ?? ?? ?? ?? C1 C0 05 05 ?? ?? ?? 90 90 90")?
//!         .reverse_search("6A ?? 89 E0")?
//!         .addr()?;
//!
//!     // Complex range + limit + offset
//!     let addr = sker
//!         .search("B8 ?? ?? ?? ?? C1 C0 05 05 ?? ?? ?? 90 90 90")?
//!         .limit(8)
//!         .reverse_search("6A ?? 89 E0")?
//!         .offset(16)
//!         .limit(1)
//!         .debug()
//!         .search("90")?
//!         .debug()
//!         .addr()?;
//!
//!     // Rebind to system module
//!     sker.bind("ntdll.dll")?;
//!
//!     // IDA-style pattern
//!     let _ = sker
//!         .search("? ? ? B8 C0 00 00 00 F6 04 25 ? ? ? ? 01 75 ? 0F 05 C3")?
//!         .addr()?;
//!
//!     // x64dbg-style pattern
//!     let _ = sker.search("?? ?? ?? B8 C0 00 00 00 F6 04 25")?.addr()?;
//!
//!     // C-style raw + mask
//!     let _ = sker.raw_search(
//!         b"\x00\x00\x00\xB8\xC0\x00\x00\x00\xF6\x04\x25",
//!         "???xxxxxxxx",
//!     )?;
//!
//!     // C-style raw + bitmap
//!     let _ = sker.raw_search_bitmap(
//!         b"\x00\x00\x00\xB8\xC0\x00\x00\x00\xF6\x04\x25",
//!         0b00011111111,
//!     )?;
//!
//!     Ok(())
//! }
//! ```
//!
//! More than examples can see:
//! [examples](https://github.com/piz-ewing/sigmatch/tree/main/examples).
//!
use custom_debug::Debug;
use log::{debug, warn};
use std::{cell::RefCell, collections::HashMap, fmt};

#[cfg(target_arch = "x86_64")]
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;

#[cfg(target_arch = "x86")]
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;

use windows::{
    core::PCWSTR,
    Win32::System::{
        Diagnostics::Debug::{IMAGE_SCN_MEM_READ, IMAGE_SECTION_HEADER},
        LibraryLoader::GetModuleHandleW,
        SystemInformation::{GetSystemInfo, SYSTEM_INFO},
        SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE},
    },
};

mod str;
use crate::str::ToPCWSTRWrapper;

mod error;
pub use error::{Error, Result};

macro_rules! ROUND_UP {
    ($x:expr, $a:expr) => {
        (($x + ($a as usize - 1)) & !($a as usize - 1))
    };
}

#[allow(unused_macros)]
macro_rules! ROUND_DOWN {
    ($x:expr, $a:expr) => {
        ($x & !($a as usize - 1))
    };
}

macro_rules! ALIGN {
    ($x:expr, $a:expr) => {
        ROUND_UP!($x, $a)
    };
}

macro_rules! INDEX {
    ($a:expr, $s:expr) => {
        ($a as usize >> $s)
    };
}

#[derive(Debug, Clone, Copy)]
pub enum Direction {
    Forward,
    Reverse,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Direction::Forward => write!(f, "forward"),
            Direction::Reverse => write!(f, "reverse"),
        }
    }
}

/// Section Information.
#[derive(Clone)]
pub struct Section {
    /// The base address of the section.
    pub section_base: usize,
    /// The size of the section.
    pub section_size: usize,
}

#[derive(Debug)]
struct _Seeker {
    /// The name of the module.
    module_name: String,
    /// The size of the module.
    #[debug(with = hex_fmt)]
    module_size: usize,
    /// The base address of the module.
    #[debug(with = hex_fmt)]
    module_base: usize,
    /// The end address of the module.
    #[debug(with = hex_fmt)]
    module_end: usize,
    /// A map of section names to their corresponding Section structs.
    #[debug(skip)]
    sections: HashMap<String, Section>,

    // Internal fields
    /// Indicates whether the Seeker has been initialized.
    inited: bool,

    /// Internal limit value.
    #[debug(with = hex_fmt)]
    limit: usize,

    /// Internal offset value.
    #[debug(with = hex_fmt)]
    offset: usize,

    /// A vector indicating whether each memory page is readable.
    #[debug(skip)]
    page_readable: Vec<bool>,

    /// Save last result
    #[debug(with = hex_fmt)]
    last: usize,
}

fn hex_fmt<T: fmt::Debug>(n: &T, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "0x{n:02X?}")
}

/// Seeker used for searching memory sections.
pub struct Seeker {
    ctx: RefCell<_Seeker>,

    // Page info
    /// The size of a memory page.
    page_size: usize,
    /// The shift value used for calculating memory page sizes.
    page_shift: u8,
}

// public
impl Seeker {
    /// create a Seeker object.
    ///
    /// # Examples
    /// ```ignore
    /// let mut sker = sigmatch::Seeker::new();
    /// ```
    ///
    pub fn new() -> Self {
        let page_size = Self::get_page_size();
        let page_shift = Self::get_page_shift(page_size);

        Seeker {
            ctx: RefCell::new(_Seeker {
                module_name: String::new(),
                module_size: 0,
                module_base: 0 as _,
                module_end: 0 as _,
                sections: HashMap::new(),

                inited: false,
                limit: 0,
                offset: 0,

                page_readable: Vec::new(),

                last: 0,
            }),
            page_size,
            page_shift,
        }
    }

    /// Sets the maximum number of matches for the next search operation only.
    ///
    /// The setting is reset after the next search operation.
    ///
    /// # Examples
    /// ```ignore
    /// let mut seeker = sigmatch::Seeker::with_name("user32.dll")?;
    /// let addr = seeker.limit(10)
    ///                  .search("00 ? 00")? // Uses limit=10
    ///                  .search("00 ? 00")? // Uses limit=0
    ///                  .addr()?;
    /// ```
    pub fn limit(&self, limit: usize) -> &Self {
        self.ctx.borrow_mut().limit = limit;
        self
    }

    /// Sets the starting offset for the next search operation only.
    ///
    /// The setting is reset after the next search operation.
    ///
    /// In forward searches, the offset is **added** to the start address (typically `last + offset`);
    /// in reverse searches, the offset is **subtracted** from the start address (i.e. `last - offset`).
    ///
    /// # Examples
    /// ```ignore
    /// let mut seeker = sigmatch::Seeker::with_name("user32.dll")?;
    /// let addr = seeker.offset(0x1000)
    ///                  .search("00 ? 00")? // Uses offset=0x1000
    ///                  .search("00 ? 00")? // Uses offset=0
    ///                  .addr()?;
    /// ```
    pub fn offset(&self, offset: usize) -> &Self {
        self.ctx.borrow_mut().offset = offset;
        self
    }

    pub fn module_base(&self) -> usize {
        self.ctx.borrow().module_base
    }

    pub fn module_name(&self) -> String {
        self.ctx.borrow().module_name.to_owned()
    }

    pub fn module_size(&self) -> usize {
        self.ctx.borrow().module_size
    }

    pub fn module_end(&self) -> usize {
        self.ctx.borrow().module_end
    }

    pub fn sections(&self) -> HashMap<String, Section> {
        self.ctx.borrow().sections.clone()
    }

    pub fn add(&self, value: usize) -> &Self {
        self.ctx.borrow_mut().last += value;
        self
    }

    pub fn sub(&self, value: usize) -> &Self {
        self.ctx.borrow_mut().last -= value;
        self
    }

    pub fn addr(&self) -> Result<usize> {
        let a = std::mem::take(&mut self.ctx.borrow_mut().last);
        if a == 0 {
            Err(Error::InvalidAddr)
        } else {
            Ok(a)
        }
    }

    pub fn debug(&self) -> &Self {
        let sker = self.ctx.borrow();
        debug!("{sker:?}");
        self
    }

    pub unsafe fn unchecked(&self) -> &Self {
        let mut ctx = self.ctx.borrow_mut();
        for v in &mut ctx.page_readable {
            *v = true;
        }
        self
    }

    /// create a Seeker object and bind a module. the module name is "main", bind the main module.
    ///
    /// # Examples
    /// ```ignore
    /// let mut sker = sigmatch::Seeker::with_name("user32.dll")?;
    /// ```
    ///
    pub fn with_name(module_name: &str) -> Result<Self> {
        let sker = Self::new();
        sker.bind(module_name)?;
        Ok(sker)
    }

    /// bind a module. the module name is "main", bind the main module.
    ///
    /// # Examples
    /// ```ignore
    /// let mut sker = sigmatch::Seeker::new();
    /// sker.bind("user32.dll");
    /// ```
    ///
    pub fn bind(&self, module_name: &str) -> Result<&Self> {
        let mut ctx = self.ctx.borrow_mut();

        ctx.inited = false;

        let module_base = if module_name == "main" {
            let Ok(r) = (unsafe { GetModuleHandleW(PCWSTR::null()) }) else {
                return Err(Error::GetModuleHandleFailed("main".to_string()));
            };
            r
        } else {
            let pcw_module_name = module_name.to_pcwstr();
            let Ok(r) = (unsafe { GetModuleHandleW(pcw_module_name.as_pcwstr()) }) else {
                return Err(Error::GetModuleHandleFailed(module_name.to_string()));
            };
            r
        };

        if module_base.is_invalid() {
            return Err(Error::GetModuleHandleFailed(module_name.to_string()));
        }

        ctx.module_base = module_base.0 as _;
        ctx.module_name = module_name.to_owned();

        unsafe {
            let dos_header = ctx.module_base as *const IMAGE_DOS_HEADER;
            if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
                return Err(Error::InvalidDosHeader(module_name.to_string()));
            }

            #[cfg(target_arch = "x86_64")]
            type ImageNtHeaders = IMAGE_NT_HEADERS64;

            #[cfg(target_arch = "x86")]
            type ImageNtHeaders = IMAGE_NT_HEADERS32;

            let nt_header =
                (ctx.module_base + (*dos_header).e_lfanew as usize) as *const ImageNtHeaders;

            if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
                return Err(Error::InvalidNtHeader(module_name.to_string()));
            }

            ctx.module_size = (*nt_header).OptionalHeader.SizeOfImage as _;
            if ctx.module_size == 0 {
                return Err(Error::ModuleSizeZero(module_name.to_string()));
            }
            ctx.module_end = ctx.module_base + ctx.module_size - 1;

            let section_header = (ctx.module_base
                + (*dos_header).e_lfanew as usize
                + memoffset::offset_of!(ImageNtHeaders, OptionalHeader)
                + (*nt_header).FileHeader.SizeOfOptionalHeader as usize)
                as *const IMAGE_SECTION_HEADER;

            for i in 0..(*nt_header).FileHeader.NumberOfSections as usize {
                let section = section_header.wrapping_add(i);
                let section_name = String::from_utf8_lossy(&(&(*section).Name)[..8])
                    .trim_end_matches(char::from(0))
                    .to_string();
                let section_rva = (*section).VirtualAddress as usize;
                let section_base = ctx.module_base + section_rva;
                let section_size = (*section).SizeOfRawData as usize;

                let ms = ctx.module_size;
                ctx.page_readable
                    .resize(ALIGN!(ms, self.page_size) >> self.page_shift, false);

                let section_readable =
                    ((*section).Characteristics & IMAGE_SCN_MEM_READ) == IMAGE_SCN_MEM_READ;
                if section_readable {
                    let index = ALIGN!(section_rva, self.page_size) >> self.page_shift;
                    let len = ALIGN!(section_size, self.page_size) >> self.page_shift;
                    for j in index..(index + len) {
                        let Some(page) = ctx.page_readable.get_mut(j) else {
                            return Err(Error::SectionOutOfBounds(section_name.to_string()));
                        };
                        *page = true;
                    }
                }
                ctx.sections.insert(
                    section_name,
                    Section {
                        section_base,
                        section_size,
                    },
                );
            }
        }

        ctx.inited = true;
        Ok(self)
    }

    /// Internal helper method for signature searching
    fn search_internal(
        &self,
        sig: &str,
        direction: Direction,
        section_name: Option<&str>,
    ) -> Result<&Self> {
        if !self.ctx.borrow().inited {
            return Err(Error::Uninitialized);
        }

        let (pattern, mask) = Self::sig2raw(sig)?;

        let (base, size) = if let Some(name) = section_name {
            let ctx = self.ctx.borrow();
            let section = ctx
                .sections
                .get(name)
                .ok_or_else(|| Error::SectionNotFound(name.to_string()))?;

            match direction {
                Direction::Forward => (section.section_base, section.section_size),
                Direction::Reverse => (
                    section.section_base + section.section_size - 1,
                    section.section_size,
                ),
            }
        } else {
            (0, 0)
        };

        let search_fn = match direction {
            Direction::Forward => Self::in_search,
            Direction::Reverse => Self::in_reverse_search,
        };

        self.ctx.borrow_mut().last = search_fn(self, &pattern, &mask, base, size)?;
        self.clear();
        Ok(self)
    }

    /// Searches for a signature in the loaded module.
    ///
    /// # Examples
    /// ```ignore
    /// let mut seeker = sigmatch::Seeker::with_name("user32.dll")?;
    /// let addr = seeker.search("00 ? 00")?
    ///                  .addr()?;
    /// ```
    pub fn search(&self, sig: &str) -> Result<&Self> {
        self.search_internal(sig, Direction::Forward, None)
    }

    /// Reverse searches for a signature in the loaded module.
    ///
    /// # Examples
    /// ```ignore
    /// let mut seeker = sigmatch::Seeker::with_name("user32.dll")?;
    /// let addr = seeker.reverse_search("00 ? 00")?
    ///                  .addr()?;
    /// ```
    pub fn reverse_search(&self, sig: &str) -> Result<&Self> {
        self.search_internal(sig, Direction::Reverse, None)
    }

    /// Searches for a signature in a specific section of the loaded module.
    ///
    /// # Examples
    /// ```ignore
    /// let mut seeker = sigmatch::Seeker::with_name("user32.dll")?;
    /// let addr = seeker.search_in_section("00 ? 00", ".text")?
    ///                  .addr()?;
    /// ```
    pub fn search_in_section(&self, sig: &str, name: &str) -> Result<&Self> {
        self.search_internal(sig, Direction::Forward, Some(name))
    }

    /// Reverse searches for a signature in a specific section of the loaded module.
    ///
    /// # Examples
    /// ```ignore
    /// let mut seeker = sigmatch::Seeker::with_name("user32.dll")?;
    /// let addr = seeker.reverse_search_in_section("00 ? 00", ".text")?
    ///                  .addr()?;
    /// ```
    pub fn reverse_search_in_section(&self, sig: &str, name: &str) -> Result<&Self> {
        self.search_internal(sig, Direction::Reverse, Some(name))
    }

    /// search a signature use mask.
    ///
    /// # Examples
    /// ```ignore
    /// let mut sker = sigmatch::Seeker::with_name("user32.dll")?;
    /// let addr = sker.raw_search( b"\xE8\x00\x00\x00\x00", "x????")?;
    /// ```
    ///
    #[deprecated]
    pub fn raw_search(&self, pattern: &[u8], mask: &str) -> Result<usize> {
        let ctx = self.ctx.borrow();
        if !ctx.inited {
            return Err(Error::Uninitialized);
        }

        let m_chars: Vec<char> = mask.chars().collect();
        self.search_pattern(pattern, &m_chars, ctx.module_base, ctx.module_size)
    }

    /// search a signature use bitmap.
    ///
    /// # Examples
    /// ```ignore
    /// let mut sker = sigmatch::Seeker::with_name("user32.dll")?;
    /// let addr = sker.raw_search_bitmap( b"\xE8\x00\x00\x00\x00", 0b10000)?;
    /// ```
    ///
    #[deprecated]
    pub fn raw_search_bitmap(&self, pattern: &[u8], bitmap: usize) -> Result<usize> {
        if pattern.len() > usize::BITS as usize {
            return Err(Error::PatternExceedsBitmapSize(
                pattern.len(),
                usize::BITS as usize,
            ));
        }

        let mut mask = String::with_capacity(pattern.len());

        for i in (0..pattern.len()).rev() {
            let bit = (bitmap >> i) & 1;
            mask.push(if bit == 1 { 'x' } else { '?' });
        }

        #[allow(deprecated)]
        self.raw_search(pattern, &mask)
    }
}

impl Default for Seeker {
    fn default() -> Self {
        Self::new()
    }
}

// private
impl Seeker {
    fn adjust_range(
        &self,
        mut start: usize,
        mut length: usize,
        direction: Direction,
    ) -> Result<(usize, usize)> {
        let ctx = self.ctx.borrow();

        match (start, length, ctx.last) {
            (s, l, _) if s != 0 => {
                if ctx.last != 0 {
                    warn!("previous search will be ignored");
                }

                if l != 0 && ctx.offset >= l {
                    return Err(Error::OffsetOutOfSection(
                        start, length, ctx.offset, direction,
                    ));
                }
            }
            (_, _, last) if last != 0 => {
                start = last;
            }
            (0, 0, 0) => {
                start = ctx.module_base;
                length = ctx.module_size;
                if let Direction::Reverse = direction {
                    start = ctx.module_end;
                }
            }
            _ => {
                return Err(Error::InvalidAdjustRange);
            }
        }

        // offset
        start = match direction {
            Direction::Forward => {
                length = length.saturating_sub(ctx.offset);
                start.saturating_add(ctx.offset)
            }
            Direction::Reverse => {
                length = length.saturating_sub(ctx.offset);
                start.saturating_sub(ctx.offset)
            }
        };

        // limit
        if ctx.limit != 0 && ctx.limit < length {
            length = ctx.limit;
        }

        // default length
        if length == 0 {
            length = start.saturating_sub(ctx.module_base);
            if let Direction::Forward = direction {
                length = ctx.module_size.saturating_sub(length)
            } else {
                length += 1;
            }
        }

        if !self.is_address_in_module(start, length, direction) {
            return Err(Error::OffsetOutOfModule(
                start, length, ctx.offset, direction,
            ));
        }

        Ok((start, length))
    }

    fn is_address_in_module(&self, start: usize, length: usize, direction: Direction) -> bool {
        let ctx = self.ctx.borrow();

        let end = match direction {
            Direction::Forward => start.checked_add(length.saturating_sub(1)),
            Direction::Reverse => start.checked_sub(length.saturating_sub(1)),
        };

        match end {
            Some(end_addr) => {
                let base = ctx.module_base;
                let end = ctx.module_end;
                start >= base && start <= end && end_addr >= base && end_addr <= end
            }
            None => false, // overflow/underflow occurred
        }
    }

    fn clear(&self) {
        let mut ctx = self.ctx.borrow_mut();
        ctx.limit = 0;
        ctx.offset = 0;
    }

    fn reset(&self) {
        let mut ctx = self.ctx.borrow_mut();
        ctx.last = 0;
        ctx.limit = 0;
        ctx.offset = 0;
    }

    fn in_search(
        &self,
        pattern: &[u8],
        mask: &[char],
        start: usize,
        length: usize,
    ) -> Result<usize> {
        if pattern.is_empty() || mask.is_empty() {
            self.reset();
            return Err(Error::InvalidPattern(pattern.len(), mask.len()));
        }

        let (start, length) = self
            .adjust_range(start, length, Direction::Forward)
            .inspect_err(|_| self.reset())?;

        self.search_pattern(pattern, mask, start, length)
            .inspect_err(|_| self.reset())
    }

    fn in_reverse_search(
        &self,
        pattern: &[u8],
        mask: &[char],
        start: usize,
        length: usize,
    ) -> Result<usize> {
        if pattern.is_empty() || mask.is_empty() {
            self.reset();
            return Err(Error::InvalidPattern(pattern.len(), mask.len()));
        }

        let (start, length) = self
            .adjust_range(start, length, Direction::Reverse)
            .inspect_err(|_| {
                self.reset();
            })?;

        self.reverse_search_pattern(pattern, mask, start, length)
            .inspect_err(|_| {
                self.reset();
            })
    }

    fn search_pattern(
        &self,
        pattern: &[u8],
        mask: &[char],
        start: usize,
        length: usize,
    ) -> Result<usize> {
        let Some(fixlen) = length.checked_sub(pattern.len()) else {
            return Err(Error::SearchLengthTooShort(length, pattern.len()));
        };

        let ctx = self.ctx.borrow();
        let base_index = INDEX!(ctx.module_base, self.page_shift);
        let mut last_index = 0;

        let mut addr = start;
        let end = start + fixlen;

        debug!("searching signature (forward): start = 0x{start:X}, length = 0x{length:X} fixlen = {fixlen:X} addr = {addr:X} end = {end:X}");

        while addr <= end {
            let page_index = INDEX!(addr, self.page_shift);
            if page_index != last_index {
                if ctx.page_readable[page_index - base_index] {
                    last_index = page_index;
                } else {
                    addr += self.page_size;
                    continue;
                }
            }

            if Self::compare(addr, pattern, mask) {
                return Ok(addr);
            }

            addr += 1;
        }

        Err(Error::PatternNotFound)
    }

    fn reverse_search_pattern(
        &self,
        pattern: &[u8],
        mask: &[char],
        start: usize,
        length: usize,
    ) -> Result<usize> {
        let pattern_len = pattern.len();
        if length < pattern_len {
            return Err(Error::SearchLengthTooShort(length, pattern.len()));
        };

        let ctx = self.ctx.borrow();

        let base_index = INDEX!(ctx.module_base, self.page_shift);
        let mut last_index = 0;

        let mut addr = start - pattern_len + 1;
        let end = start - length + 1;

        debug!("searching signature (reverse): start = 0x{start:X}, length = 0x{length:X} addr = {addr:X} end = {end:X}");

        while addr >= end {
            let page_index = INDEX!(addr, self.page_shift);
            if page_index != last_index {
                if ctx.page_readable[page_index - base_index] {
                    last_index = page_index;
                } else {
                    addr -= self.page_size;
                    continue;
                }
            }
            if Self::compare(addr, pattern, mask) {
                return Ok(addr);
            }

            addr -= 1;
        }

        Err(Error::PatternNotFound)
    }
}

// static
impl Seeker {
    fn get_page_size() -> usize {
        unsafe {
            let mut sys_info: SYSTEM_INFO = std::mem::zeroed();
            GetSystemInfo(&mut sys_info);
            sys_info.dwPageSize as usize
        }
    }

    fn get_page_shift(page_size: usize) -> u8 {
        for shift in 0..=64_u8 {
            if 1 << shift == page_size {
                return shift;
            }
        }
        panic!("invalid page size")
    }

    fn sig2raw(sig: &str) -> Result<(Vec<u8>, Vec<char>)> {
        let mut pattern = Vec::new();
        let mut mask = Vec::new();
        let r = regex::Regex::new("[0-9a-fA-F]{2}|\\?{1,2}").unwrap();
        for s in r.find_iter(sig) {
            let s = s.as_str();
            if s.starts_with('?') {
                pattern.push(0);
                mask.push('?');
            } else {
                let Ok(b) = u8::from_str_radix(s, 16) else {
                    return Err(Error::InvalidSigHex);
                };

                pattern.push(b);
                mask.push('x');
            }
        }
        Ok((pattern, mask))
    }

    fn compare(s: usize, d: &[u8], m: &[char]) -> bool {
        for i in 0..d.len() {
            if m[i] == 'x' && unsafe { std::ptr::read((s + i) as *const u8) } != d[i] {
                return false;
            }
        }
        true
    }
}
