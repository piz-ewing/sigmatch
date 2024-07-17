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
//! anyhow = "1.0"
//! sigmatch = "0.1"
//! ```
//!
//! ```no_run
//! fn main() {
//!      let Ok(mut _sker) = sigmatch::Seeker::with_name("user32.dll") else {
//!          return;
//!      };
//!
//!      // IDA sig
//!      let Ok(_ida_example) = sker.search("E8 ? ? ? ? 45 33 F6 66 44 89 34 33") else {
//!          return;
//!      };
//!
//!      // x64dbg sig
//!      let Ok(_x64dbg_example) = sker.search("E8 ?? ?? ?? ?? 45 33 F6 66 44 89 34 33") else {
//!          return;
//!      };
//!
//!      // c sig + mask
//!      let Ok(_c_example) = sker.raw_search(
//!          b"\xE8\x00\x00\x00\x00\x45\x33\xF6\x66\x44\x89\x34\x33",
//!          "x????xxxxxxxx",
//!      ) else {
//!          return;
//!      };
//!
//!      // rebind and reversese_search
//!      let _ = || -> anyhow::Result<()> {
//!          // the module name is "main", then retrieve the main module.
//!          let _rebind_example = sker.bind("main")?.reverse_search("ab cd ?? ef")?;
//!          Ok(())
//!      }();
//!
//!      // new Seeker
//!      let mut sker1 = sigmatch::Seeker::new();
//!      if sker1.bind("ntdll.dll").is_err() {
//!          return;
//!      }
//! }
//! ```
//!
//! More than examples can see:
//! [examples](https://github.com/piz-ewing/sigmatch/tree/main/examples).
//!
use anyhow::{bail, Context, Result};
use std::{cell::RefCell, collections::HashMap};

#[cfg(target_arch = "x86")]
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;

#[cfg(target_arch = "x86_64")]
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;

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

/// Section Information.
#[derive(Clone)]
pub struct Section {
    /// The base address of the section.
    pub section_base: usize,
    /// The size of the section.
    pub section_size: usize,
}

struct _Seeker {
    /// The name of the module.
    module_name: String,
    /// The size of the module.
    module_size: usize,
    /// The base address of the module.
    module_base: usize,
    /// A map of section names to their corresponding Section structs.
    sections: HashMap<String, Section>,

    // Internal fields
    /// Indicates whether the Seeker has been initialized.
    inited: bool,

    /// Internal limit value.
    limit: usize,

    /// A vector indicating whether each memory page is readable.
    page_readable: Vec<bool>,

    /// Save last result
    last: usize,
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
    /// ```no_run
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
                sections: HashMap::new(),

                inited: false,
                limit: 0,

                page_readable: Vec::new(),

                last: 0,
            }),
            page_size,
            page_shift,
        }
    }

    pub fn limit(&self, limit: usize) -> &Self {
        self.ctx.borrow_mut().limit = limit;
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

    pub fn sections(&self) -> HashMap<String, Section> {
        self.ctx.borrow().sections.clone()
    }

    pub fn addr(&self) -> Result<usize> {
        let a = std::mem::take(&mut self.ctx.borrow_mut().last);
        if a == 0 {
            bail!("invalid addr")
        }
        Ok(a)
    }

    /// create a Seeker object and bind a module. the module name is "main", bind the main module.
    ///
    /// # Examples
    /// ```no_run
    /// let mut sker = sigmatch::Seeker::with_name("user32.dll")?;
    /// ```
    ///
    pub fn with_name(module_name: &str) -> Result<Self> {
        let sker = Self::new();
        sker.bind(module_name)?;
        return Ok(sker);
    }

    /// bind a module. the module name is "main", bind the main module.
    ///
    /// # Examples
    /// ```no_run
    /// let mut sker = sigmatch::Seeker::new();
    /// sker.bind("user32.dll");
    /// ```
    ///
    pub fn bind(&self, module_name: &str) -> Result<&Self> {
        let mut ctx = self.ctx.borrow_mut();

        ctx.inited = false;

        let module_base = if module_name == "main" {
            let Ok(r) = (unsafe { GetModuleHandleW(PCWSTR::null()) }) else {
                bail!("get main module handle failed");
            };
            r
        } else {
            let pcw_module_name = module_name.to_pcwstr();
            let Ok(r) = (unsafe { GetModuleHandleW(pcw_module_name.as_pcwstr()) }) else {
                bail!("get {} module handle failed", module_name);
            };
            r
        };

        if module_base.is_invalid() {
            bail!("{} module handle is_invalid", module_name);
        }

        ctx.module_base = module_base.0 as _;
        ctx.module_name = module_name.to_owned();

        unsafe {
            let dos_header = ctx.module_base as *const IMAGE_DOS_HEADER;
            if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
                bail!("{} module dos header invalid", module_name)
            }

            #[cfg(target_arch = "x86_64")]
            type ImageNtHeaders = IMAGE_NT_HEADERS64;

            #[cfg(target_arch = "x86")]
            type ImageNtHeaders = IMAGE_NT_HEADERS32;

            let nt_header =
                (ctx.module_base + (*dos_header).e_lfanew as usize) as *const ImageNtHeaders;

            if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
                bail!("{} module nt header invalid", module_name)
            }

            ctx.module_size = (*nt_header).OptionalHeader.SizeOfImage as _;
            if ctx.module_size == 0 {
                bail!("{} module_size is zero", module_name)
            }

            let section_header = (ctx.module_base
                + (*dos_header).e_lfanew as usize
                + memoffset::offset_of!(ImageNtHeaders, OptionalHeader) as usize
                + (*nt_header).FileHeader.SizeOfOptionalHeader as usize)
                as *const IMAGE_SECTION_HEADER;

            for i in 0..(*nt_header).FileHeader.NumberOfSections as usize {
                let section = section_header.wrapping_add(i);
                let section_name = String::from_utf8_lossy(&(*section).Name[..8])
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
                        let page = ctx.page_readable.get_mut(j).context(format!(
                            "module {} section {} out of bounds",
                            module_name, section_name,
                        ))?;
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

    /// search a signature.
    ///
    /// # Examples
    /// ```no_run
    /// let mut sker = sigmatch::Seeker::with_name("user32.dll")?;
    /// let addr = sker.search("00 ? 00")?;
    /// ```
    ///
    pub fn search(&self, sig: &str) -> Result<&Self> {
        if !self.ctx.borrow().inited {
            bail!("seeker uninited");
        }

        let (pattern, mask) = Self::sig2raw(sig)?;

        self.ctx.borrow_mut().last = self.in_search(&pattern, &mask, 0, 0, 0)?;
        Ok(self)
    }

    /// reverse search a signature.
    ///
    /// # Examples
    /// ```no_run
    /// let mut sker = sigmatch::Seeker::with_name("user32.dll")?;
    /// let addr = sker.reverse_search("00 ? 00")?;
    /// ```
    ///
    pub fn reverse_search(&self, sig: &str) -> Result<&Self> {
        let ctx = self.ctx.borrow();

        if !ctx.inited {
            bail!("seeker uninited");
        }

        let (pattern, mask) = Self::sig2raw(sig)?;

        self.ctx.borrow_mut().last = self.in_reverse_search(&pattern, &mask, 0, 0, 0)?;
        Ok(self)
    }

    /// search a signature use mask.
    ///
    /// # Examples
    /// ```no_run
    /// let mut sker = sigmatch::Seeker::with_name("user32.dll")?;
    /// let addr = sker.raw_search( b"\xE8\x00\x00\x00\x00", "x????")?;
    /// ```
    ///
    pub fn raw_search(&self, pattern: &[u8], mask: &str) -> Result<usize> {
        let ctx = self.ctx.borrow();

        if !ctx.inited {
            bail!("seeker uninited");
        }

        let m_chars: Vec<char> = mask.chars().collect();
        self.search_pattern(&pattern, &m_chars, ctx.module_base, ctx.module_size)
    }

    /// reverse search a signature use mask.
    ///
    /// # Examples
    /// ```no_run
    /// let mut sker = sigmatch::Seeker::with_name("user32.dll")?;
    /// let addr = sker.raw_reverse_search( b"\xE8\x00\x00\x00\x00", "x????")?;
    /// ```
    ///
    pub fn raw_reverse_search(&self, pattern: &[u8], mask: &str) -> Result<usize> {
        let ctx = self.ctx.borrow();

        if !ctx.inited {
            bail!("seeker uninited");
        }

        let m_chars: Vec<char> = mask.chars().collect();
        self.reverse_search_pattern(
            &pattern,
            &m_chars,
            ctx.module_base + ctx.module_size,
            ctx.module_size,
        )
    }
}

// private
impl Seeker {
    fn adjust_range(
        &self,
        mut start: usize,
        mut length: usize,
        off: usize,
        reverse: bool,
    ) -> Result<(usize, usize)> {
        let ctx = self.ctx.borrow();

        let (ostart, olength) = (start, length);

        // result first
        if ctx.last != 0 {
            start = ctx.last;
            if reverse {
                start -= off;
            } else {
                start += off;
            }
            length = ctx.limit;
        }
        // start first
        else if start == 0 {
            start = ctx.module_base;
            length = ctx.module_size;
        }

        if length == 0 {
            length = start - if ostart == 0 { ctx.module_base } else { ostart };

            if !reverse {
                length = ctx.limit
                    - if olength == 0 {
                        ctx.module_size
                    } else {
                        olength
                    };
            }
        }

        if start == 0 || length == 0 {
            bail!("invalid adjust_range")
        }

        Ok((start, length))
    }

    fn reset(&self) {
        let mut ctx = self.ctx.borrow_mut();
        ctx.last = 0;
        ctx.limit = 0;
    }

    fn in_search(
        &self,
        pattern: &[u8],
        mask: &[char],
        off: usize,
        start: usize,
        length: usize,
    ) -> Result<usize> {
        if pattern.len() == 0 || mask.len() == 0 {
            self.reset();
            bail!(std::format!(
                "invalid pattern({}) or mask({})",
                pattern.len(),
                mask.len()
            ))
        }

        let (start, length) = self.adjust_range(start, length, off, false).map_err(|e| {
            self.reset();
            e
        })?;

        self.search_pattern(pattern, mask, start, length)
            .map_err(|e| {
                self.reset();
                e
            })
    }

    fn in_reverse_search(
        &self,
        pattern: &[u8],
        mask: &[char],
        off: usize,
        start: usize,
        length: usize,
    ) -> Result<usize> {
        if pattern.len() == 0 || mask.len() == 0 {
            self.reset();
            bail!(std::format!(
                "invalid pattern({}) or mask({})",
                pattern.len(),
                mask.len()
            ))
        }

        let (start, length) = self.adjust_range(start, length, off, true).map_err(|e| {
            self.reset();
            e
        })?;

        self.reverse_search_pattern(pattern, mask, start, length)
            .map_err(|e| {
                self.reset();
                e
            })
    }

    fn search_pattern(
        &self,
        pattern: &[u8],
        mask: &[char],
        start: usize,
        length: usize,
    ) -> Result<usize> {
        let fixlen = length.saturating_sub(pattern.len());
        if fixlen == 0 {
            bail!("src len < pattern len");
        }

        let ctx = self.ctx.borrow();
        let base_index = INDEX!(ctx.module_base, self.page_shift);
        let mut last_index = 0;

        let mut addr = start;
        let end = start + fixlen;

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

        bail!("search_pattern failed");
    }

    fn reverse_search_pattern(
        &self,
        pattern: &[u8],
        mask: &[char],
        start: usize,
        length: usize,
    ) -> Result<usize> {
        let fixlen = length.saturating_sub(pattern.len());
        if fixlen == 0 {
            bail!("src len < pattern len");
        }
        let ctx = self.ctx.borrow();

        let base_index = INDEX!(ctx.module_base, self.page_shift);
        let mut last_index = 0;

        let mut addr = start - pattern.len();
        let end = start - fixlen;

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

        bail!("reverse_search_pattern failed");
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
        for shift in 0..=64 as u8 {
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
            if s.chars().next().unwrap() == '?' {
                pattern.push(0);
                mask.push('?');
            } else {
                let Ok(b) = u8::from_str_radix(s, 16) else {
                    bail!("sig is not a valid hex pattern");
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
