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
use std::collections::HashMap;

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
pub struct Section {
    /// The base address of the section.
    pub section_base: usize,
    /// The size of the section.
    pub section_size: usize,
}

/// Seeker used for searching memory sections.
pub struct Seeker {
    /// The name of the module.
    pub module_name: String,
    /// The size of the module.
    pub module_size: usize,
    /// The base address of the module.
    pub module_base: usize,
    /// A map of section names to their corresponding Section structs.
    pub sections: HashMap<String, Section>,

    // Internal fields
    /// Indicates whether the Seeker has been initialized.
    inited: bool,
    /// Internal limit value.
    _limit: usize,

    // Page info
    /// The size of a memory page.
    page_size: usize,
    /// The shift value used for calculating memory page sizes.
    page_shift: u8,
    /// A vector indicating whether each memory page is readable.
    page_readable: Vec<bool>,
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
        Seeker {
            module_name: String::new(),
            module_size: 0,
            module_base: 0 as _,
            sections: HashMap::new(),

            inited: false,
            _limit: 0,

            page_size: 0,
            page_shift: 0,
            page_readable: Vec::new(),
        }
    }

    /// create a Seeker object and bind a module. the module name is "main", bind the main module.
    ///
    /// # Examples
    /// ```no_run
    /// let mut sker = sigmatch::Seeker::with_name("user32.dll")?;
    /// ```
    ///
    pub fn with_name(module_name: &str) -> Result<Self> {
        let mut sker = Self::new();
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
    pub fn bind(&mut self, module_name: &str) -> Result<&mut Self> {
        self.inited = false;

        if self.page_size == 0 || self.page_shift == 0 {
            self.page_info()?;
        }

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

        self.module_base = module_base.0 as _;
        self.module_name = module_name.to_owned();

        unsafe {
            let dos_header = self.module_base as *const IMAGE_DOS_HEADER;
            if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
                bail!("{} module dos header invalid", module_name)
            }

            #[cfg(target_arch = "x86_64")]
            type ImageNtHeaders = IMAGE_NT_HEADERS64;

            #[cfg(target_arch = "x86")]
            type ImageNtHeaders = IMAGE_NT_HEADERS32;

            let nt_header =
                (self.module_base + (*dos_header).e_lfanew as usize) as *const ImageNtHeaders;

            if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
                bail!("{} module nt header invalid", module_name)
            }

            self.module_size = (*nt_header).OptionalHeader.SizeOfImage as _;
            if self.module_size == 0 {
                bail!("{} module_size is zero", module_name)
            }

            let section_header = (self.module_base
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
                let section_base = self.module_base + section_rva;
                let section_size = (*section).SizeOfRawData as usize;

                self.page_readable.resize(
                    ALIGN!(self.module_size, self.page_size) >> self.page_shift,
                    false,
                );

                let section_readable =
                    ((*section).Characteristics & IMAGE_SCN_MEM_READ) == IMAGE_SCN_MEM_READ;
                if section_readable {
                    let index = ALIGN!(section_rva, self.page_size) >> self.page_shift;
                    let len = ALIGN!(section_size, self.page_size) >> self.page_shift;
                    for j in index..(index + len) {
                        let page = self.page_readable.get_mut(j).context(format!(
                            "module {} section {} out of bounds",
                            module_name, section_name,
                        ))?;
                        *page = true;
                    }
                }
                self.sections.insert(
                    section_name,
                    Section {
                        section_base,
                        section_size,
                    },
                );
            }
        }

        self.inited = true;
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
    pub fn search(&mut self, sig: &str) -> Result<usize> {
        if !self.inited {
            bail!("seeker uninited");
        }

        let (pattern, mask) = Self::sig2raw(sig)?;
        self.search_pattern(&pattern, &mask, self.module_base, self.module_size)
    }

    /// reverse search a signature.
    ///
    /// # Examples
    /// ```no_run
    /// let mut sker = sigmatch::Seeker::with_name("user32.dll")?;
    /// let addr = sker.reverse_search("00 ? 00")?;
    /// ```
    ///
    pub fn reverse_search(&mut self, sig: &str) -> Result<usize> {
        if !self.inited {
            bail!("seeker uninited");
        }

        let (pattern, mask) = Self::sig2raw(sig)?;
        self.reverse_search_pattern(
            &pattern,
            &mask,
            self.module_base + self.module_size,
            self.module_size,
        )
    }

    /// search a signature use mask.
    ///
    /// # Examples
    /// ```no_run
    /// let mut sker = sigmatch::Seeker::with_name("user32.dll")?;
    /// let addr = sker.raw_search( b"\xE8\x00\x00\x00\x00", "x????")?;
    /// ```
    ///
    pub fn raw_search(&mut self, pattern: &[u8], mask: &str) -> Result<usize> {
        if !self.inited {
            bail!("seeker uninited");
        }

        let m_chars: Vec<char> = mask.chars().collect();
        self.search_pattern(&pattern, &m_chars, self.module_base, self.module_size)
    }

    /// reverse search a signature use mask.
    ///
    /// # Examples
    /// ```no_run
    /// let mut sker = sigmatch::Seeker::with_name("user32.dll")?;
    /// let addr = sker.raw_reverse_search( b"\xE8\x00\x00\x00\x00", "x????")?;
    /// ```
    ///
    pub fn raw_reverse_search(&mut self, pattern: &[u8], mask: &str) -> Result<usize> {
        if !self.inited {
            bail!("seeker uninited");
        }

        let m_chars: Vec<char> = mask.chars().collect();
        self.reverse_search_pattern(
            &pattern,
            &m_chars,
            self.module_base + self.module_size,
            self.module_size,
        )
    }
}

// private
impl Seeker {
    fn page_info(&mut self) -> Result<()> {
        self.page_size = Self::get_page_size();
        if self.page_size == 0 {
            bail!("get page_size 0");
        }

        self.page_shift = Self::get_page_shift(self.page_size);
        if self.page_shift == 0 {
            bail!("get page_shift 0");
        }

        Ok(())
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

        let base_index = INDEX!(self.module_base, self.page_shift);
        let mut last_index = 0;

        let mut addr = start;
        let end = start + fixlen;

        while addr <= end {
            let page_index = INDEX!(addr, self.page_shift);
            if page_index != last_index {
                if self.page_readable[page_index - base_index] {
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

        let base_index = INDEX!(self.module_base, self.page_shift);
        let mut last_index = 0;

        let mut addr = start - pattern.len();
        let end = start - fixlen;

        while addr >= end {
            let page_index = INDEX!(addr, self.page_shift);
            if page_index != last_index {
                if self.page_readable[page_index - base_index] {
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
        0
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
