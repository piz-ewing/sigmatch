# sigmatch

A memory signature search library for the Windows platform written in Rust.


[![Crates.io](https://img.shields.io/crates/v/sigmatch)](https://crates.io/crates/sigmatch)
[![Crates.io](https://img.shields.io/crates/l/sigmatch)](https://github.com/piz-ewing/sigmatch)
[![depstatus](https://deps.rs/repo/github/piz-ewing/sigmatch/status.svg)](https://deps.rs/repo/github/piz-ewing/sigmatch)
[![Crates.io](https://img.shields.io/crates/d/sigmatch)](https://github.com/piz-ewing/sigmatch)


## Features
- 🧩 **Fluent API**: Clear, logical calls for complex search workflows.
- ✨ **Ergonomic**: Ready to use, supports multiple signature formats.
- 🛡️ **Robust Errors**: Based on `anyhow`, rich context, panic-free.
- 🧱 **Safe Memory**: Auto skips inaccessible regions for stable scans.
- 🚀 **Extreme Performance**: Fast and stable by design.
- 🧪 **Optimized & Tested**: Actively tested, continually improved.


## Quick Use

Assuming you've obtained the signatures via [IDA-Pro-SigMaker](https://github.com/A200K/IDA-Pro-SigMaker).

| Signature type                       | Example preview                                                                              |
| ------------------------------------ | -------------------------------------------------------------------------------------------- |
| IDA Signature                        | E8 ? ? ? ? 45 33 F6 66 44 89 34 33                                                           |
| x64Dbg Signature                     | E8 ?? ?? ?? ?? 45 33 F6 66 44 89 34 33                                                       |
| C Byte Array Signature + String mask | \xE8\x00\x00\x00\x00\x45\x33\xF6\x66\x44\x89\x34\x33 x????xxxxxxxx                           |
| C Raw Bytes Signature + Bitmask      | 0xE8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xF6, 0x66, 0x44, 0x89, 0x34, 0x33 0b1111111100001 |

```toml
[dependencies]
sigmatch = "0.2"
```

```rust
use sigmatch::{Result, Seeker};

fn example() -> Result<()> {

    let sker = Seeker::with_name("main")?;

    // Searching: forward search (push+mov+mov eax...)
    let addr = sker
        .search("6A ?? 89 E0 B8 ?? ?? ?? ?? C1 C0 05 05 ?? ?? ?? 90 90 90")?
        .addr()?;

    // Reverse search from mov eax block
    let addr = sker
        .search("B8 ?? ?? ?? ?? C1 C0 05 05 ?? ?? ?? 90 90 90")?
        .reverse_search("6A ?? 89 E0")?
        .addr()?;

    // Complex range + limit + offset
    let addr = sker
        .search("B8 ?? ?? ?? ?? C1 C0 05 05 ?? ?? ?? 90 90 90")?
        .limit(8)
        .reverse_search("6A ?? 89 E0")?
        .offset(16)
        .limit(1)
        .debug()
        .search("90")?
        .debug()
        .addr()?;

    // Rebind to system module
    sker.bind("ntdll.dll")?;

    // IDA-style pattern
    let _ = sker
        .search("? ? ? B8 C0 00 00 00 F6 04 25 ? ? ? ? 01 75 ? 0F 05 C3")?
        .addr()?;

    // x64dbg-style pattern
    let _ = sker.search("?? ?? ?? B8 C0 00 00 00 F6 04 25")?.addr()?;

    // C-style raw + mask
    let _ = sker.raw_search(
        b"\x00\x00\x00\xB8\xC0\x00\x00\x00\xF6\x04\x25",
        "???xxxxxxxx",
    )?;

    // C-style raw + bitmap
    let _ = sker.raw_search_bitmap(
        b"\x00\x00\x00\xB8\xC0\x00\x00\x00\xF6\x04\x25",
        0b00011111111,
    )?;

    Ok(())
}
```

## Recent

- Added support for method chaining
- Introduced section-based signature scanning
- Added `limit()` and `offset()` methods to control search behavior
- Improved unit test coverage
- Reorganized project structure for better clarity


## Planned Features

- [ ] Cross-platform support (Linux, macOS, etc.)
- [ ] Multi-threaded scanning for performance
- [ ] Expanded and more comprehensive test coverage


## Examples & Issues

- See more examples in the [examples](https://github.com/piz-ewing/sigmatch/tree/main/examples) directory.
- Report bugs or suggestions via [issues](https://github.com/piz-ewing/sigmatch/issues).

