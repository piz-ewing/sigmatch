# sigmatch

A flexible Rust library for searching byte signatures in loaded Windows PE modules.

> **Version 0.3 is not compatible with 0.2.** The stateful 0.2 API (`search`, `reverse_search`, `addr`, `offset`, `limit`, and `unchecked`) was removed. Update the dependency to `sigmatch = "0.3"` and use the explicit query API shown below.


[![Crates.io](https://img.shields.io/crates/v/sigmatch)](https://crates.io/crates/sigmatch)
[![Crates.io](https://img.shields.io/crates/l/sigmatch)](https://github.com/piz-ewing/sigmatch)
[![depstatus](https://deps.rs/repo/github/piz-ewing/sigmatch/status.svg)](https://deps.rs/repo/github/piz-ewing/sigmatch/status.svg)
[![Crates.io](https://img.shields.io/crates/d/sigmatch)](https://github.com/piz-ewing/sigmatch)

Language: English | [简体中文](README_CN.md)


## Features

- 🧩 **Fluent Query API**: Compose section, direction, start address, and byte-window limits without hidden seeker state.
- ✨ **Flexible Patterns**: Accept IDA/x64dbg signatures, masked byte arrays, and bitmap patterns.
- 🔗 **Reference Queries**: Find a string in one section, then enumerate matching references with an explicit x86/x64 decoder.
- 🧱 **Safe Memory**: Check module bounds, page readability, page protections, and arithmetic before reading.
- 🚀 **Predictable Performance**: Apply section and range limits before scanning and resolve page metadata before the candidate loop.
- 🛡️ **Robust Errors**: Strict parsing and `thiserror` errors instead of silent pattern or address failures.
- 🧪 **Tested**: Covers parser, search boundaries, cross-page reads, page protections, overflow, and references.


## Quick Use

Assuming you've obtained the signatures via [IDA-Pro-SigMaker](https://github.com/A200K/IDA-Pro-SigMaker).

| Signature type                       | Example preview                                                                              |
| ------------------------------------ | -------------------------------------------------------------------------------------------- |
| IDA Signature                        | E8 ? ? ? ? 45 33 F6 66 44 89 34 33                                                           |
| x64dbg Signature                     | E8 ?? ?? ?? ?? 45 33 F6 66 44 89 34 33                                                       |
| C Byte Array Signature + String mask | \xE8\x00\x00\x00\x00\x45\x33\xF6\x66\x44\x89\x34\x33 x????xxxxxxxx                           |
| C Raw Bytes Signature + Bitmask      | 0xE8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xF6, 0x66, 0x44, 0x89, 0x34, 0x33 0b1111111100001 |

```toml
[dependencies]
sigmatch = "0.3"
```

```rust
use sigmatch::{Pattern, ReferenceEncoding, Result, Seeker};

fn example() -> Result<()> {
    let mut seeker = Seeker::with_name("main")?;

    // Simple section-bounded lookup.
    let mov = seeker.find_in(
        ".text",
        "B8 ?? ?? ?? ?? C1 C0 05 05 ?? ?? ?? 90 90 90",
    )?;

    // A separate query can search backwards from that result.
    let push = seeker
        .scan("6A ?? 89 E0")?
        .in_section(".text")
        .backward_from(mov.address())
        .within(8)
        .first()?;

    // Forward searches and lazy result iteration use the same query API.
    let _nearby = seeker
        .scan("90 90")?
        .in_section(".text")
        .forward_from(push.address())
        .within(0x20)
        .first()?;

    // Parse a pattern once and reuse it.
    let pattern = Pattern::signature(
        "? ? ? B8 C0 00 00 00 F6 04 25 ? ? ? ? 01 75 ? 0F 05 C3",
    )?;
    let _ = seeker.find_in(".text", &pattern)?;

    let masked = Pattern::masked(
        b"\x00\x00\x00\xB8\xC0\x00\x00\x00\xF6\x04\x25",
        "???xxxxxxxx",
    )?;
    let _ = seeker.find_in(".text", &masked)?;

    let bitmap = Pattern::bitmap(
        b"\x00\x00\x00\xB8\xC0\x00\x00\x00\xF6\x04\x25",
        0b111_1111_1000,
    )?;
    let _ = seeker.find_in(".text", &bitmap)?;

    // Find a string and enumerate references to it.
    let string = seeker.string("example string", ".rdata")?;
    let references = string
        .refs_in(".text")
        .matching("48 8D 35 ? ? ? ?")
        .using(ReferenceEncoding::X64RipRel32 {
            displacement_offset: 3,
            instruction_size: 7,
        })
        .all()?;
    for reference in references {
        println!(
            "reference={:#x} target={:#x}",
            reference.address(),
            reference.target()
        );
    }

    // Rebind to another loaded module when needed.
    seeker.bind("ntdll.dll")?;
    let _ = seeker.find_in(".text", "4C 8B D1")?;

    Ok(())
}
```

Queries are lazy and independent: section and range constraints are applied before scanning, and `first()` or `all()` decides when results are consumed. `find_in(section, pattern)` is a shorthand for a simple forward lookup; use `scan` when direction, byte windows, or iteration need to be explicit.


## Recent

- Added the explicit query API with forward, backward, section, and byte-window controls.
- Added reusable text, masked-byte, and bitmap patterns.
- Added string reference queries with explicit x86/x64 address decoders.
- Added transactional module rebinding and safer page-aware scanning.
- Expanded edge-case tests for boundaries, protections, overflow, and references.


## Planned Features

- [ ] Composed or named multi-field reference decoding.
- [ ] More real-module integration tests and performance benchmarks.
- [ ] Cross-platform support (Linux, macOS, etc.).


## Examples & Issues

- See the runnable example in [examples/demo.rs](examples/demo.rs).
- Report bugs or suggestions via [issues](https://github.com/piz-ewing/sigmatch/issues).
