# sigmatch

A memory signature search library for the Windows platform written in Rust.

It's a basic version migrated from another C++ project of mine, with more features coming soon!

[![Crates.io](https://img.shields.io/crates/v/sigmatch)](https://crates.io/crates/sigmatch)
[![Crates.io](https://img.shields.io/crates/l/sigmatch)](https://github.com/piz-ewing/sigmatch)
[![depstatus](https://deps.rs/repo/github/piz-ewing/sigmatch/status.svg)](https://deps.rs/repo/github/piz-ewing/sigmatch)
[![Crates.io](https://img.shields.io/crates/d/sigmatch)](https://github.com/piz-ewing/sigmatch)

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
anyhow = "1.0"
sigmatch = "0.1"
```

```rust
fn main() {
    let Ok(mut sker) = sigmatch::Seeker::with_name("user32.dll") else {
        return;
    };

    // IDA sig
    let Ok(_ida_example) = sker.search("E8 ? ? ? ? 45 33 F6 66 44 89 34 33") else {
        return;
    };

    // x64dbg sig
    let Ok(_x64dbg_example) = sker.search("E8 ?? ?? ?? ?? 45 33 F6 66 44 89 34 33") else {
        return;
    };

    // c sig + mask
    let Ok(_c_example) = sker.raw_search(
        b"\xE8\x00\x00\x00\x00\x45\x33\xF6\x66\x44\x89\x34\x33",
        "x????xxxxxxxx",
    ) else {
        return;
    };

    // rebind and reversese_search
    let _ = || -> anyhow::Result<()> {
        // the module name is "main", then retrieve the main module.
        let _rebind_example = sker.bind("main")?.reverse_search("ab cd ?? ef")?;
        Ok(())
    }();

    // new Seeker
    let mut sker1 = sigmatch::Seeker::new();
    if sker1.bind("ntdll.dll").is_err() {
        return;
    }
}
```

## todo

-   supports chaining calls.

-   allows specifying search addresses.

-   section-based search support.

-   support for limiting the search.

-   unit testing

-   improved file organization

## examples

More than examples can see [examples](https://github.com/piz-ewing/sigmatch/tree/main/examples).
