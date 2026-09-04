# sigmatch

一个灵活、受边界保护的 Windows PE 模块内存特征搜索库，使用 Rust 编写。

> **0.3 与 0.2 不兼容。** 0.2 中的状态式 API（`search`、`reverse_search`、`addr`、`offset`、`limit` 和 `unchecked`）已经移除。请将依赖改为 `sigmatch = "0.3"`，并使用下面的显式查询 API。


[![Crates.io](https://img.shields.io/crates/v/sigmatch)](https://crates.io/crates/sigmatch)
[![Crates.io](https://img.shields.io/crates/l/sigmatch)](https://github.com/piz-ewing/sigmatch)
[![depstatus](https://deps.rs/repo/github/piz-ewing/sigmatch/status.svg)](https://deps.rs/repo/github/piz-ewing/sigmatch/status.svg)
[![Crates.io](https://img.shields.io/crates/d/sigmatch)](https://github.com/piz-ewing/sigmatch)

语言：简体中文 | [English](README.md)


## 功能特性

- 🧩 **链式查询 API**：组合区段、方向、起点和字节窗口，不依赖 Seeker 的隐藏状态。
- ✨ **灵活的模式输入**：支持 IDA/x64dbg 特征码、掩码字节数组和位图模式。
- 🔗 **引用查询**：先在一个区段中定位字符串，再用明确的 x86/x64 解码器枚举指向它的引用。
- 🧱 **安全内存访问**：读取前检查模块边界、页面可读性、页面保护属性和算术溢出。
- 🚀 **可预期的性能**：扫描前应用区段和范围限制，并在候选循环前准备页面元数据。
- 🛡️ **健壮错误处理**：严格解析输入，使用 `thiserror` 返回模式和地址错误，不静默忽略失败。
- 🧪 **完善测试**：覆盖模式解析、搜索边界、跨页读取、页面保护、溢出和引用查询。


## 快速使用

假设你已经通过 [IDA-Pro-SigMaker](https://github.com/A200K/IDA-Pro-SigMaker) 获取了特征码。

| 特征码类型                         | 示例                                                                                       |
| ---------------------------------- | ------------------------------------------------------------------------------------------ |
| IDA Signature                     | E8 ? ? ? ? 45 33 F6 66 44 89 34 33                                                         |
| x64dbg Signature                  | E8 ?? ?? ?? ?? 45 33 F6 66 44 89 34 33                                                     |
| C 字节数组 + 字符串掩码            | \xE8\x00\x00\x00\x00\x45\x33\xF6\x66\x44\x89\x34\x33 x????xxxxxxxx                         |
| C 原始字节 + 位图掩码              | 0xE8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xF6, 0x66, 0x44, 0x89, 0x34, 0x33 0b1111111100001 |

```toml
[dependencies]
sigmatch = "0.3"
```

```rust
use sigmatch::{Pattern, ReferenceEncoding, Result, Seeker};

fn example() -> Result<()> {
    let mut seeker = Seeker::with_name("main")?;

    // 简单的区段限定查找。
    let mov = seeker.find_in(
        ".text",
        "B8 ?? ?? ?? ?? C1 C0 05 05 ?? ?? ?? 90 90 90",
    )?;

    // 可以从上一个结果开始，创建完全独立的反向查询。
    let push = seeker
        .scan("6A ?? 89 E0")?
        .in_section(".text")
        .backward_from(mov.address())
        .within(8)
        .first()?;

    // 正向查找和惰性结果遍历使用同一套查询 API。
    let _nearby = seeker
        .scan("90 90")?
        .in_section(".text")
        .forward_from(push.address())
        .within(0x20)
        .first()?;

    // 只解析一次，在多个查询中复用模式。
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

    // 定位字符串，并枚举所有指向它的引用。
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

    // 需要时重绑定到另一个已加载模块。
    seeker.bind("ntdll.dll")?;
    let _ = seeker.find_in(".text", "4C 8B D1")?;

    Ok(())
}
```

查询是惰性的，而且彼此独立：区段和范围会在扫描前确定，`first()` 或 `all()` 决定何时消费结果。`find_in(section, pattern)` 是简单正向查找的简写；需要明确指定方向、字节窗口或遍历结果时使用 `scan`。


## 近期更新

- 增加显式链式查询 API，支持正向、反向、区段和字节窗口控制。
- 增加可复用的文本、掩码字节和位图模式。
- 增加字符串引用查询和明确的 x86/x64 地址解码器。
- 增加事务性模块重绑定和更安全的页面检查。
- 增加针对边界、保护属性、溢出和引用查询的测试。


## 计划中的功能

- [ ] 组合式或命名的多字段引用解码。
- [ ] 更多真实模块集成测试和性能基准。
- [ ] 跨平台支持（Linux、macOS 等）。


## 示例与问题反馈

- 可运行示例见 [examples/demo.rs](examples/demo.rs)。
- Bug 或建议请通过 [issues](https://github.com/piz-ewing/sigmatch/issues) 反馈。
