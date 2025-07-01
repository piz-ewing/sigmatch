use anyhow::{anyhow, Result};
use log::*;
use windows::{
    core::s,
    Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress},
};

#[unsafe(naked)]
pub(crate) unsafe extern "C" fn magic_function() {
    std::arch::naked_asm! {
        "push 0",
        "mov eax, esp",
        "mov eax, 0x12345678",
        "rol eax, 5",
        "add eax, 0x90ABCDEF",
        "nop",
        "nop",
        "nop",
    };
}

fn example() -> Result<()> {
    let expected = magic_function as usize;

    let sker = sigmatch::Seeker::with_name("main")?;

    info!("🔍 Searching: forward search (push+mov+mov eax...)");
    let addr = sker
        .search("6A ?? 89 E0 B8 ?? ?? ?? ?? C1 C0 05 05 ?? ?? ?? 90 90 90")?
        .addr()?;
    assert_eq!(
        addr, expected,
        "search address mismatch, found {addr:#x}, expected {expected:#x}"
    );

    info!("🔍 Searching: reverse from mov eax block to push pattern");
    let addr = sker
        .search("B8 ?? ?? ?? ?? C1 C0 05 05 ?? ?? ?? 90 90 90")?
        .reverse_search("6A ?? 89 E0")?
        .addr()?;
    assert_eq!(
        addr, expected,
        "reverse search address mismatch, found {addr:#x}, expected {expected:#x}"
    );

    info!("🔍 Searching: complex range offset+limit+debug combo");
    let addr = sker
        .debug()
        .search("B8 ?? ?? ?? ?? C1 C0 05 05 ?? ?? ?? 90 90 90")?
        .debug()
        .limit(8) // offset(4) + pattern_len(4)
        .reverse_search("6A ?? 89 E0")?
        .offset(0x10) // offset(16) + pattern_len(2)
        .limit(2)
        .debug()
        .search("90 90")?
        .debug()
        .addr()?;
    assert_eq!(
        addr,
        expected + 0x10,
        "reverse search address mismatch, found {addr:#x}, expected {expected:#x}"
    );

    info!("🔄 Rebinding module to ntdll.dll...");
    sker.bind("ntdll.dll")?;

    // quick test
    let expected = unsafe {
        GetProcAddress(GetModuleHandleA(s!("ntdll.dll"))?, s!("NtCreateProcess"))
            .ok_or_else(|| anyhow!("get proc NtCreateProcess address failed"))? as usize
    };

    info!("🔍 IDA-style signature search");
    let _ida_example = sker
        .search("? ? ? B8 C0 00 00 00 F6 04 25 ? ? ? ? 01 75 ? 0F 05 C3")?
        .addr()?;
    assert_eq!(
        _ida_example, expected,
        "_ida_exampl address mismatch, found {_ida_example:#x}, expected {expected:#x}"
    );

    info!("🔍 x64dbg-style signature search");
    let _x64dbg_example = sker.search("?? ?? ?? B8 C0 00 00 00 F6 04 25")?.addr()?;
    assert_eq!(
        _x64dbg_example, expected,
        "_x64dbg_example address mismatch, found {_x64dbg_example:#x}, expected {expected:#x}"
    );

    info!("🔍 C-style raw bytes + mask search");
    let _c_example = sker.raw_search(
        b"\x00\x00\x00\xB8\xC0\x00\x00\x00\xF6\x04\x25",
        "???xxxxxxxx",
    )?;
    assert_eq!(
        _c_example, expected,
        "_c_example address mismatch, found {_c_example:#x}, expected {expected:#x}"
    );

    info!("🔍 C-style raw bytes + bitmap search");
    let _c_bitmap_example = sker.raw_search_bitmap(
        b"\x00\x00\x00\xB8\xC0\x00\x00\x00\xF6\x04\x25",
        0b00011111111,
    )?;
    assert_eq!(
        _c_bitmap_example, expected,
        "_c_bitmap_example address mismatch, found {_c_bitmap_example:#x}, expected {expected:#x}"
    );
    info!("✅ Match successful!");
    Ok(())
}

fn test_edge_cases() -> sigmatch::Result<()> {
    use log::info;

    let sker = sigmatch::Seeker::with_name("main")?;
    unsafe {
        sker.unchecked();
    }

    let base = sker.module_base();
    let size = sker.module_size();
    let end = sker.module_end();

    info!("🔍 Test: reverse search '4d 5a' from module end");
    let addr = sker
        .offset(size - 2)
        .limit(2)
        .reverse_search("4d 5a")?
        .addr()?;
    assert_eq!(addr, base, "Failed: reverse search to find MZ header");

    info!("🔍 Test: reverse search '00 00' from module end");
    let addr = sker.limit(2).reverse_search("00 00")?.addr()?;
    assert_eq!(addr, end - 1, "Failed: reverse search for 00 00 at end");

    info!("🔍 Test: reverse search '00 00' then reverse search '4d 5a' after offset");
    let addr = sker
        .limit(2)
        .reverse_search("00 00")?
        .offset(size - 3)
        .reverse_search("4d 5a")?
        .addr()?;
    assert_eq!(addr, base, "Failed: chained reverse search for MZ");

    info!("🔍 Test: reverse search '00 00', sub(), forward search '4d 5a'");
    let addr = sker
        .limit(2)
        .reverse_search("00 00")?
        .sub(size - 2)
        .search("4d 5a")?
        .addr()?;
    assert_eq!(addr, base, "Failed: sub then forward search for MZ");

    info!("🔍 Test: forward search '4d 5a' twice");
    let addr = sker.search("4d 5a")?.search("4d 5a")?.addr()?;
    assert_eq!(addr, base, "Failed: double forward search for MZ");

    info!("🔍 Test: debug -> search -> add -> reverse search");
    let addr = sker
        .debug()
        .search("4d 5a")?
        .limit(10)
        .add(2)
        .debug()
        .reverse_search("4d 5a")?
        .addr()?;
    assert_eq!(addr, base, "Failed: debug > offset > reverse search");

    info!("🔍 Test: forward search '00 00' twice near end");
    let addr = sker
        .offset(size - 2)
        .search("00 00")?
        .search("00 00")?
        .addr()?;
    assert_eq!(addr, end - 1, "Failed: repeated forward search 00 00");

    info!("🔍 Test: reverse search '00 00' from near base");
    let addr = sker.offset(2).reverse_search("00 00")?.addr()?;
    assert_eq!(
        addr,
        end - 3,
        "Failed: reverse search 00 00 from near start"
    );

    info!("🧪 Test: pattern length too long near module end (expect error)");
    let result = sker.offset(size - 1).limit(1).reverse_search("00 00"); // len=2 but only 1 byte left
    assert!(
        matches!(result, Err(sigmatch::Error::SearchLengthTooShort { .. })),
        "Expected PatternOutOfBounds error"
    );

    info!("🧪 Test: pattern not found");
    let result = sker.search("DE AD BE EF");
    assert!(
        matches!(result, Err(sigmatch::Error::PatternNotFound)),
        "Expected PatternNotFound error"
    );

    info!("🧪 Test: search length less than pattern length (expect error)");
    let result = sker.offset(0).limit(1).search("00 00"); // pattern len = 2, limit = 1
    assert!(
        matches!(result, Err(sigmatch::Error::SearchLengthTooShort(_, _))),
        "Expected SearchLengthTooShort error"
    );

    info!("🧪 Test: pattern spanning page boundary");
    let page_size = 0x1000;
    let addr = sker
        .offset(page_size - 1)
        .limit(4)
        .search("?? ?? ??")?
        .addr()?;
    assert!(addr >= base, "Expected valid address crossing page");

    info!("🧪 Test: offset exceeds module boundary, expect OffsetOutOfModule error");
    let result = sker.offset(size + 100).reverse_search("4d 5a");
    assert!(
        matches!(result, Err(sigmatch::Error::OffsetOutOfModule(..))),
        "Expected OffsetOutOfModule error"
    );

    info!("🧪 Test: empty pattern input, expect InvalidPattern error");
    let result = sker.search("");
    assert!(
        matches!(result, Err(sigmatch::Error::InvalidPattern(_, _))),
        "Empty pattern should return InvalidPattern"
    );

    info!("✅ All edge case tests passed.");
    Ok(())
}

fn main() {
    pretty_env_logger::formatted_builder()
        .filter_level(log::LevelFilter::Info)
        .init();
    match example() {
        Ok(_) => {}
        Err(e) => error!("Error: {e:#}"),
    }
    match test_edge_cases() {
        Ok(_) => {}
        Err(e) => error!("Error: {e:#}"),
    }
}
