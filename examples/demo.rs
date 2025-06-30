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
        .search("B8 ?? ?? ?? ?? C1 C0 05 05 ?? ?? ?? 90 90 90")?
        .limit(8) // offset(4) + pattern_len(4)
        .reverse_search("6A ?? 89 E0")?
        .offset(16) // offset(16) + pattern_len(1)
        .limit(1)
        .debug()
        .search("90")?
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

fn main() {
    pretty_env_logger::formatted_builder()
        .filter_level(log::LevelFilter::Info)
        .init();
    match example() {
        Ok(_) => {}
        Err(e) => error!("Error: {e:#}"),
    }
}
