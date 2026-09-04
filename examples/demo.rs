//! Executable example for the 0.3.1 query API.

use anyhow::{anyhow, Result};
use log::info;
use sigmatch::{Pattern, Seeker};
use windows::{
    core::s,
    Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress},
};

#[unsafe(naked)]
unsafe extern "C" fn magic_function() {
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

fn main_module_example() -> Result<()> {
    let expected = magic_function as *const () as usize;
    let seeker = Seeker::with_name("main")?;

    let first = seeker
        .scan("6A ?? 89 E0 B8 ?? ?? ?? ?? C1 C0 05 05 ?? ?? ?? 90 90 90")?
        .in_section(".text")
        .first()?;
    assert_eq!(first.address(), expected);
    info!("forward match at {:#x}", first.address());

    let mov = seeker
        .scan("B8 ?? ?? ?? ?? C1 C0 05 05 ?? ?? ?? 90 90 90")?
        .in_section(".text")
        .first()?;
    let reverse = seeker
        .scan("6A ?? 89 E0")?
        .in_section(".text")
        .backward_from(mov.address())
        .within(8)
        .first()?;
    assert_eq!(reverse.address(), expected);
    info!("backward match at {:#x}", reverse.address());

    let nop = seeker
        .scan("90 90")?
        .in_section(".text")
        .forward_from(expected + 0x10)
        .within(2)
        .first()?;
    assert_eq!(nop.address(), expected + 0x10);

    Ok(())
}

fn ntdll_example() -> Result<()> {
    let mut seeker = Seeker::with_name("main")?;
    seeker.bind("ntdll.dll")?;
    let expected = unsafe {
        GetProcAddress(GetModuleHandleA(s!("ntdll.dll"))?, s!("NtCreateProcess"))
            .ok_or_else(|| anyhow!("get proc NtCreateProcess address failed"))? as usize
    };

    let ida = Pattern::signature("? ? ? B8 C0 00 00 00 F6 04 25 ? ? ? ? 01 75 ? 0F 05 C3")?;
    let ida_hit = seeker.scan(&ida)?.first()?.address();
    assert_eq!(ida_hit, expected);
    info!("ntdll signature match at {:#x}", ida_hit);

    // All input forms are normalized to Pattern before scanning. Reusing a
    // parsed Pattern avoids parsing the same signature for every query.
    let masked = Pattern::masked(
        b"\x00\x00\x00\xB8\xC0\x00\x00\x00\xF6\x04\x25",
        "???xxxxxxxx",
    )?;
    let masked_hit = seeker.scan(&masked)?.first()?.address();
    assert_eq!(masked_hit, expected);

    let bitmap = Pattern::bitmap(
        b"\x00\x00\x00\xB8\xC0\x00\x00\x00\xF6\x04\x25",
        0b111_1111_1000,
    )?;
    let bitmap_hit = seeker.scan(&bitmap)?.first()?.address();
    assert_eq!(bitmap_hit, expected);
    Ok(())
}

fn main() {
    pretty_env_logger::formatted_builder()
        .filter_level(log::LevelFilter::Info)
        .init();
    if let Err(error) = main_module_example() {
        log::error!("main module example failed: {error:#}");
    }
    if let Err(error) = ntdll_example() {
        log::error!("ntdll example failed: {error:#}");
    }
}
