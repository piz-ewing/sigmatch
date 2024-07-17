fn main() {
    let Ok(sker) = sigmatch::Seeker::with_name("main") else {
        return;
    };

    let Ok(addr) = sker.search("00") else {
        return;
    };

    println!("{:#x}", addr.wrapping_sub(sker.module_base()));

    let Ok(sker) = sigmatch::Seeker::with_name("user32.dll") else {
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
        let _rebind_example = sker.bind("main")?.reverse_search("ab cd ?? ef")?;
        Ok(())
    }();

    // new Seeker
    let sker1 = sigmatch::Seeker::new();
    if sker1.bind("ntdll.dll").is_err() {
        return;
    }
}
