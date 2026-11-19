use windows::Win32::System::Memory::{
    MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READONLY,
    PAGE_READWRITE, PAGE_WRITECOPY,
};

pub(crate) fn region_is_readable(info: &MEMORY_BASIC_INFORMATION) -> bool {
    info.State == MEM_COMMIT && protection_is_readable(info.Protect)
}

fn protection_is_readable(protection: PAGE_PROTECTION_FLAGS) -> bool {
    if protection.contains(PAGE_GUARD) || protection.contains(PAGE_NOACCESS) {
        return false;
    }
    matches!(
        protection.0 & 0xff,
        value if value == PAGE_READONLY.0
            || value == PAGE_READWRITE.0
            || value == PAGE_WRITECOPY.0
            || value == PAGE_EXECUTE_READ.0
            || value == PAGE_EXECUTE_READWRITE.0
            || value == PAGE_EXECUTE_WRITECOPY.0
    )
}
