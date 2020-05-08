#[cfg(target_os = "windows")]
pub unsafe fn raw_alloc(len: usize) -> *mut u8 {
    extern "system" {
        fn VirtualAlloc(addr: *mut u8, len: usize, alloc_type: u32, protect: u32) -> *mut u8;
    }

    const MEM_COMMIT_RESERVE: u32 = 0x1000 | 0x2000;
    const PAGE_READWRITE:     u32 = 4;

    let result = VirtualAlloc(std::ptr::null_mut(), len, MEM_COMMIT_RESERVE, PAGE_READWRITE);

    assert!(!result.is_null(), "Allocating memory with size of {} bytes failed.", len);

    result
}

#[cfg(target_os = "windows")]
pub unsafe fn raw_free(addr: *mut u8) {
    extern "system" {
        fn VirtualFree (addr: *mut u8, len: usize, free_type: u32) -> u32;
    }

    const MEM_RELEASE: u32 = 0x8000;

    let result = VirtualFree(addr, 0, MEM_RELEASE);

    assert!(result != 0, "Freeing memory at addresss {:p} failed.", addr);
}
