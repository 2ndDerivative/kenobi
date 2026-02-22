use std::{ffi::c_void, ops::Deref, ptr::NonNull, sync::LazyLock};

use windows::Win32::Security::Authentication::Identity::{FreeContextBuffer, QuerySecurityPackageInfoW, SecBuffer};

use crate::NEGOTIATE;

const FALLBACK_BUFFER_SIZE: u32 = 48256;
static MAX_TOKEN_BUFFER_SIZE: LazyLock<windows_result::Result<u32>> = LazyLock::new(get_max_buffer_size);
fn get_max_buffer_size() -> windows_result::Result<u32> {
    let buf = unsafe { QuerySecurityPackageInfoW(NEGOTIATE)? };
    let size = unsafe { (*buf).cbMaxToken };
    unsafe { FreeContextBuffer(buf as *mut c_void)? };
    Ok(size)
}

pub struct NonResizableVec {
    pointer: NonNull<[u8]>,
    length: u32,
}
impl NonResizableVec {
    fn length_or_fallback() -> u32 {
        *MAX_TOKEN_BUFFER_SIZE.as_ref().unwrap_or(&FALLBACK_BUFFER_SIZE)
    }
    pub fn new() -> Self {
        let length = Self::length_or_fallback();
        let alloc = vec![0u8; length as usize].into_boxed_slice();
        let pointer = unsafe { NonNull::new_unchecked(Box::into_raw(alloc)) };
        NonResizableVec { pointer, length }
    }
    pub fn resize_max(&mut self) {
        self.length = Self::length_or_fallback();
    }
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.pointer.as_ptr() as *const u8, self.length as usize) }
    }
    pub fn sec_buffer(&self, buffer_type: u32) -> SecBuffer {
        SecBuffer {
            cbBuffer: self.length,
            BufferType: buffer_type,
            pvBuffer: self.pointer.as_ptr() as *mut c_void,
        }
    }
}
impl Deref for NonResizableVec {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}
impl Drop for NonResizableVec {
    fn drop(&mut self) {
        let _ = unsafe { Box::from_raw(self.pointer.as_ptr()) };
    }
}
