use std::{ffi::c_void, ops::Deref};

use windows::Win32::Security::Authentication::Identity::{FreeContextBuffer, SecPkgContext_SessionKey};

pub struct SessionKey {
    key: &'static [u8],
}
impl SessionKey {
    /// The SessionKey struct must be exclusive owner of the memory behind the session key pointer
    pub(crate) unsafe fn new(raw_handle: SecPkgContext_SessionKey) -> Self {
        Self {
            key: unsafe { std::slice::from_raw_parts(raw_handle.SessionKey, raw_handle.SessionKeyLength as usize) },
        }
    }
}
impl Drop for SessionKey {
    fn drop(&mut self) {
        let _ = unsafe { FreeContextBuffer(self.key.as_ptr() as *mut c_void) };
    }
}
impl Deref for SessionKey {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.key
    }
}
