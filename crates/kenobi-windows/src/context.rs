use std::{
    ffi::c_void,
    mem::ManuallyDrop,
    ops::{Deref, DerefMut},
};

use windows::Win32::Security::{
    Authentication::Identity::{DeleteSecurityContext, FreeContextBuffer, SecPkgContext_SessionKey},
    Credentials::SecHandle,
};

#[derive(Default)]
pub(crate) struct ContextHandle(SecHandle);
impl ContextHandle {
    pub fn leak(self) -> SecHandle {
        ManuallyDrop::new(self).0
    }
    pub unsafe fn pick_up(sec: SecHandle) -> Self {
        Self(sec)
    }
}
impl Deref for ContextHandle {
    type Target = SecHandle;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for ContextHandle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for ContextHandle {
    fn drop(&mut self) {
        let _ = unsafe { DeleteSecurityContext(&self.0) };
    }
}
unsafe impl Send for ContextHandle {}

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
