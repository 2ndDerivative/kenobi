use std::ops::{Deref, DerefMut};

use windows::Win32::Security::{Authentication::Identity::DeleteSecurityContext, Credentials::SecHandle};

#[derive(Default)]
pub struct ContextHandle(SecHandle);
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
