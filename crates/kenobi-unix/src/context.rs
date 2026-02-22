use std::{ops::Deref, ptr::NonNull};

use libgssapi_sys::{
    GSS_C_INQ_SSPI_SESSION_KEY, gss_buffer_set_desc_struct, gss_ctx_id_struct, gss_delete_sec_context,
    gss_inquire_sec_context_by_oid, gss_release_buffer_set,
};

use crate::Error;

pub struct ContextHandle(NonNull<gss_ctx_id_struct>);
impl ContextHandle {
    pub fn new(ctx: NonNull<gss_ctx_id_struct>) -> Self {
        Self(ctx)
    }
    pub fn as_mut(&mut self) -> &mut gss_ctx_id_struct {
        unsafe { self.0.as_mut() }
    }
    pub fn session_key(&self) -> Result<SessionKey, Error> {
        let mut minor = 0;
        let mut buffer_set: *mut gss_buffer_set_desc_struct = std::ptr::null_mut();
        let major = unsafe {
            gss_inquire_sec_context_by_oid(
                &mut minor,
                self.0.as_ptr(),
                GSS_C_INQ_SSPI_SESSION_KEY,
                std::ptr::from_mut(&mut buffer_set),
            )
        };
        if let Some(err) = Error::gss(major) {
            return Err(err);
        } else if let Some(minor_err) = Error::mechanism(minor) {
            return Err(minor_err);
        }
        Ok(SessionKey(buffer_set))
    }
}
impl Drop for ContextHandle {
    fn drop(&mut self) {
        let mut _s = 0;
        unsafe { gss_delete_sec_context(&mut _s, &mut NonNull::as_ptr(self.0), std::ptr::null_mut()) };
    }
}

pub struct SessionKey(*mut gss_buffer_set_desc_struct);
impl SessionKey {
    pub fn as_slice(&self) -> &[u8] {
        let deref: gss_buffer_set_desc_struct = unsafe { *self.0 };
        let key = unsafe { std::slice::from_raw_parts_mut(deref.elements, deref.count) }[0];
        unsafe { std::slice::from_raw_parts(key.value as *const u8, key.length as usize) }
    }
}
impl Drop for SessionKey {
    fn drop(&mut self) {
        let mut _min = 0;
        let _maj = unsafe { gss_release_buffer_set(&mut _min, &mut self.0) };
    }
}
impl Deref for SessionKey {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}
