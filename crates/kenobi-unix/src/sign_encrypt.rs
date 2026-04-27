use std::{
    ffi::c_void,
    fmt::{Debug, Formatter, Result as FmtResult},
    ops::Deref,
};

use libgssapi_sys::{GSS_C_QOP_DEFAULT, gss_buffer_desc, gss_release_buffer, gss_unwrap, gss_wrap};

use crate::{Error, context::ContextHandle};

pub(crate) fn sign(ctx: &mut ContextHandle, message: &[u8]) -> Result<Signed, Error> {
    wrap(ctx, false, message).map(Signed)
}
pub(crate) fn encrypt(ctx: &mut ContextHandle, message: &[u8]) -> Result<Encrypted, Error> {
    wrap(ctx, true, message).map(Encrypted)
}
fn wrap(ctx: &mut ContextHandle, encrypt: bool, message: &[u8]) -> Result<SecurityBuffer, Error> {
    let mut minor = 0;
    let mut input_buffer_desc = gss_buffer_desc {
        length: message.len(),
        value: message.as_ptr() as *mut c_void,
    };
    let mut output_buffer = gss_buffer_desc {
        length: 0,
        value: std::ptr::null_mut(),
    };

    let mut conf_state = 0;
    if let Some(major) = Error::gss(unsafe {
        gss_wrap(
            &raw mut minor,
            ctx.as_ptr().cast_mut(),
            i32::from(encrypt),
            GSS_C_QOP_DEFAULT,
            &raw mut input_buffer_desc,
            &raw mut conf_state,
            &raw mut output_buffer,
        )
    }) {
        return Err(major);
    }
    if let Some(err) = Error::mechanism(minor) {
        return Err(err);
    }
    assert!(!(encrypt && conf_state == 0), "Failed to encrypt");
    Ok(SecurityBuffer(output_buffer))
}

pub(crate) fn unwrap_raw(ctx: &mut ContextHandle, message: &[u8]) -> Result<Plaintext, Error> {
    let mut minor = 0;
    let mut input_buffer_desc = gss_buffer_desc {
        length: message.len(),
        value: message.as_ptr() as *mut c_void,
    };
    let mut output_buffer = gss_buffer_desc {
        length: 0,
        value: std::ptr::null_mut(),
    };
    let mut conf_state = 0;
    if let Some(major) = Error::gss(unsafe {
        gss_unwrap(
            &raw mut minor,
            ctx.as_ptr().cast_mut(),
            &raw mut input_buffer_desc,
            &raw mut output_buffer,
            &raw mut conf_state,
            std::ptr::null_mut(),
        )
    }) {
        return Err(major);
    }
    if let Some(minor) = Error::mechanism(minor) {
        return Err(minor);
    }

    Ok(Plaintext::new(SecurityBuffer(output_buffer), conf_state != 0))
}

#[derive(Debug)]
pub struct Plaintext {
    buffer: SecurityBuffer,
    was_encrypted: bool,
}
impl Plaintext {
    fn new(buffer: SecurityBuffer, was_encrypted: bool) -> Self {
        Self { buffer, was_encrypted }
    }
}
impl Deref for Plaintext {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}
impl Plaintext {
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.buffer.as_slice()
    }
    #[must_use]
    pub fn was_encrypted(&self) -> bool {
        self.was_encrypted
    }
}

#[derive(Debug)]
pub struct Encrypted(SecurityBuffer);
impl Encrypted {
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}
impl Deref for Encrypted {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}
impl AsRef<[u8]> for Encrypted {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}
#[derive(Debug)]
pub struct Signed(SecurityBuffer);
impl Signed {
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}
impl AsRef<[u8]> for Signed {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

struct SecurityBuffer(gss_buffer_desc);
unsafe impl Send for SecurityBuffer {}
unsafe impl Sync for SecurityBuffer {}
impl Debug for SecurityBuffer {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        self.as_slice().fmt(f)
    }
}
impl Drop for SecurityBuffer {
    fn drop(&mut self) {
        let mut min = 0;
        let _maj = unsafe { gss_release_buffer(&raw mut min, &raw mut self.0) };
    }
}
impl SecurityBuffer {
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.0.value as *const u8, self.0.length) }
    }
}
