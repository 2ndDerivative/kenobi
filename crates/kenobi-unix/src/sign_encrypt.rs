use std::{ffi::c_void, ops::Deref};

use libgssapi_sys::{GSS_C_QOP_DEFAULT, gss_buffer_desc, gss_ctx_id_struct, gss_release_buffer, gss_unwrap, gss_wrap};

use crate::{Error, context::ContextHandle};

pub(crate) fn sign(ctx: &ContextHandle, message: &[u8]) -> Result<Signed, Error> {
    wrap(ctx, false, message).map(Signed)
}
pub(crate) fn encrypt(ctx: &ContextHandle, message: &[u8]) -> Result<Encrypted, Error> {
    wrap(ctx, true, message).map(Encrypted)
}
fn wrap(ctx: &ContextHandle, encrypt: bool, message: &[u8]) -> Result<SecurityBuffer, Error> {
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
            &mut minor,
            ctx.as_ptr() as *mut gss_ctx_id_struct,
            if encrypt { 1 } else { 0 },
            GSS_C_QOP_DEFAULT,
            &mut input_buffer_desc,
            &mut conf_state,
            &mut output_buffer,
        )
    }) {
        return Err(major);
    };
    if let Some(err) = Error::mechanism(minor) {
        return Err(err);
    }
    if encrypt && conf_state == 0 {
        panic!("Failed to encrypt")
    }
    Ok(SecurityBuffer(output_buffer))
}

pub(crate) fn unwrap_raw(ctx: &ContextHandle, message: &[u8]) -> Result<Plaintext, Error> {
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
            &mut minor,
            ctx.as_ptr() as *mut gss_ctx_id_struct,
            &mut input_buffer_desc,
            &mut output_buffer,
            &mut conf_state,
            std::ptr::null_mut(),
        )
    }) {
        return Err(major);
    };
    if let Some(minor) = Error::mechanism(minor) {
        return Err(minor);
    }

    Ok(Plaintext::new(SecurityBuffer(output_buffer), conf_state != 0))
}

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
    pub fn as_slice(&self) -> &[u8] {
        self.buffer.as_slice()
    }
    pub fn was_encrypted(&self) -> bool {
        self.was_encrypted
    }
}

pub struct Encrypted(SecurityBuffer);
impl Encrypted {
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
pub struct Signed(SecurityBuffer);
impl Signed {
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
impl Drop for SecurityBuffer {
    fn drop(&mut self) {
        let mut _min = 0;
        let _maj = unsafe { gss_release_buffer(&mut _min, &mut self.0) };
    }
}
impl SecurityBuffer {
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.0.value as *const u8, self.0.length) }
    }
}
