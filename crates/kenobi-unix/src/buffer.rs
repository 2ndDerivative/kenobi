use std::{ffi::c_void, ptr};

use libgssapi_sys::{gss_buffer_desc, gss_buffer_desc_struct, gss_channel_bindings_struct, gss_release_buffer};

pub struct Token(gss_buffer_desc);
unsafe impl Sync for Token {}
unsafe impl Send for Token {}
impl Drop for Token {
    fn drop(&mut self) {
        let mut _min = 0;
        let _maj = unsafe { gss_release_buffer(&mut _min, &mut self.0) };
    }
}
impl Token {
    /// # Safety
    /// Must be sole owner of underlying buffer
    pub unsafe fn from_raw(buf: gss_buffer_desc) -> Option<Self> {
        if buf.value.is_null() { None } else { Some(Self(buf)) }
    }
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.0.value as *const u8, self.0.length) }
    }
}

pub(crate) fn empty_token() -> gss_buffer_desc {
    gss_buffer_desc {
        length: 0,
        value: ptr::null_mut(),
    }
}

pub(crate) fn as_channel_bindings(arr: &[u8]) -> gss_channel_bindings_struct {
    gss_channel_bindings_struct {
        initiator_addrtype: 0,
        initiator_address: gss_buffer_desc_struct {
            length: 0,
            value: ptr::null_mut(),
        },
        acceptor_addrtype: 0,
        acceptor_address: gss_buffer_desc_struct {
            length: 0,
            value: ptr::null_mut(),
        },
        application_data: gss_buffer_desc_struct {
            length: arr.len(),
            value: arr.as_ptr() as *mut c_void,
        },
    }
}
