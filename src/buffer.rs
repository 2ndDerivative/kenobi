use std::ffi::c_void;

use windows::Win32::Security::Authentication::Identity::{
    SecBuffer, SecBufferDesc, SECBUFFER_TOKEN, SECBUFFER_VERSION,
};

pub struct SecurityBuffer<'b> {
    buf: SecBuffer,
    i: &'b [u8],
}
impl<'b> SecurityBuffer<'b> {
    pub fn new(i: &'b [u8]) -> Self {
        let inner = SecBuffer {
            cbBuffer: i.len() as u32,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: i.as_ptr() as *mut c_void,
        };
        Self { buf: inner, i }
    }
    pub fn description(&mut self) -> SecBufferDesc {
        SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut self.buf,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.buf.cbBuffer == 0
    }
}

impl AsRef<[u8]> for SecurityBuffer<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.i[0..self.buf.cbBuffer as usize]
    }
}
