use std::{ffi::c_void, ops::Deref};

use windows::Win32::{
    Foundation::{SEC_E_INVALID_TOKEN, SEC_E_MESSAGE_ALTERED, SEC_E_OK},
    Security::Authentication::Identity::{
        DecryptMessage, EncryptMessage, QueryContextAttributesW, SECBUFFER_DATA, SECBUFFER_STREAM_HEADER,
        SECBUFFER_STREAM_TRAILER, SECBUFFER_VERSION, SECPKG_ATTR_STREAM_SIZES, SECQOP_WRAP_NO_ENCRYPT, SecBuffer,
        SecBufferDesc, SecPkgContext_StreamSizes,
    },
};
use windows_result::HRESULT;

use crate::context_handle::ContextHandle;

impl ContextHandle {
    /// ONLY USE WITH FINISHED CONTEXT
    pub(crate) fn sign_message(&self, message: &[u8]) -> Signature {
        let sizes = get_context_sizes(self);

        let mut header = vec![0u8; sizes.cbHeader as usize].into_boxed_slice();
        let mut trailer = vec![0u8; sizes.cbTrailer as usize].into_boxed_slice();

        let mut data = message.to_vec();

        let mut buffers = vec![
            SecBuffer {
                cbBuffer: sizes.cbHeader,
                BufferType: SECBUFFER_STREAM_HEADER,
                pvBuffer: header.as_mut_ptr() as *mut c_void,
            },
            SecBuffer {
                cbBuffer: data.len() as u32,
                BufferType: SECBUFFER_DATA,
                pvBuffer: data.as_mut_ptr() as *mut c_void,
            },
            SecBuffer {
                cbBuffer: sizes.cbTrailer as u32,
                BufferType: SECBUFFER_STREAM_TRAILER,
                pvBuffer: trailer.as_mut_ptr() as *mut c_void,
            },
        ];
        let sec_buffer = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: buffers.len() as u32,
            pBuffers: buffers.as_mut_ptr(),
        };
        let res = unsafe { EncryptMessage(self.deref(), SECQOP_WRAP_NO_ENCRYPT, &sec_buffer, 0) };

        match res {
            HRESULT(0) => {
                let signature = [&header, data.as_slice(), &trailer].concat();
                Signature(signature)
            }
            _ => panic!(),
        }
    }
    pub(crate) fn unwrap(&self, message: &[u8]) -> Result<Plaintext, Altered> {
        let sizes = get_context_sizes(self);

        let mut buffer = vec![0; sizes.cbMaximumMessage as usize];
        buffer.copy_from_slice(message);

        let mut buffers = vec![
            SecBuffer {
                cbBuffer: sizes.cbHeader,
                BufferType: SECBUFFER_STREAM_HEADER,
                pvBuffer: message.as_ptr() as *mut c_void,
            },
            SecBuffer {
                cbBuffer: buffer.len() as u32,
                BufferType: SECBUFFER_DATA,
                pvBuffer: buffer.as_mut_ptr() as *mut c_void,
            },
            SecBuffer {
                cbBuffer: sizes.cbTrailer,
                BufferType: SECBUFFER_STREAM_TRAILER,
                pvBuffer: message[(message.len() - sizes.cbTrailer as usize)..].as_ptr() as *mut c_void,
            },
        ];
        let buffer_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: buffers.len() as u32,
            pBuffers: buffers.as_mut_ptr(),
        };
        let mut pfqop = 0;
        let res = unsafe { DecryptMessage(self.deref(), &buffer_desc, 0, Some(&mut pfqop)) };
        match res {
            SEC_E_OK => Ok(Plaintext {
                buffer,
                was_encrypted: pfqop != SECQOP_WRAP_NO_ENCRYPT,
            }),
            SEC_E_MESSAGE_ALTERED | SEC_E_INVALID_TOKEN => Err(Altered),
            err => panic!("Unexpected error code: {} (\"{}\")", err.0, err.message()),
        }
    }
}

fn get_context_sizes(ctx: &ContextHandle) -> SecPkgContext_StreamSizes {
    let mut sizes = SecPkgContext_StreamSizes::default();
    unsafe {
        QueryContextAttributesW(
            ctx.deref(),
            SECPKG_ATTR_STREAM_SIZES,
            std::ptr::from_mut(&mut sizes) as *mut c_void,
        )
        .unwrap()
    };
    sizes
}

pub struct Plaintext {
    buffer: Vec<u8>,
    was_encrypted: bool,
}
impl Plaintext {
    pub fn was_encrypted(&self) -> bool {
        self.was_encrypted
    }
}
impl Deref for Plaintext {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Signature(Vec<u8>);
impl Signature {
    pub fn new(sig: &[u8]) -> Self {
        Self(sig.to_vec())
    }
}
impl Deref for Signature {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[derive(Debug)]
pub struct Altered;
impl std::error::Error for Altered {}
impl std::fmt::Display for Altered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the input message has been altered or the signature is invalid")
    }
}
