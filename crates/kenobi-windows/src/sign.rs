use std::{ffi::c_void, ops::Deref};

use windows::Win32::{
    Foundation::{SEC_E_INVALID_TOKEN, SEC_E_MESSAGE_ALTERED, SEC_E_OK},
    Security::Authentication::Identity::{
        DecryptMessage, EncryptMessage, QueryContextAttributesW, SECBUFFER_DATA, SECBUFFER_PADDING, SECBUFFER_STREAM,
        SECBUFFER_TOKEN, SECBUFFER_VERSION, SECPKG_ATTR_SIZES, SECQOP_WRAP_NO_ENCRYPT, SecBuffer, SecBufferDesc,
        SecPkgContext_Sizes,
    },
};
use windows_result::HRESULT;

use crate::context_handle::ContextHandle;

impl ContextHandle {
    fn wrap_raw(&self, encrypt: bool, message: &[u8]) -> windows_result::Result<Vec<u8>> {
        let sizes = get_context_sizes(self).unwrap();

        let mut header = vec![0u8; sizes.cbSecurityTrailer as usize];
        let mut signature = message.to_vec();
        let mut trailer = vec![0u8; sizes.cbBlockSize as usize];

        let mut buffers = vec![
            SecBuffer {
                cbBuffer: sizes.cbSecurityTrailer,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: header.as_mut_ptr() as *mut c_void,
            },
            SecBuffer {
                cbBuffer: message.len() as u32,
                BufferType: SECBUFFER_DATA,
                pvBuffer: signature.as_mut_ptr() as *mut c_void,
            },
            SecBuffer {
                cbBuffer: sizes.cbBlockSize,
                BufferType: SECBUFFER_PADDING,
                pvBuffer: trailer.as_mut_ptr() as *mut c_void,
            },
        ];
        let sec_buffer = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: buffers.len() as u32,
            pBuffers: buffers.as_mut_ptr(),
        };
        let res = unsafe {
            EncryptMessage(
                self.deref(),
                if encrypt { 0 } else { SECQOP_WRAP_NO_ENCRYPT },
                &sec_buffer,
                0,
            )
        };
        match res {
            HRESULT(0) => {
                let header_sl = &header[..buffers[0].cbBuffer as usize];
                assert_eq!(message.len(), buffers[1].cbBuffer as usize);
                let trailer_sl = &trailer[..buffers[2].cbBuffer as usize];
                let out = [header_sl, &signature, trailer_sl].concat();
                Ok(out)
            }
            err => Err(windows_result::Error::new(err, "")),
        }
    }
    /// ONLY USE WITH FINISHED CONTEXT
    pub(crate) fn wrap_sign(&self, message: &[u8]) -> windows_result::Result<Signature> {
        self.wrap_raw(false, message).map(Signature)
    }
    /// ONLY USED IN A FINISHED, ENCRYPTION-ALLOWED CONTEXT
    pub(crate) fn wrap_encrypt(&self, message: &[u8]) -> windows_result::Result<Encrypted> {
        self.wrap_raw(true, message).map(Encrypted)
    }

    pub(crate) fn unwrap(&self, message: &[u8]) -> Result<Plaintext, Altered> {
        let mut input = message.to_vec();

        let mut buffers = vec![
            SecBuffer {
                BufferType: SECBUFFER_STREAM,
                cbBuffer: message.len() as u32,
                pvBuffer: input.as_mut_ptr() as *mut c_void,
            },
            SecBuffer {
                BufferType: SECBUFFER_DATA,
                cbBuffer: 0,
                pvBuffer: std::ptr::null_mut(),
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
            SEC_E_OK => {
                let header_length = buffers[1].pvBuffer as usize - buffers[0].pvBuffer as usize;
                let data_length = buffers[1].cbBuffer as usize;
                let buffer = input[header_length..header_length + data_length].to_vec();
                Ok(Plaintext {
                    buffer,
                    was_encrypted: pfqop != SECQOP_WRAP_NO_ENCRYPT,
                })
            }
            SEC_E_MESSAGE_ALTERED | SEC_E_INVALID_TOKEN => Err(Altered),
            err => panic!("Unexpected error code: {} (\"{}\")", err.0, err.message()),
        }
    }
}

fn get_context_sizes(ctx: &ContextHandle) -> windows_result::Result<SecPkgContext_Sizes> {
    let mut sizes = SecPkgContext_Sizes::default();
    unsafe {
        QueryContextAttributesW(
            ctx.deref(),
            SECPKG_ATTR_SIZES,
            std::ptr::from_mut(&mut sizes) as *mut c_void,
        )?
    };
    Ok(sizes)
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
#[derive(Clone, Debug, PartialEq)]
pub struct Encrypted(Vec<u8>);
impl Encrypted {
    pub fn new(sig: &[u8]) -> Self {
        Self(sig.to_vec())
    }
}
impl Deref for Encrypted {
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
