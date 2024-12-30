use std::{
    ffi::{c_void, OsString},
    io::Read,
    os::windows::ffi::OsStrExt,
};

use credentials::Credentials;
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::SEC_E_OK,
        Security::{
            Authentication::Identity::{
                AcceptSecurityContext, DeleteSecurityContext, FreeContextBuffer, QuerySecurityPackageInfoW, SecBuffer,
                SecBufferDesc, ASC_REQ_CONFIDENTIALITY, ASC_REQ_MUTUAL_AUTH, SECBUFFER_TOKEN, SECBUFFER_VERSION,
                SECURITY_NATIVE_DREP,
            },
            Credentials::SecHandle,
        },
    },
};

mod credentials;

pub trait Step {
    fn step(self, token: &[u8]) -> StepResult;
}

pub struct ContextBuilder {
    credentials: Credentials,
    max_context_length: usize,
}
struct TokenBuffer<'b> {
    token: &'b [u8],
    buffer: SecBuffer,
    buffer_desc: SecBufferDesc,
}
impl<'b> TokenBuffer<'b> {
    fn new(token: &'b [u8]) -> Self {
        let mut buffer = SecBuffer {
            cbBuffer: token.len() as u32,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: token.as_ptr() as *mut c_void,
        };
        let buffer_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut buffer,
        };
        Self {
            token,
            buffer,
            buffer_desc,
        }
    }
    fn read(&mut self) -> Option<Box<[u8]>> {
        (self.buffer.cbBuffer > 0).then_some({
            let mut out = vec![0; self.buffer.cbBuffer as usize];
            self.token.read_exact(&mut out).unwrap();
            out.into_boxed_slice()
        })
    }
}
impl Step for ContextBuilder {
    fn step(mut self, token: &[u8]) -> StepResult {
        let mut buffer = vec![0; self.max_context_length].into_boxed_slice();
        let in_buf = TokenBuffer::new(token);
        let mut out_buf = TokenBuffer::new(&buffer);
        let context_ptr_mut = std::ptr::null_mut();
        let mut attr_flags = 0;
        let res = unsafe {
            // step() consumes the Context, therefore all of these references as pointers should be thread safe
            AcceptSecurityContext(
                Some(self.credentials.handle()),
                Some(context_ptr_mut),
                Some(&in_buf.buffer_desc),
                ASC_REQ_CONFIDENTIALITY | ASC_REQ_MUTUAL_AUTH,
                SECURITY_NATIVE_DREP,
                Some(context_ptr_mut),
                Some(&mut out_buf.buffer_desc),
                &mut attr_flags,
                Some(&mut 0),
            )
        };
        let is_done = res == SEC_E_OK;
        if res.0.is_negative() {
            return StepResult::Error(res.message());
        };
        let response_token = out_buf.read();
        if is_done {
            StepResult::Finished(
                FinishedContext {
                    _context: unsafe { Box::from_raw(context_ptr_mut) },
                },
                response_token,
            )
        } else {
            StepResult::Continue(
                PendingContext {
                    credentials: std::mem::take(&mut self.credentials),
                    context: unsafe { Box::from_raw(context_ptr_mut) },
                    buffer: std::mem::take(&mut buffer),
                    attr_flags,
                },
                response_token.unwrap(),
            )
        }
    }
}
pub struct PendingContext {
    credentials: Credentials,
    context: Box<SecHandle>,
    buffer: Box<[u8]>,
    attr_flags: u32,
}
pub struct FinishedContext {
    _context: Box<SecHandle>,
}
impl FinishedContext {
    pub fn client(&self) -> Result<String, String> {
        todo!()
    }
}
impl ContextBuilder {
    pub fn new(principal: Option<&str>) -> Result<Self, String> {
        let credentials = Credentials::new(principal)?;
        let max_context_length = unsafe {
            let info =
                QuerySecurityPackageInfoW(PCWSTR(to_boxed_zero_term("Negotiate").as_ptr())).map_err(|e| e.message())?;
            let context_length = (*info).cbMaxToken as usize;
            FreeContextBuffer(info as *mut c_void).map_err(|e| e.message())?;
            context_length
        };
        Ok(ContextBuilder {
            credentials,
            max_context_length,
        })
    }
}
impl Step for PendingContext {
    fn step(mut self, token: &[u8]) -> StepResult {
        let in_buf = TokenBuffer::new(token);
        let mut out_buf = TokenBuffer::new(&self.buffer);
        let context_ptr_mut = Box::into_raw(std::mem::take(&mut self.context));
        let res = unsafe {
            // step() consumes the Context, therefore all of these references as pointers should be thread safe
            AcceptSecurityContext(
                Some(self.credentials.handle()),
                Some(context_ptr_mut),
                Some(&in_buf.buffer_desc),
                ASC_REQ_CONFIDENTIALITY | ASC_REQ_MUTUAL_AUTH,
                SECURITY_NATIVE_DREP,
                Some(context_ptr_mut),
                Some(&mut out_buf.buffer_desc),
                &mut self.attr_flags,
                Some(&mut 0),
            )
        };
        let is_done = res == SEC_E_OK;
        if res.0.is_negative() {
            return StepResult::Error(res.message());
        };
        let response_token = out_buf.read();
        if is_done {
            StepResult::Finished(
                FinishedContext {
                    _context: unsafe { Box::from_raw(context_ptr_mut) },
                },
                response_token,
            )
        } else {
            StepResult::Continue(
                PendingContext {
                    credentials: std::mem::take(&mut self.credentials),
                    context: unsafe { Box::from_raw(context_ptr_mut) },
                    buffer: std::mem::take(&mut self.buffer),
                    attr_flags: self.attr_flags,
                },
                response_token.unwrap(),
            )
        }
    }
}
impl Drop for PendingContext {
    fn drop(&mut self) {
        unsafe {
            let _ = DeleteSecurityContext(self.context.as_mut());
        }
    }
}
pub enum StepResult {
    Finished(FinishedContext, Option<Box<[u8]>>),
    Continue(PendingContext, Box<[u8]>),
    Error(String),
}

fn to_boxed_zero_term(s: &str) -> Box<[u16]> {
    let mut v = OsString::from(s).encode_wide().collect::<Vec<_>>();
    v.push(0);
    v.into_boxed_slice()
}
