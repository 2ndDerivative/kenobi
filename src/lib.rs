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
                AcceptSecurityContext, DeleteSecurityContext, QuerySecurityPackageInfoW, SecBuffer,
                SecBufferDesc, ASC_REQ_CONFIDENTIALITY, ASC_REQ_MUTUAL_AUTH, SECBUFFER_TOKEN,
                SECBUFFER_VERSION, SECURITY_NATIVE_DREP,
            },
            Credentials::SecHandle,
        },
    },
};

mod credentials;

pub struct Context {
    credentials: Credentials,
    context: Option<Box<SecHandle>>,
    buffer: Box<[u8]>,
    attr_flags: u32,
}
impl Context {
    pub fn new(principal: Option<&str>) -> Result<Self, String> {
        let credentials = Credentials::new(principal)?;
        let max_context_length = unsafe {
            let info = QuerySecurityPackageInfoW(PCWSTR(to_boxed_zero_term("Negotiate").as_ptr()))
                .unwrap();
            (*info).cbMaxToken as usize
        };
        let buffer = vec![0; max_context_length].into_boxed_slice();
        Ok(Context {
            credentials,
            context: None,
            buffer,
            attr_flags: 0,
        })
    }
    pub fn step(&mut self, token: &[u8]) -> StepResult {
        let mut out_buf = SecBuffer {
            cbBuffer: self.buffer.len() as u32,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: self.buffer.as_mut_ptr() as *mut c_void,
        };
        let mut secbuffer = SecBuffer {
            cbBuffer: token.len() as u32,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: token.as_ptr() as *mut c_void,
        };
        let in_buf_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut secbuffer,
        };
        let mut out_buf_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut out_buf,
        };
        let context_ptr_c: Option<*const SecHandle> = match &mut self.context {
            Some(b) => Some(&**b),
            None => None,
        };
        let context_ptr: *mut SecHandle = match &mut self.context {
            Some(b) => &mut **b,
            None => std::ptr::null_mut(),
        };
        let res = unsafe {
            AcceptSecurityContext(
                Some(self.credentials.handle()),
                context_ptr_c,
                Some(&in_buf_desc),
                ASC_REQ_CONFIDENTIALITY | ASC_REQ_MUTUAL_AUTH,
                SECURITY_NATIVE_DREP,
                Some(context_ptr),
                Some(&mut out_buf_desc),
                &mut self.attr_flags,
                Some(&mut 0),
            )
        };
        let is_done = res == SEC_E_OK;
        if res.0.is_negative() {
            return StepResult::Error(res.message());
        };
        let response_token = (out_buf.cbBuffer > 0).then_some({
            let mut out = vec![0; out_buf.cbBuffer as usize];
            self.buffer.as_ref().read_exact(&mut out).unwrap();
            out.into_boxed_slice()
        });
        if is_done {
            StepResult::Finished(response_token)
        } else {
            StepResult::Continue(response_token)
        }
    }
}
impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            if let Some(ctx) = &mut self.context {
                let _ = DeleteSecurityContext(ctx.as_mut());
            }
        }
    }
}
pub enum StepResult {
    Finished(Option<Box<[u8]>>),
    Continue(Option<Box<[u8]>>),
    Error(String),
}
impl std::fmt::Debug for StepResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Finished(_) => f.write_str("Finished"),
            Self::Error(e) => write!(f, "Error: {e}"),
            Self::Continue(c) => {
                if let Some(c) = c {
                    let x = String::from_utf8_lossy(c);
                    write!(f, "Continue with: {x}")
                } else {
                    f.write_str("Continue")
                }
            }
        }
    }
}

fn to_boxed_zero_term(s: &str) -> Box<[u16]> {
    let mut v = OsString::from(s).encode_wide().collect::<Vec<_>>();
    v.push(0);
    v.into_boxed_slice()
}
