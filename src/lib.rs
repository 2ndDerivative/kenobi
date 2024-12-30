use std::{
    error::Error,
    ffi::{c_void, OsStr, OsString},
    fmt::{Display, Formatter},
    mem::{transmute, MaybeUninit},
    os::windows::ffi::OsStrExt,
    sync::LazyLock,
};

use credentials::Credentials;
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{
            SEC_E_INCOMPLETE_MESSAGE, SEC_E_INSUFFICIENT_MEMORY, SEC_E_INTERNAL_ERROR, SEC_E_INVALID_HANDLE,
            SEC_E_INVALID_TOKEN, SEC_E_LOGON_DENIED, SEC_E_NO_AUTHENTICATING_AUTHORITY, SEC_E_NO_CREDENTIALS, SEC_E_OK,
            SEC_E_UNSUPPORTED_FUNCTION,
        },
        Security::{
            Authentication::Identity::{
                AcceptSecurityContext, FreeContextBuffer, QuerySecurityPackageInfoW, SecBuffer, SecBufferDesc,
                ASC_REQ_CONFIDENTIALITY, ASC_REQ_MUTUAL_AUTH, SECBUFFER_TOKEN, SECBUFFER_VERSION, SECURITY_NATIVE_DREP,
            },
            Credentials::SecHandle,
        },
    },
};

static NEGOTIATE_ZERO_TERM_UTF16: LazyLock<Box<[u16]>> = LazyLock::new(|| {
    OsStr::new("Negotiate")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
});

mod attributes;
mod credentials;

pub type StepResult = Result<StepSuccess, StepError>;

pub trait Step {
    fn step(self, token: &[u8]) -> Result<StepSuccess, StepError>;
}
pub struct Handle<'s>(&'s SecHandle);
pub trait SecurityInfo {
    fn security_info(&self) -> Handle;
    fn client_name(&self) -> Result<OsString, String> {
        attributes::client_name(self.security_info().0)
    }
    fn client_native_name(&self) -> Result<OsString, String> {
        attributes::client_native_name(self.security_info().0)
    }
    fn server_native_name(&self) -> Result<OsString, String> {
        attributes::server_native_name(self.security_info().0)
    }
}
pub struct ContextBuilder {
    credentials: Credentials,
    max_context_length: usize,
}
impl ContextBuilder {
    pub fn new(principal: Option<&str>) -> Result<Self, String> {
        let credentials = Credentials::new(principal)?;
        let max_context_length = unsafe {
            let info = QuerySecurityPackageInfoW(PCWSTR(NEGOTIATE_ZERO_TERM_UTF16.as_ptr().cast()))
                .map_err(|e| e.message())?;
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
impl Step for ContextBuilder {
    fn step(self, token: &[u8]) -> StepResult {
        step(
            self.credentials,
            None,
            0,
            token,
            vec![0; self.max_context_length].into_boxed_slice(),
        )
    }
}
pub struct PendingContext {
    credentials: Credentials,
    context: Box<SecHandle>,
    buffer: Box<[u8]>,
    attr_flags: u32,
}
impl std::fmt::Debug for PendingContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingContext")
    }
}
impl SecurityInfo for PendingContext {
    fn security_info(&self) -> Handle {
        Handle(self.context.as_ref())
    }
}
impl Step for PendingContext {
    fn step(self, token: &[u8]) -> StepResult {
        let Self {
            credentials,
            context,
            buffer,
            attr_flags,
        } = self;
        step(credentials, Some(context), attr_flags, token, buffer)
    }
}
fn step(
    credentials: Credentials,
    context: Option<Box<SecHandle>>,
    mut attr_flags: u32,
    token: &[u8],
    output_buffer: Box<[u8]>,
) -> StepResult {
    let mut in_buf = SecBuffer {
        cbBuffer: token.len() as u32,
        BufferType: SECBUFFER_TOKEN,
        pvBuffer: token.as_ptr() as *mut c_void,
    };
    let in_buf_desc = SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: 1,
        pBuffers: &mut in_buf,
    };
    let mut out_buf = SecBuffer {
        cbBuffer: output_buffer.len() as u32,
        BufferType: SECBUFFER_TOKEN,
        pvBuffer: output_buffer.as_ptr() as *mut c_void,
    };
    let mut out_buf_desc = SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: 1,
        pBuffers: &mut out_buf,
    };
    let ph_context: Option<*const SecHandle> = match &context {
        Some(bx) => Some(&**bx),
        None => None,
    };
    let mut context: Box<MaybeUninit<SecHandle>> = match context {
        // T -> MaybeUninit<T> is always safe
        Some(bx) => unsafe { transmute::<Box<SecHandle>, Box<MaybeUninit<SecHandle>>>(bx) },
        None => Box::new_uninit(),
    };
    let res = unsafe {
        // step() consumes the Context, therefore all of these references as pointers should be thread safe
        AcceptSecurityContext(
            Some(credentials.handle()),
            ph_context,
            Some(&in_buf_desc),
            ASC_REQ_CONFIDENTIALITY | ASC_REQ_MUTUAL_AUTH,
            SECURITY_NATIVE_DREP,
            Some(context.as_mut_ptr()),
            Some(&mut out_buf_desc),
            &mut attr_flags,
            Some(&mut 0),
        )
    };
    let is_done = match res {
        SEC_E_OK => true,
        SEC_E_INCOMPLETE_MESSAGE => return Err(StepError::IncompleteMessage),
        SEC_E_INSUFFICIENT_MEMORY => panic!("Insufficient memory for the security operation"),
        SEC_E_INVALID_HANDLE => {
            panic!("Invalid handle. Something went wrong on the library side. Please contact the maintainer")
        }
        SEC_E_INTERNAL_ERROR => panic!("Internal SSPI error."),
        SEC_E_NO_CREDENTIALS => panic!(
            "Invalid credentials handle. Something went wrong on the library side. Please contact the maintainer"
        ),
        SEC_E_UNSUPPORTED_FUNCTION => unreachable!(
            "Unsupported function error. should be impossible without ASC_REQ_DELEGATE or ASC_REQ_PROMPT_FOR_CREDS"
        ),
        SEC_E_NO_AUTHENTICATING_AUTHORITY => return Err(StepError::NoAuthenticatingAuthority),
        SEC_E_INVALID_TOKEN => return Err(StepError::InvalidToken),
        SEC_E_LOGON_DENIED => return Err(StepError::LogonDenied),
        x if x.0.is_negative() => panic!("Unknown OS error. code: {}, message {}", x.0, x.message()),
        _ => false,
    };
    // Documentation claims to always write initialized Context into here if there was no error
    let context = unsafe { context.assume_init() };
    let response_token = (out_buf.cbBuffer > 0).then_some(output_buffer[0..out_buf.cbBuffer as usize].into());
    if is_done {
        Ok(StepSuccess::Finished(FinishedContext { context }, response_token))
    } else {
        Ok(StepSuccess::Continue(
            PendingContext {
                credentials,
                context,
                buffer: output_buffer,
                attr_flags,
            },
            response_token.expect("Windows expects to continue, but didn't provide a token"),
        ))
    }
}
pub struct FinishedContext {
    context: Box<SecHandle>,
}
impl std::fmt::Debug for FinishedContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("FinishedContext")
    }
}
impl FinishedContext {
    pub fn client_target(&self) -> Result<OsString, String> {
        attributes::client_target(&self.context)
    }
}
impl SecurityInfo for FinishedContext {
    fn security_info(&self) -> Handle {
        Handle(self.context.as_ref())
    }
}
#[derive(Debug)]
pub enum StepSuccess {
    Finished(FinishedContext, Option<Box<[u8]>>),
    Continue(PendingContext, Box<[u8]>),
}
#[derive(Debug)]
/// More easily discernable Errors from the operating System that may happen in Negotiate stepping.
pub enum StepError {
    InvalidToken,
    LogonDenied,
    NoAuthenticatingAuthority,
    IncompleteMessage,
}
impl Error for StepError {}
impl Display for StepError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidToken => write!(f, "{SEC_E_INVALID_TOKEN}"),
            Self::LogonDenied => write!(f, "{SEC_E_LOGON_DENIED}"),
            Self::NoAuthenticatingAuthority => write!(f, "{SEC_E_NO_AUTHENTICATING_AUTHORITY}"),
            Self::IncompleteMessage => write!(f, "{SEC_E_INCOMPLETE_MESSAGE}"),
        }
    }
}
