//! Wrapper struct to handle guaranteed DeleteSecurityContext
use std::{
    error::Error,
    fmt::{Display, Formatter},
    mem::{transmute, MaybeUninit},
    ops::{Deref, DerefMut},
};

use windows::Win32::{
    Foundation::{
        SEC_E_INCOMPLETE_MESSAGE, SEC_E_INSUFFICIENT_MEMORY, SEC_E_INTERNAL_ERROR, SEC_E_INVALID_HANDLE,
        SEC_E_INVALID_TOKEN, SEC_E_LOGON_DENIED, SEC_E_NO_AUTHENTICATING_AUTHORITY, SEC_E_NO_CREDENTIALS, SEC_E_OK,
        SEC_E_UNSUPPORTED_FUNCTION,
    },
    Security::{
        Authentication::Identity::{
            AcceptSecurityContext, DeleteSecurityContext, ASC_REQ_CONFIDENTIALITY, ASC_REQ_MUTUAL_AUTH,
            SECURITY_NATIVE_DREP,
        },
        Credentials::SecHandle,
    },
};

use crate::{buffer::SecurityBuffer, credentials::CredentialsHandle, FinishedContext, PendingContext, StepResult};

pub trait Step {
    fn step(self, token: &[u8]) -> Result<StepSuccess, StepError>;
}

pub struct ContextHandle(SecHandle);
impl ContextHandle {
    pub fn step(
        credentials: CredentialsHandle,
        context: Option<ContextHandle>,
        mut attr_flags: u32,
        token: &[u8],
        buffer: Box<[u8]>,
    ) -> StepResult {
        let mut in_buf = SecurityBuffer::new(token);
        let mut out_buf = SecurityBuffer::new(&buffer);
        let old_context: Option<*const SecHandle> = context.as_deref().map(std::ptr::from_ref);
        let mut context: MaybeUninit<SecHandle> = match context {
            // T -> MaybeUninit<T> is always safe
            Some(bx) => unsafe { transmute::<SecHandle, MaybeUninit<SecHandle>>(*bx) },
            None => MaybeUninit::uninit(),
        };
        let res = unsafe {
            // step() consumes the Context, therefore all of these references as pointers should be thread safe
            AcceptSecurityContext(
                Some(credentials.deref()),
                old_context,
                Some(&in_buf.description()),
                ASC_REQ_CONFIDENTIALITY | ASC_REQ_MUTUAL_AUTH,
                SECURITY_NATIVE_DREP,
                Some(context.as_mut_ptr()),
                Some(&mut out_buf.description()),
                &mut attr_flags,
                Some(&mut 0),
            )
        };
        let context = Self(unsafe { context.assume_init() });
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
            _e => false,
        };
        // Documentation claims to always write initialized Context into here if there was no error
        let response_token = (!out_buf.is_empty()).then_some(out_buf.as_ref().into());
        if is_done {
            Ok(StepSuccess::Finished(FinishedContext { context }, response_token))
        } else {
            Ok(StepSuccess::Continue(
                PendingContext {
                    credentials,
                    context,
                    buffer,
                    attr_flags,
                },
                response_token.expect("Windows expects to continue, but didn't provide a token"),
            ))
        }
    }
}
impl Drop for ContextHandle {
    fn drop(&mut self) {
        let _ = unsafe { DeleteSecurityContext(&self.0) };
    }
}
impl Deref for ContextHandle {
    type Target = SecHandle;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for ContextHandle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
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
