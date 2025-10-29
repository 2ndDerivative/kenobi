use std::{
    mem::{ManuallyDrop, MaybeUninit},
    ops::Deref,
};

use windows::Win32::{
    Foundation::{
        FILETIME, SEC_E_INCOMPLETE_MESSAGE, SEC_E_INSUFFICIENT_MEMORY, SEC_E_INTERNAL_ERROR, SEC_E_INVALID_HANDLE,
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
    Storage::FileSystem::LocalFileTimeToFileTime,
};

use crate::{step::StepError, windows::buffer::SecurityBuffer, StepResult, StepSuccess};

use super::{credentials::CredentialsHandle, FinishedContext, PendingContext};

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
        let old_context: Option<*const SecHandle> = context.as_ref().map(|x| std::ptr::from_ref(x.as_ref()));
        let mut mut_context: MaybeUninit<SecHandle> = match context {
            // T -> MaybeUninit<T> is always safe
            Some(bx) => MaybeUninit::new(ManuallyDrop::new(bx).0),
            None => MaybeUninit::uninit(),
        };
        let mut file_time_local = 0;
        #[cfg(feature = "tracing")]
        tracing::trace!("Stepping security context for handle {credentials:?}");
        let res = unsafe {
            // step() consumes the Context, therefore all of these references as pointers should be thread safe
            AcceptSecurityContext(
                Some(credentials.deref()),
                old_context,
                Some(&in_buf.description()),
                ASC_REQ_CONFIDENTIALITY | ASC_REQ_MUTUAL_AUTH,
                SECURITY_NATIVE_DREP,
                Some(mut_context.as_mut_ptr()),
                Some(&mut out_buf.description()),
                &mut attr_flags,
                Some(&mut file_time_local),
            )
        };
        let context = Self(unsafe { mut_context.assume_init() });
        let expires = raw_local_file_time_to_utc(file_time_local);
        #[cfg(feature = "tracing")]
        tracing::trace!("Stepped security context for handle {credentials:?}: code {}", res.0);
        let is_done = match res {
            SEC_E_OK => {
                #[cfg(feature = "tracing")]
                tracing::trace!("Sucessfully stepped security context");
                true
            }
            SEC_E_INCOMPLETE_MESSAGE => return Err(StepError::IncompleteMessage),
            SEC_E_INSUFFICIENT_MEMORY => {
                #[cfg(feature = "tracing")]
                tracing::error!("insufficient memory!");
                panic!("Insufficient memory for the security operation")
            }
            _e @ SEC_E_INVALID_HANDLE => {
                #[cfg(feature = "tracing")]
                tracing::error!("Invalid handle: {}", _e.message());
                panic!("Invalid handle. Something went wrong on the library side. Please contact the maintainer")
            }
            _e @ SEC_E_INTERNAL_ERROR => {
                #[cfg(feature = "tracing")]
                tracing::error!("internal SSPI error: {}", _e.message());
                panic!("Internal SSPI error.")
            }
            _e @ SEC_E_NO_CREDENTIALS => {
                #[cfg(feature = "tracing")]
                tracing::error!("invalid credentials handle: {}", _e.message());
                panic!(
                    "Invalid credentials handle. Something went wrong on the library side. Please contact the maintainer"
                )
            }
            SEC_E_UNSUPPORTED_FUNCTION => {
                #[cfg(feature = "tracing")]
                tracing::error!("unsupported function error!");
                unreachable!(
                "Unsupported function error. should be impossible without ASC_REQ_DELEGATE or ASC_REQ_PROMPT_FOR_CREDS"
            )
            }
            SEC_E_NO_AUTHENTICATING_AUTHORITY => return Err(StepError::NoAuthenticatingAuthority),
            SEC_E_INVALID_TOKEN => return Err(StepError::InvalidToken),
            SEC_E_LOGON_DENIED => return Err(StepError::LogonDenied),
            x if x.0.is_negative() => {
                #[cfg(feature = "tracing")]
                tracing::error!(code = x.0, message = x.message(), "Unknown OS error");
                panic!("Unknown OS error. code: {}, message {}", x.0, x.message())
            }
            _e => false,
        };
        // Documentation claims to always write initialized Context into here if there was no error
        let response_token = (!out_buf.is_empty()).then_some(out_buf.as_ref().into());
        if is_done {
            #[cfg(feature = "tracing")]
            tracing::debug!("Finished security context");
            Ok(StepSuccess::Finished(
                crate::FinishedContext(FinishedContext { context, expires }),
                response_token,
            ))
        } else {
            #[cfg(feature = "tracing")]
            tracing::debug!("Advanced context context");
            Ok(StepSuccess::Continue(
                crate::PendingContext(PendingContext {
                    credentials,
                    context,
                    buffer,
                    attr_flags,
                }),
                response_token.expect("Windows expects to continue, but didn't provide a token"),
            ))
        }
    }
}
fn raw_local_file_time_to_utc(raw_time: i64) -> FILETIME {
    let file_time_local = unsafe { std::mem::transmute::<i64, FILETIME>(raw_time) };
    let mut result = MaybeUninit::uninit();
    unsafe { LocalFileTimeToFileTime(&file_time_local, result.as_mut_ptr()).unwrap() };
    unsafe { result.assume_init() }
}
impl Drop for ContextHandle {
    fn drop(&mut self) {
        let _ = unsafe { DeleteSecurityContext(&self.0) };
    }
}
impl AsRef<SecHandle> for ContextHandle {
    fn as_ref(&self) -> &SecHandle {
        &self.0
    }
}
impl AsMut<SecHandle> for ContextHandle {
    fn as_mut(&mut self) -> &mut SecHandle {
        &mut self.0
    }
}
