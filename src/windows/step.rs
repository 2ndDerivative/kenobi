use std::{
    mem::{ManuallyDrop, MaybeUninit},
    ops::Deref,
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
                Some(&mut 0),
            )
        };
        let context = Self(unsafe { mut_context.assume_init() });
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
