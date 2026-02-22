use std::{ffi::c_void, marker::PhantomData, ops::DerefMut};

use windows::Win32::{
    Foundation::{
        SEC_E_INTERNAL_ERROR, SEC_E_INVALID_HANDLE, SEC_E_INVALID_TOKEN, SEC_E_LOGON_DENIED,
        SEC_E_NO_AUTHENTICATING_AUTHORITY, SEC_E_OK, SEC_E_UNSUPPORTED_FUNCTION, SEC_I_CONTINUE_NEEDED,
    },
    Security::Authentication::Identity::{
        ASC_REQ_MUTUAL_AUTH, AcceptSecurityContext, SECBUFFER_TOKEN, SECBUFFER_VERSION, SECURITY_NATIVE_DREP,
        SecBuffer, SecBufferDesc,
    },
};

use kenobi_core::cred::usage::InboundUsable;

use crate::{
    buffer::NonResizableVec,
    context_handle::ContextHandle,
    cred::Credentials,
    server::typestate::{DelegationPolicy, SigningPolicy},
    sign::{Altered, Signature},
};

mod builder;
mod error;
pub mod impersonation;
mod typestate;

pub use builder::ServerBuilder;
pub use error::AcceptContextError;
pub use typestate::{CanDelegate, CanSign, MaybeSign, NoDelegation, NoSigning, OfferDelegate};

pub struct ServerContext<Usage, S = NoSigning, D = NoDelegation> {
    cred: Credentials<Usage>,
    context: ContextHandle,
    attributes: u32,
    /// should never be resized
    token_buffer: NonResizableVec,
    _enc: PhantomData<(D, S)>,
}
impl<Usage: InboundUsable, S, D> ServerContext<Usage, S, D>
where
    S: SigningPolicy,
    D: DelegationPolicy,
{
    pub fn initialize(
        cred: Credentials<Usage>,
        first_token: &[u8],
    ) -> Result<StepOut<Usage, S, D>, AcceptContextError> {
        step(cred, None, 0, NonResizableVec::new(), first_token)
    }
}
impl<Usage, D, S> ServerContext<Usage, D, S> {
    pub fn last_token(&self) -> Option<&[u8]> {
        (!self.token_buffer.is_empty()).then_some(&self.token_buffer)
    }
}
impl<Usage, D> ServerContext<Usage, CanSign, D> {
    pub fn sign_message(&self, message: &[u8]) -> Signature {
        self.context.wrap_sign(message).unwrap()
    }
    pub fn verify_message(&self, message: &[u8]) -> Result<(), Altered> {
        self.context.unwrap(message)?;
        Ok(())
    }
}
impl<Usage, S> ServerContext<Usage, S, OfferDelegate> {
    pub fn check_delegation(
        self,
    ) -> Result<ServerContext<Usage, S, CanDelegate>, ServerContext<Usage, S, NoDelegation>> {
        if self.attributes & <OfferDelegate as typestate::delegation::Sealed>::REQUEST_FLAGS.0 != 0 {
            Ok(self.convert_policy())
        } else {
            Err(self.convert_policy())
        }
    }
}
impl<Usage, D> ServerContext<Usage, MaybeSign, D> {
    pub fn check_signing(self) -> Result<ServerContext<Usage, CanSign, D>, ServerContext<Usage, NoSigning, D>> {
        if self.attributes & <MaybeSign as typestate::sign::Sealed>::REQUEST_FLAGS.0 != 0 {
            Ok(self.convert_policy())
        } else {
            Err(self.convert_policy())
        }
    }
}
impl<Usage, S1, D1> ServerContext<Usage, S1, D1> {
    fn convert_policy<S2, D2>(self) -> ServerContext<Usage, S2, D2> {
        let ServerContext {
            cred,
            context,
            attributes,
            token_buffer,
            ..
        } = self;
        ServerContext {
            cred,
            context,
            attributes,
            token_buffer,
            _enc: PhantomData,
        }
    }
}

pub struct PendingServerContext<Usage, S = NoSigning, D = NoDelegation> {
    cred: Credentials<Usage>,
    context: ContextHandle,
    attributes: u32,
    token_buffer: NonResizableVec,
    _enc: PhantomData<(S, D)>,
}
impl<Usage, S, D> PendingServerContext<Usage, S, D> {
    pub fn next_token(&self) -> &[u8] {
        assert!(!self.token_buffer.is_empty());
        &self.token_buffer
    }
}

impl<Usage: InboundUsable, S: SigningPolicy, D: DelegationPolicy> PendingServerContext<Usage, S, D> {
    pub fn step(self, token: &[u8]) -> Result<StepOut<Usage, S, D>, AcceptContextError> {
        step(self.cred, Some(self.context), self.attributes, self.token_buffer, token)
    }
}

fn step<Usage: InboundUsable, S: SigningPolicy, D: DelegationPolicy>(
    cred: Credentials<Usage>,
    mut context: Option<ContextHandle>,
    mut attributes: u32,
    mut token_buffer: NonResizableVec,
    in_token: &[u8],
) -> Result<StepOut<Usage, S, D>, AcceptContextError> {
    token_buffer.resize_max();

    let mut out_token_buffer = token_buffer.sec_buffer(SECBUFFER_TOKEN);
    let mut out_token_buffer_desc = SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: 1,
        pBuffers: &mut out_token_buffer,
    };

    let mut in_buf = SecBuffer {
        cbBuffer: in_token.len() as u32,
        BufferType: SECBUFFER_TOKEN,
        pvBuffer: in_token.as_ptr() as *mut c_void,
    };
    let in_buf_desc = SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: 1,
        pBuffers: &mut in_buf,
    };
    let old_context_ptr = context.as_deref().map(std::ptr::from_ref);
    let hres = unsafe {
        AcceptSecurityContext(
            Some(cred.as_ref().raw_handle()),
            old_context_ptr,
            Some(&in_buf_desc),
            ASC_REQ_MUTUAL_AUTH
                | <S as typestate::sign::Sealed>::REQUEST_FLAGS
                | <D as typestate::delegation::Sealed>::REQUEST_FLAGS,
            SECURITY_NATIVE_DREP,
            Some(context.get_or_insert_default().deref_mut()),
            Some(&mut out_token_buffer_desc),
            &mut attributes,
            None,
        )
    };
    token_buffer.set_length(out_token_buffer.cbBuffer);
    match hres {
        SEC_E_OK => {
            let context = context.expect("get_or_inserted before");
            // Flag checks
            Ok(StepOut::Completed(ServerContext {
                cred,
                context,
                attributes,
                token_buffer,
                _enc: PhantomData,
            }))
        }
        SEC_I_CONTINUE_NEEDED => {
            let context = context.expect("get_or_inserted before");
            Ok(StepOut::Pending(PendingServerContext {
                cred,
                context,
                attributes,
                token_buffer,
                _enc: PhantomData,
            }))
        }
        SEC_E_INTERNAL_ERROR => Err(AcceptContextError::Internal),
        SEC_E_INVALID_HANDLE => Err(AcceptContextError::InvalidHandle),
        SEC_E_INVALID_TOKEN => Err(AcceptContextError::InvalidToken),
        SEC_E_LOGON_DENIED => Err(AcceptContextError::Denied),
        SEC_E_NO_AUTHENTICATING_AUTHORITY => Err(AcceptContextError::NoAuthority),
        SEC_E_UNSUPPORTED_FUNCTION => unreachable!("only applicable from Schannel SSP"),
        e => todo!("unknown error code: {e:?} (\"{}\")", e.message()),
    }
}

pub enum StepOut<Usage, S = NoSigning, D = NoDelegation> {
    Pending(PendingServerContext<Usage, S, D>),
    Completed(ServerContext<Usage, S, D>),
}
