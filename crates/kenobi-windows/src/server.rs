use std::{ffi::c_void, marker::PhantomData, ops::DerefMut};

use windows::Win32::{
    Foundation::{
        SEC_E_INTERNAL_ERROR, SEC_E_INVALID_HANDLE, SEC_E_INVALID_TOKEN, SEC_E_LOGON_DENIED,
        SEC_E_NO_AUTHENTICATING_AUTHORITY, SEC_E_OK, SEC_E_UNSUPPORTED_FUNCTION, SEC_I_CONTINUE_NEEDED,
    },
    Security::Authentication::Identity::{
        ASC_REQ_MUTUAL_AUTH, AcceptSecurityContext, SEC_CHANNEL_BINDINGS, SECBUFFER_CHANNEL_BINDINGS, SECBUFFER_TOKEN,
        SECBUFFER_VERSION, SECURITY_NATIVE_DREP, SecBuffer, SecBufferDesc,
    },
};

use kenobi_core::cred::usage::InboundUsable;

use crate::{
    buffer::NonResizableVec,
    context_handle::ContextHandle,
    cred::Credentials,
    server::typestate::{DelegationPolicy, EncryptionPolicy, SigningPolicy},
    sign_encrypt::{Altered, Plaintext, Signature},
};

mod builder;
mod error;
pub mod impersonation;
mod typestate;

pub use builder::ServerBuilder;
pub use error::AcceptContextError;
pub use typestate::{
    CanDelegate, CanEncrypt, CanSign, MaybeEncrypt, MaybeSign, NoDelegation, NoEncryption, NoSigning, OfferDelegate,
};

pub struct ServerContext<Usage, S, E, D> {
    cred: Credentials<Usage>,
    context: ContextHandle,
    attributes: u32,
    /// should never be resized
    token_buffer: NonResizableVec,
    _enc: PhantomData<(D, E, S)>,
}
impl<Usage: InboundUsable, S, E, D> ServerContext<Usage, S, E, D>
where
    S: SigningPolicy,
    E: EncryptionPolicy,
    D: DelegationPolicy,
{
    pub fn initialize(
        cred: Credentials<Usage>,
        first_token: &[u8],
    ) -> Result<StepOut<Usage, S, E, D>, AcceptContextError> {
        step(cred, None, 0, NonResizableVec::new(), None, first_token)
    }
}
impl<Usage, S, E, D> ServerContext<Usage, S, E, D> {
    pub fn last_token(&self) -> Option<&[u8]> {
        (!self.token_buffer.is_empty()).then_some(&self.token_buffer)
    }
}
impl<Usage, E, D> ServerContext<Usage, CanSign, E, D> {
    pub fn sign_message(&self, message: &[u8]) -> Signature {
        self.context.wrap_sign(message).unwrap()
    }
    pub fn verify_message(&self, message: &[u8]) -> Result<Plaintext, Altered> {
        self.context.unwrap(message)
    }
}
impl<Usage, S, E> ServerContext<Usage, S, E, OfferDelegate> {
    #[allow(clippy::type_complexity)]
    pub fn check_delegation(
        self,
    ) -> Result<ServerContext<Usage, S, E, CanDelegate>, ServerContext<Usage, S, E, NoDelegation>> {
        if self.attributes & <OfferDelegate as typestate::delegation::Sealed>::REQUEST_FLAGS.0 != 0 {
            Ok(self.convert_policy())
        } else {
            Err(self.convert_policy())
        }
    }
}
impl<Usage, E, D> ServerContext<Usage, MaybeSign, E, D> {
    #[allow(clippy::type_complexity)]
    pub fn check_signing(self) -> Result<ServerContext<Usage, CanSign, E, D>, ServerContext<Usage, NoSigning, E, D>> {
        if self.attributes & <MaybeSign as typestate::sign::Sealed>::REQUEST_FLAGS.0 != 0 {
            Ok(self.convert_policy())
        } else {
            Err(self.convert_policy())
        }
    }
}
impl<Usage, S, D> ServerContext<Usage, S, MaybeEncrypt, D> {
    #[allow(clippy::type_complexity)]
    pub fn check_encryption(
        self,
    ) -> Result<ServerContext<Usage, S, CanEncrypt, D>, ServerContext<Usage, S, NoEncryption, D>> {
        if self.attributes & <MaybeEncrypt as typestate::encrypt::Sealed>::REQUEST_FLAGS.0 != 0 {
            Ok(self.convert_policy())
        } else {
            Err(self.convert_policy())
        }
    }
}
impl<Usage, S1, E1, D1> ServerContext<Usage, S1, E1, D1> {
    fn convert_policy<S2, E2, D2>(self) -> ServerContext<Usage, S2, E2, D2> {
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

pub struct PendingServerContext<Usage, S = NoSigning, E = NoEncryption, D = NoDelegation> {
    cred: Credentials<Usage>,
    context: ContextHandle,
    attributes: u32,
    token_buffer: NonResizableVec,
    _enc: PhantomData<(S, E, D)>,
}
impl<Usage, S, E, D> PendingServerContext<Usage, S, E, D> {
    pub fn next_token(&self) -> &[u8] {
        assert!(!self.token_buffer.is_empty());
        &self.token_buffer
    }
}

impl<Usage: InboundUsable, S: SigningPolicy, E: EncryptionPolicy, D: DelegationPolicy>
    PendingServerContext<Usage, S, E, D>
{
    pub fn step(self, token: &[u8]) -> Result<StepOut<Usage, S, E, D>, AcceptContextError> {
        step(
            self.cred,
            Some(self.context),
            self.attributes,
            self.token_buffer,
            None,
            token,
        )
    }
}

fn step<Usage: InboundUsable, S: SigningPolicy, E: EncryptionPolicy, D: DelegationPolicy>(
    cred: Credentials<Usage>,
    mut context: Option<ContextHandle>,
    mut attributes: u32,
    mut token_buffer: NonResizableVec,
    channel_bindings: Option<&[u8]>,
    in_token: &[u8],
) -> Result<StepOut<Usage, S, E, D>, AcceptContextError> {
    token_buffer.resize_max();

    let mut out_token_buffer = token_buffer.sec_buffer(SECBUFFER_TOKEN);
    let mut out_token_buffer_desc = SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: 1,
        pBuffers: &mut out_token_buffer,
    };

    let mut buffers = vec![SecBuffer {
        cbBuffer: in_token.len() as u32,
        BufferType: SECBUFFER_TOKEN,
        pvBuffer: in_token.as_ptr() as *mut c_void,
    }];

    // Add channel binding data
    let mut channel_binding_buffer = channel_bindings.map(|cb| {
        let scb = SEC_CHANNEL_BINDINGS {
            dwApplicationDataOffset: 32,
            cbApplicationDataLength: cb.len() as u32,
            ..Default::default()
        };
        let mut buffer = vec![0u8; 32 + cb.len()];
        unsafe {
            std::ptr::write(buffer.as_mut_ptr() as *mut SEC_CHANNEL_BINDINGS, scb);
        }
        buffer[32..].copy_from_slice(cb);
        buffer
    });
    buffers.extend(channel_binding_buffer.as_mut().map(|cb| SecBuffer {
        cbBuffer: cb.len() as u32,
        BufferType: SECBUFFER_CHANNEL_BINDINGS,
        pvBuffer: cb.as_mut_ptr() as *mut c_void,
    }));

    let in_buf_desc = SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: buffers.len() as u32,
        pBuffers: buffers.as_mut_ptr(),
    };
    let old_context_ptr = context.as_deref().map(std::ptr::from_ref);
    let hres = unsafe {
        AcceptSecurityContext(
            Some(cred.as_ref().raw_handle()),
            old_context_ptr,
            Some(&in_buf_desc),
            ASC_REQ_MUTUAL_AUTH
                | <S as typestate::sign::Sealed>::REQUEST_FLAGS
                | <E as typestate::encrypt::Sealed>::REQUEST_FLAGS
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

pub enum StepOut<Usage, S = NoSigning, E = NoEncryption, D = NoDelegation> {
    Pending(PendingServerContext<Usage, S, E, D>),
    Completed(ServerContext<Usage, S, E, D>),
}
