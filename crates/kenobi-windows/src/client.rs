use kenobi_core::cred::usage::OutboundUsable;
use std::{
    ffi::c_void,
    marker::PhantomData,
    ops::{Deref, DerefMut},
};
use windows::Win32::{
    Foundation::{
        SEC_E_INTERNAL_ERROR, SEC_E_INVALID_HANDLE, SEC_E_INVALID_TOKEN, SEC_E_LOGON_DENIED,
        SEC_E_NO_AUTHENTICATING_AUTHORITY, SEC_E_NO_CREDENTIALS, SEC_E_OK, SEC_E_TARGET_UNKNOWN,
        SEC_E_UNSUPPORTED_FUNCTION, SEC_E_WRONG_PRINCIPAL, SEC_I_COMPLETE_AND_CONTINUE, SEC_I_COMPLETE_NEEDED,
        SEC_I_CONTINUE_NEEDED,
    },
    Security::Authentication::Identity::{
        ISC_REQ_MUTUAL_AUTH, ISC_RET_MUTUAL_AUTH, InitializeSecurityContextW, QueryContextAttributesW, SECBUFFER_TOKEN,
        SECBUFFER_VERSION, SECPKG_ATTR_SESSION_KEY, SECURITY_NATIVE_DREP, SecBuffer, SecBufferDesc,
        SecPkgContext_SessionKey,
    },
};

mod builder;
mod error;
mod typestate;

use crate::{
    buffer::NonResizableVec,
    context::SessionKey,
    context_handle::ContextHandle,
    cred::Credentials,
    sign::{Altered, Encrypted, Plaintext, Signature},
};

pub use builder::ClientBuilder;
pub use error::InitializeContextError;
pub use typestate::{
    CanEncrypt, CanSign, CannotEncrypt, CannotSign, Delegatable, DelegationPolicy, EncryptionPolicy, MaybeEncrypt,
    MaybeSign, NoDelegation, SigningPolicy,
};

pub struct ClientContext<Usage, E = CannotEncrypt, S = CannotSign, D = NoDelegation> {
    attributes: u32,
    cred: Credentials<Usage>,
    context: ContextHandle,
    token_buffer: NonResizableVec,
    _enc: PhantomData<(E, S, D)>,
}
impl<Usage, E, S, D> ClientContext<Usage, E, S, D> {
    pub fn is_mutually_authenticated(&self) -> bool {
        self.attributes & ISC_RET_MUTUAL_AUTH != 0
    }
    pub fn attributes(&self) -> u32 {
        self.attributes
    }
    pub fn last_token(&self) -> Option<&[u8]> {
        (!self.token_buffer.is_empty()).then_some(self.token_buffer.as_slice())
    }
    pub fn get_session_key(&self) -> windows_result::Result<SessionKey> {
        let mut key = SecPkgContext_SessionKey::default();
        unsafe {
            QueryContextAttributesW(
                self.context.deref(),
                SECPKG_ATTR_SESSION_KEY,
                std::ptr::from_mut(&mut key) as *mut c_void,
            )
        }?;
        unsafe { Ok(SessionKey::new(key)) }
    }
}
impl<Usage, E, D> ClientContext<Usage, E, CanSign, D> {
    pub fn sign_message(&self, message: &[u8]) -> Signature {
        self.context.wrap_sign(message).unwrap()
    }
    pub fn unwrap(&self, message: &[u8]) -> Result<Plaintext, Altered> {
        self.context.unwrap(message)
    }
}
impl<Usage, D> ClientContext<Usage, CanEncrypt, CanSign, D> {
    pub fn encrypt(&self, message: &[u8]) -> Encrypted {
        self.context.wrap_encrypt(message).unwrap()
    }
}
impl<Usage: OutboundUsable> ClientContext<Usage> {
    pub fn new_from_cred(
        cred: Credentials<Usage>,
        target_principal: Option<&str>,
    ) -> Result<StepOut<Usage>, InitializeContextError> {
        ClientBuilder::new_from_credentials(cred, target_principal).initialize()
    }
}
type CheckSignResult<Usage, E, D> = Result<ClientContext<Usage, E, CanSign, D>, ClientContext<Usage, E, CannotSign, D>>;
impl<Usage, E, D> ClientContext<Usage, E, MaybeSign, D> {
    pub fn check_signing(self) -> CheckSignResult<Usage, E, D> {
        if <MaybeSign as typestate::signing::Sealed>::requirements_met_manual(self.attributes) {
            Ok(self.convert_policy())
        } else {
            Err(self.convert_policy())
        }
    }
}
type CheckEncryptionResult<Usage, S, D> =
    Result<ClientContext<Usage, CanEncrypt, S, D>, ClientContext<Usage, CannotEncrypt, S, D>>;
impl<Usage, S, D> ClientContext<Usage, MaybeEncrypt, S, D> {
    pub fn check_encryption(self) -> CheckEncryptionResult<Usage, S, D> {
        if <MaybeEncrypt as typestate::encryption::Sealed>::requirements_met_manual(self.attributes) {
            Ok(self.convert_policy())
        } else {
            Err(self.convert_policy())
        }
    }
}
impl<Usage, S1, E1, D1> ClientContext<Usage, S1, E1, D1> {
    fn convert_policy<S2, E2, D2>(self) -> ClientContext<Usage, S2, E2, D2> {
        let ClientContext {
            attributes,
            cred,
            context,
            token_buffer,
            ..
        } = self;
        ClientContext {
            cred,
            context,
            attributes,
            token_buffer,
            _enc: PhantomData,
        }
    }
}

pub struct PendingClientContext<Usage, E = CannotEncrypt, S = CannotSign, D = NoDelegation> {
    target_spn: Option<Box<[u16]>>,
    cred: Credentials<Usage>,
    context: ContextHandle,
    token_buffer: NonResizableVec,
    attributes: u32,
    _enc: PhantomData<(E, S, D)>,
}
impl<Usage: OutboundUsable, E: EncryptionPolicy, S: SigningPolicy, D: DelegationPolicy>
    PendingClientContext<Usage, E, S, D>
{
    pub fn step(self, token: &[u8]) -> Result<StepOut<Usage, E, S, D>, InitializeContextError> {
        step(
            self.cred,
            self.target_spn,
            Some(self.context),
            self.attributes,
            self.token_buffer,
            Some(token),
        )
    }
}
impl<Usage, E, S, D> PendingClientContext<Usage, E, S, D> {
    pub fn next_token(&self) -> &[u8] {
        assert!(
            !self.token_buffer.is_empty(),
            "Pending client context returned no token to transmit"
        );
        self.token_buffer.as_slice()
    }
}

fn step<Usage: OutboundUsable, E: EncryptionPolicy, S: SigningPolicy, D: DelegationPolicy>(
    cred: Credentials<Usage>,
    target_spn: Option<Box<[u16]>>,
    mut context: Option<ContextHandle>,
    mut attributes: u32,
    mut token_buffer: NonResizableVec,
    in_token: Option<&[u8]>,
) -> Result<StepOut<Usage, E, S, D>, InitializeContextError> {
    token_buffer.resize_max();

    let mut out_token_buffer = token_buffer.sec_buffer(SECBUFFER_TOKEN);
    let mut out_token_buffer_desc = SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: 1,
        pBuffers: &mut out_token_buffer,
    };
    let mut in_token_buf = in_token
        .map(|token| {
            let cb_buffer = token
                .len()
                .try_into()
                .map_err(|_| InitializeContextError::InvalidToken)?;
            Ok(SecBuffer {
                cbBuffer: cb_buffer,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: token.as_ptr() as *mut c_void,
            })
        })
        .transpose()?;
    let in_token_buf_desc = in_token_buf.as_mut().map(|s| SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: 1,
        pBuffers: s,
    });
    let hres = unsafe {
        InitializeSecurityContextW(
            Some(cred.as_ref().raw_handle()),
            context.as_deref().map(std::ptr::from_ref),
            target_spn.as_ref().map(|b| b.as_ptr()),
            ISC_REQ_MUTUAL_AUTH | E::ADDED_REQ_FLAGS | S::ADDED_REQ_FLAGS | D::ADDED_REQ_FLAGS,
            0,
            SECURITY_NATIVE_DREP,
            in_token_buf_desc.as_ref().map(std::ptr::from_ref),
            0,
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
            Ok(StepOut::Completed(ClientContext {
                attributes,
                cred,
                context,
                token_buffer,
                _enc: PhantomData,
            }))
        }
        SEC_I_COMPLETE_AND_CONTINUE | SEC_I_COMPLETE_NEEDED => {
            panic!("CompleteAuthToken is not supported by Negotiate")
        }
        SEC_I_CONTINUE_NEEDED => {
            let context = context.expect("get_or_inserted before");
            Ok(StepOut::Pending(PendingClientContext {
                target_spn,
                cred,
                context,
                token_buffer,
                attributes,
                _enc: PhantomData,
            }))
        }
        SEC_E_INTERNAL_ERROR => Err(InitializeContextError::Internal),
        SEC_E_INVALID_HANDLE => Err(InitializeContextError::InvalidHandle),
        SEC_E_INVALID_TOKEN => Err(InitializeContextError::InvalidToken),
        SEC_E_LOGON_DENIED => Err(InitializeContextError::Denied),
        SEC_E_NO_CREDENTIALS => todo!("constrained delegation"),
        SEC_E_NO_AUTHENTICATING_AUTHORITY => Err(InitializeContextError::NoAuthority),
        SEC_E_TARGET_UNKNOWN => Err(InitializeContextError::TargetUnknown),
        SEC_E_UNSUPPORTED_FUNCTION => panic!("unsupported function"),
        SEC_E_WRONG_PRINCIPAL => Err(InitializeContextError::WrongPrincipal),
        e => todo!("unknown error code: {e:?} ({})", e.message()),
    }
}

pub enum StepOut<Usage, E = CannotEncrypt, S = CannotSign, D = NoDelegation> {
    Pending(PendingClientContext<Usage, E, S, D>),
    Completed(ClientContext<Usage, E, S, D>),
}
