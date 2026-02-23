use kenobi_core::cred::usage::OutboundUsable;
pub use kenobi_core::typestate::{Encryption, MaybeEncryption, MaybeSigning, NoEncryption, NoSigning, Signing};
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
        ISC_REQ_FLAGS, ISC_REQ_MUTUAL_AUTH, ISC_RET_MUTUAL_AUTH, InitializeSecurityContextW, QueryContextAttributesW,
        SEC_CHANNEL_BINDINGS, SECBUFFER_CHANNEL_BINDINGS, SECBUFFER_TOKEN, SECBUFFER_VERSION, SECPKG_ATTR_SESSION_KEY,
        SECURITY_NATIVE_DREP, SecBuffer, SecBufferDesc, SecPkgContext_SessionKey,
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
    sign_encrypt::{Altered, Encrypted, Plaintext, Signature},
};

pub use builder::ClientBuilder;
pub use error::InitializeContextError;
pub use typestate::{Delegatable, DelegationPolicy, EncryptionPolicy, NoDelegation, SigningPolicy};

pub struct ClientContext<Usage, S = NoSigning, E = NoEncryption, D = NoDelegation> {
    attributes: u32,
    cred: Credentials<Usage>,
    context: ContextHandle,
    token_buffer: NonResizableVec,
    _enc: PhantomData<(S, E, D)>,
}
impl<Usage, S, E, D> ClientContext<Usage, S, E, D> {
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
impl<Usage, E, D> ClientContext<Usage, Signing, E, D> {
    pub fn sign_message(&self, message: &[u8]) -> Signature {
        self.context.wrap_sign(message).unwrap()
    }
    pub fn unwrap(&self, message: &[u8]) -> Result<Plaintext, Altered> {
        self.context.unwrap(message)
    }
}
impl<Usage, D> ClientContext<Usage, Signing, Encryption, D> {
    pub fn encrypt(&self, message: &[u8]) -> Encrypted {
        self.context.wrap_encrypt(message).unwrap()
    }
}
impl<Usage: OutboundUsable> ClientContext<Usage, NoSigning, NoEncryption> {
    pub fn new_from_cred(
        cred: Credentials<Usage>,
        target_principal: Option<&str>,
    ) -> Result<StepOut<Usage, NoSigning, NoEncryption, NoDelegation>, InitializeContextError> {
        ClientBuilder::new_from_credentials(cred, target_principal).initialize()
    }
}
type CheckSignResult<Usage, E, D> = Result<ClientContext<Usage, Signing, E, D>, ClientContext<Usage, NoSigning, E, D>>;
impl<Usage, E, D> ClientContext<Usage, MaybeSigning, E, D> {
    pub fn check_signing(self) -> CheckSignResult<Usage, E, D> {
        if <MaybeSigning as typestate::signing::Sealed>::requirements_met_manual(self.attributes) {
            Ok(self.convert_policy())
        } else {
            Err(self.convert_policy())
        }
    }
}
type CheckEncryptionResult<Usage, S, D> =
    Result<ClientContext<Usage, S, Encryption, D>, ClientContext<Usage, S, NoEncryption, D>>;
impl<Usage, S, D> ClientContext<Usage, S, MaybeEncryption, D> {
    pub fn check_encryption(self) -> CheckEncryptionResult<Usage, S, D> {
        if <MaybeEncryption as typestate::encryption::Sealed>::requirements_met_manual(self.attributes) {
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

pub struct PendingClientContext<Usage, S = NoSigning, E = NoEncryption, D = NoDelegation> {
    target_spn: Option<Box<[u16]>>,
    cred: Credentials<Usage>,
    context: ContextHandle,
    token_buffer: NonResizableVec,
    attributes: u32,
    _enc: PhantomData<(S, E, D)>,
}
impl<Usage: OutboundUsable, S: SigningPolicy, E: EncryptionPolicy, D: DelegationPolicy>
    PendingClientContext<Usage, S, E, D>
{
    pub fn step(self, token: &[u8]) -> Result<StepOut<Usage, S, E, D>, InitializeContextError> {
        step(
            self.cred,
            self.target_spn,
            Some(self.context),
            self.attributes,
            self.token_buffer,
            None,
            Some(token),
        )
    }
}
impl<Usage, S, E, D> PendingClientContext<Usage, S, E, D> {
    pub fn next_token(&self) -> &[u8] {
        assert!(
            !self.token_buffer.is_empty(),
            "Pending client context returned no token to transmit"
        );
        self.token_buffer.as_slice()
    }
}

fn step<Usage: OutboundUsable, S: SigningPolicy, E: EncryptionPolicy, D: DelegationPolicy>(
    cred: Credentials<Usage>,
    target_spn: Option<Box<[u16]>>,
    mut context: Option<ContextHandle>,
    mut attributes: u32,
    mut token_buffer: NonResizableVec,
    channel_bindings: Option<&[u8]>,
    in_token: Option<&[u8]>,
) -> Result<StepOut<Usage, S, E, D>, InitializeContextError> {
    token_buffer.resize_max();

    let mut out_token_buffer = token_buffer.sec_buffer(SECBUFFER_TOKEN);
    let mut out_token_buffer_desc = SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: 1,
        pBuffers: &mut out_token_buffer,
    };
    let in_token_buf = in_token
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
    let mut buffers = vec![];
    buffers.extend(in_token_buf);

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

    let in_token_buf_desc = match buffers.as_mut_slice() {
        [] => None,
        v => Some(SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: v.len() as u32,
            pBuffers: v.as_mut_ptr(),
        }),
    };
    let mutual_auth: ISC_REQ_FLAGS = if S::REMOVE_MUTUAL_AUTH_FLAG {
        ISC_REQ_FLAGS(0)
    } else {
        ISC_REQ_MUTUAL_AUTH
    };
    let hres = unsafe {
        InitializeSecurityContextW(
            Some(cred.as_ref().raw_handle()),
            context.as_deref().map(std::ptr::from_ref),
            target_spn.as_ref().map(|b| b.as_ptr()),
            mutual_auth | S::ADDED_REQ_FLAGS | E::ADDED_REQ_FLAGS | D::ADDED_REQ_FLAGS,
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

pub enum StepOut<Usage, S = NoSigning, E = NoEncryption, D = NoDelegation> {
    Pending(PendingClientContext<Usage, S, E, D>),
    Completed(ClientContext<Usage, S, E, D>),
}
