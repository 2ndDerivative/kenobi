use std::{ffi::c_void, marker::PhantomData, ops::DerefMut};

use windows::Win32::{
    Foundation::{
        SEC_E_INTERNAL_ERROR, SEC_E_INVALID_HANDLE, SEC_E_INVALID_TOKEN, SEC_E_LOGON_DENIED,
        SEC_E_NO_AUTHENTICATING_AUTHORITY, SEC_E_NO_CREDENTIALS, SEC_E_OK, SEC_E_TARGET_UNKNOWN,
        SEC_E_UNSUPPORTED_FUNCTION, SEC_E_WRONG_PRINCIPAL, SEC_I_COMPLETE_AND_CONTINUE, SEC_I_COMPLETE_NEEDED,
        SEC_I_CONTINUE_NEEDED,
    },
    Security::Authentication::Identity::{
        ISC_REQ_FLAGS, ISC_RET_MUTUAL_AUTH, InitializeSecurityContextW, SECBUFFER_TOKEN, SECBUFFER_VERSION,
        SECURITY_NATIVE_DREP, SecBuffer, SecBufferDesc,
    },
};

mod builder;
mod error;
mod typestate;

use crate::{
    buffer::{RustSecBuffer, RustSecBuffers},
    client::typestate::{EncryptionPolicy, SigningPolicy},
    context_handle::ContextHandle,
    credentials::Credentials,
};

pub use builder::ClientBuilder;
pub use error::InitializeContextError;
pub use typestate::{
    CanEncrypt, CanSign, CannotEncrypt, CannotSign, Delegatable, MaybeEncrypt, MaybeSign, NoDelegation,
};

pub struct ClientContext<Cred, E = CannotEncrypt, S = CannotSign, D = NoDelegation> {
    cred: Cred,
    context: ContextHandle,
    attributes: u32,
    _enc: PhantomData<(E, S, D)>,
}
impl<Cred, E, S, D> ClientContext<Cred, E, S, D> {
    pub fn is_mutually_authenticated(&self) -> bool {
        self.attributes & ISC_RET_MUTUAL_AUTH != 0
    }
    pub fn attributes(&self) -> u32 {
        self.attributes
    }
}
impl<Cred: AsRef<Credentials>> ClientContext<Cred> {
    pub fn new_from_cred(
        cred: Cred,
        target_principal: Option<&str>,
        server_init_token: Option<&[u8]>,
    ) -> Result<StepOut<Cred>, InitializeContextError> {
        ClientBuilder::new_from_credentials(cred, target_principal).initialize(server_init_token)
    }
}
type CheckSignResult<Cred, E, D> = Result<ClientContext<Cred, E, CanSign, D>, ClientContext<Cred, E, CannotSign, D>>;
impl<Cred, E, D> ClientContext<Cred, E, MaybeSign, D> {
    pub fn check_signing(self) -> CheckSignResult<Cred, E, D> {
        if <MaybeSign as typestate::signing::Sealed>::requirements_met_manual(self.attributes) {
            Ok(self.convert_policy())
        } else {
            Err(self.convert_policy())
        }
    }
}
type CheckEncryptionResult<Cred, S, D> =
    Result<ClientContext<Cred, CanEncrypt, S, D>, ClientContext<Cred, CannotEncrypt, S, D>>;
impl<Cred, S, D> ClientContext<Cred, MaybeEncrypt, S, D> {
    pub fn check_encryption(self) -> CheckEncryptionResult<Cred, S, D> {
        if <MaybeEncrypt as typestate::encryption::Sealed>::requirements_met_manual(self.attributes) {
            Ok(self.convert_policy())
        } else {
            Err(self.convert_policy())
        }
    }
}
impl<Cred, S1, E1, D1> ClientContext<Cred, S1, E1, D1> {
    fn convert_policy<S2, E2, D2>(self) -> ClientContext<Cred, S2, E2, D2> {
        let ClientContext {
            cred,
            context,
            attributes,
            ..
        } = self;
        ClientContext {
            cred,
            context,
            attributes,
            _enc: PhantomData,
        }
    }
}

pub struct PendingClientContext<Cred, E = CannotEncrypt, S = CannotSign, D = NoDelegation> {
    requirements: ISC_REQ_FLAGS,
    target_spn: Option<Box<[u16]>>,
    cred: Cred,
    context: ContextHandle,
    sec_buffers: RustSecBuffers,
    attributes: u32,
    _enc: PhantomData<(E, S, D)>,
}
impl<Cred: AsRef<Credentials>, E: EncryptionPolicy, S: SigningPolicy, D> PendingClientContext<Cred, E, S, D> {
    pub fn step(self, token: &[u8]) -> Result<StepOut<Cred, E, S, D>, InitializeContextError> {
        step(
            self.cred,
            self.target_spn,
            Some(self.context),
            self.requirements,
            self.attributes,
            Some(self.sec_buffers),
            Some(token),
        )
    }
}
impl<Cred, E, S, D> PendingClientContext<Cred, E, S, D> {
    pub fn next_token(&self) -> &[u8] {
        self.sec_buffers
            .as_slice()
            .iter()
            .find(|t| t.buffer_type == SECBUFFER_TOKEN)
            .expect("the rust-controlled secbuffer here should always have a token buffer")
            .as_slice()
    }
}

fn step<Cred: AsRef<Credentials>, E: EncryptionPolicy, S: SigningPolicy, D>(
    cred: Cred,
    target_spn: Option<Box<[u16]>>,
    mut context: Option<ContextHandle>,
    requirements: ISC_REQ_FLAGS,
    mut attributes: u32,
    out_buffers: Option<RustSecBuffers>,
    in_token: Option<&[u8]>,
) -> Result<StepOut<Cred, E, S, D>, InitializeContextError> {
    let mut sec_buffers = out_buffers.unwrap_or_else(|| {
        let buf = RustSecBuffer::new_for_token().unwrap();
        RustSecBuffers::new(Box::new([buf]))
    });
    sec_buffers
        .as_mut_slice()
        .iter_mut()
        .find(|x| x.buffer_type == SECBUFFER_TOKEN)
        .unwrap()
        .reformat_as_input();
    let mut secbuf = in_token.map(|token| SecBuffer {
        cbBuffer: token.len() as u32,
        BufferType: SECBUFFER_TOKEN,
        pvBuffer: token.as_ptr() as *mut c_void,
    });
    let buf_desc = secbuf.as_mut().map(|s| SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: 1,
        pBuffers: s,
    });
    let hres = unsafe {
        InitializeSecurityContextW(
            Some(cred.as_ref().raw_handle()),
            context.as_deref().map(std::ptr::from_ref),
            target_spn.as_ref().map(|b| b.as_ptr()),
            requirements,
            0,
            SECURITY_NATIVE_DREP,
            buf_desc.as_ref().map(std::ptr::from_ref),
            0,
            Some(context.get_or_insert_default().deref_mut()),
            Some(sec_buffers.as_windows_ptr()),
            &mut attributes,
            None,
        )
    };
    let context = context.expect("get_or_inserted before");
    match hres {
        SEC_E_OK => {
            if !E::requirements_met_initialization(attributes) {
                return Err(InitializeContextError::ServerRefusedEncryption);
            };
            if !S::requirements_met_initialization(attributes) {
                return Err(InitializeContextError::ServerRefusedSigning);
            }
            Ok(StepOut::Completed(ClientContext {
                cred,
                context,
                attributes,
                _enc: PhantomData,
            }))
        }
        SEC_I_COMPLETE_AND_CONTINUE | SEC_I_COMPLETE_NEEDED => {
            panic!("CompleteAuthToken is not supported by Negotiate")
        }
        SEC_I_CONTINUE_NEEDED => Ok(StepOut::Pending(PendingClientContext {
            requirements,
            target_spn,
            cred,
            context,
            sec_buffers,
            attributes,
            _enc: PhantomData,
        })),
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

pub enum StepOut<Cred, E = CannotEncrypt, S = CannotSign, D = NoDelegation> {
    Pending(PendingClientContext<Cred, E, S, D>),
    Completed(ClientContext<Cred, E, S, D>),
}
