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

use crate::{
    buffer::{RustSecBuffer, RustSecBuffers},
    context_handle::ContextHandle,
    credentials::Credentials,
    server::typestate::DelegationPolicy,
};

mod builder;
mod error;
pub mod impersonation;
mod typestate;

pub use builder::ServerBuilder;
pub use error::AcceptContextError;
pub use typestate::{CanDelegate, NoDelegation, OfferDelegate};

pub struct ServerContext<Cred, D = NoDelegation> {
    cred: Cred,
    context: ContextHandle,
    attributes: u32,
    sec_buffers: RustSecBuffers,
    _enc: PhantomData<D>,
}
impl<Cred: AsRef<Credentials>, D: DelegationPolicy> ServerContext<Cred, D> {
    pub fn initialize(cred: Cred, first_token: &[u8]) -> Result<StepOut<Cred, D>, AcceptContextError> {
        let buf = RustSecBuffer::new_for_token().unwrap();
        step(cred, None, 0, RustSecBuffers::new(Box::new([buf])), first_token)
    }
}
impl<Cred, D> ServerContext<Cred, D> {
    pub fn last_token(&self) -> Option<&[u8]> {
        let token = self
            .sec_buffers
            .as_slice()
            .iter()
            .find(|x| x.buffer_type == SECBUFFER_TOKEN)
            .expect("the Rust-controlled buffer should always have a token buffer")
            .as_slice();
        (!token.is_empty()).then_some(token)
    }
}
impl<Cred> ServerContext<Cred, OfferDelegate> {
    pub fn check_delegation(self) -> Result<ServerContext<Cred, CanDelegate>, ServerContext<Cred, NoDelegation>> {
        if self.attributes & <OfferDelegate as typestate::delegation::Sealed>::REQUEST_FLAGS.0 != 0 {
            Ok(self.convert_policy())
        } else {
            Err(self.convert_policy())
        }
    }
}
impl<Cred, D1> ServerContext<Cred, D1> {
    fn convert_policy<D2>(self) -> ServerContext<Cred, D2> {
        let ServerContext {
            cred,
            context,
            attributes,
            sec_buffers,
            ..
        } = self;
        ServerContext {
            cred,
            context,
            attributes,
            sec_buffers,
            _enc: PhantomData,
        }
    }
}

pub struct PendingServerContext<Cred, D = NoDelegation> {
    cred: Cred,
    context: ContextHandle,
    attributes: u32,
    sec_buffers: RustSecBuffers,
    _enc: PhantomData<D>,
}
impl<Cred, D> PendingServerContext<Cred, D> {
    pub fn next_token(&self) -> &[u8] {
        self.sec_buffers
            .as_slice()
            .iter()
            .find(|t| t.buffer_type == SECBUFFER_TOKEN)
            .expect("the Rust-controlled buffer should always have a token buffer")
            .as_slice()
    }
}

impl<Cred: AsRef<Credentials>, D: DelegationPolicy> PendingServerContext<Cred, D> {
    pub fn step(self, token: &[u8]) -> Result<StepOut<Cred, D>, AcceptContextError> {
        step(self.cred, Some(self.context), self.attributes, self.sec_buffers, token)
    }
}

fn step<Cred: AsRef<Credentials>, D: DelegationPolicy>(
    cred: Cred,
    mut context: Option<ContextHandle>,
    mut attributes: u32,
    mut sec_buffers: RustSecBuffers,
    in_token: &[u8],
) -> Result<StepOut<Cred, D>, AcceptContextError> {
    let old_context_ptr = context.as_deref().map(std::ptr::from_ref);
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
    let hres = unsafe {
        AcceptSecurityContext(
            Some(cred.as_ref().raw_handle()),
            old_context_ptr,
            Some(&in_buf_desc),
            ASC_REQ_MUTUAL_AUTH | <D as typestate::delegation::Sealed>::REQUEST_FLAGS,
            SECURITY_NATIVE_DREP,
            Some(context.get_or_insert_default().deref_mut()),
            Some(sec_buffers.as_windows_ptr()),
            &mut attributes,
            None,
        )
    };
    let context = context.expect("get_or_inserted before");
    match hres {
        SEC_E_OK => {
            // Flag checks
            Ok(StepOut::Completed(ServerContext {
                cred,
                context,
                attributes,
                sec_buffers,
                _enc: PhantomData,
            }))
        }
        SEC_I_CONTINUE_NEEDED => Ok(StepOut::Pending(PendingServerContext {
            cred,
            context,
            attributes,
            sec_buffers,
            _enc: PhantomData,
        })),
        SEC_E_INTERNAL_ERROR => Err(AcceptContextError::Internal),
        SEC_E_INVALID_HANDLE => Err(AcceptContextError::InvalidHandle),
        SEC_E_INVALID_TOKEN => Err(AcceptContextError::InvalidToken),
        SEC_E_LOGON_DENIED => Err(AcceptContextError::Denied),
        SEC_E_NO_AUTHENTICATING_AUTHORITY => Err(AcceptContextError::NoAuthority),
        SEC_E_UNSUPPORTED_FUNCTION => unreachable!("only applicable from Schannel SSP"),
        e => todo!("unknown error code: {e:?}"),
    }
}

pub enum StepOut<Cred, D = NoDelegation> {
    Pending(PendingServerContext<Cred, D>),
    Completed(ServerContext<Cred, D>),
}
