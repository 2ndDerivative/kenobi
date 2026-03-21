use std::{
    ffi::c_void,
    fmt::Display,
    marker::PhantomData,
    ptr::{self, NonNull},
    sync::Arc,
    time::Duration,
};

use kenobi_core::{
    cred::usage::{InboundUsable, Outbound},
    typestate::{Encryption, MaybeDelegation, MaybeEncryption, MaybeSigning, NoEncryption, NoSigning, Signing},
};
use libgssapi_sys::{
    GSS_C_CONF_FLAG, GSS_C_INTEG_FLAG, GSS_S_COMPLETE, GSS_S_CONTINUE_NEEDED, gss_accept_sec_context,
    gss_buffer_desc_struct, gss_inquire_context,
};

use crate::{
    Error,
    buffer::{Token, as_channel_bindings, empty_token},
    context::ContextHandle,
    cred::Credentials,
    name::NameHandle,
    sign_encrypt,
};
pub use builder::ServerBuilder;
mod builder;

pub struct ServerContext<Usage, S, E, D> {
    cred: Arc<Credentials<Usage>>,
    context: ContextHandle,
    attributes: u32,
    last_token: Option<Token>,
    delegated_creds: Option<Credentials<Outbound>>,
    _enc: PhantomData<(S, E, D)>,
}
impl<CU, S, E, D> ServerContext<CU, S, E, D> {
    fn change_policy<S2, E2, D2>(self) -> ServerContext<CU, S2, E2, D2> {
        ServerContext {
            cred: self.cred,
            context: self.context,
            attributes: self.attributes,
            last_token: self.last_token,
            delegated_creds: self.delegated_creds,
            _enc: PhantomData,
        }
    }
    pub fn last_token(&self) -> Option<&[u8]> {
        self.last_token.as_ref().map(|t| t.as_slice())
    }
    pub fn client_name(&mut self) -> Result<impl Display + Send + Sync, Error> {
        let mut min = 0;
        let mut initiator_name = ptr::null_mut();
        let maj = unsafe {
            gss_inquire_context(
                &mut min,
                self.context.as_mut(),
                &mut initiator_name,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if let Some(err) = Error::gss(maj) {
            return Err(err);
        }
        if let Some(err_min) = Error::mechanism(min) {
            return Err(err_min);
        }
        let Some(nn_name) = NonNull::new(initiator_name) else {
            panic!("gss returned null pointer despite okay value");
        };
        let name = unsafe { NameHandle::from_raw(nn_name) };
        Ok(name)
    }
}
impl<CU, E, D> ServerContext<CU, MaybeSigning, E, D> {
    #[allow(clippy::type_complexity)]
    pub fn check_signing(self) -> Result<ServerContext<CU, Signing, E, D>, ServerContext<CU, NoSigning, E, D>> {
        if self.attributes & GSS_C_INTEG_FLAG != 0 {
            Ok(self.change_policy())
        } else {
            Err(self.change_policy())
        }
    }
}
impl<CU, S, D> ServerContext<CU, S, MaybeEncryption, D> {
    #[allow(clippy::type_complexity)]
    pub fn check_encryption(
        self,
    ) -> Result<ServerContext<CU, S, Encryption, D>, ServerContext<CU, S, NoEncryption, D>> {
        if self.attributes & GSS_C_CONF_FLAG != 0 {
            Ok(self.change_policy())
        } else {
            Err(self.change_policy())
        }
    }
}

impl<CU, E, D> ServerContext<CU, Signing, E, D> {
    pub fn sign(&mut self, message: &[u8]) -> Result<sign_encrypt::Signed, crate::Error> {
        sign_encrypt::sign(&mut self.context, message)
    }

    pub fn unwrap(&mut self, message: &[u8]) -> Result<sign_encrypt::Plaintext, crate::Error> {
        sign_encrypt::unwrap_raw(&mut self.context, message)
    }
}
impl<CU, S, D> ServerContext<CU, S, Encryption, D> {
    pub fn encrypt(&mut self, message: &[u8]) -> Result<sign_encrypt::Encrypted, crate::Error> {
        sign_encrypt::encrypt(&mut self.context, message)
    }
}

pub struct PendingServerContext<CU> {
    context: ContextHandle,
    cred: Arc<Credentials<CU>>,
    next_token: Token,
    principal: Option<NameHandle>,
}
impl<CU: InboundUsable> PendingServerContext<CU> {
    pub fn step(self, token: &[u8]) -> StepOut<CU> {
        step(Some(self.context), self.cred, self.principal, token, None)
    }
}
impl<CU> PendingServerContext<CU> {
    pub fn next_token(&self) -> &[u8] {
        self.next_token.as_slice()
    }
}

fn step<CU: InboundUsable>(
    mut ctx: Option<ContextHandle>,
    cred: Arc<Credentials<CU>>,
    mut principal: Option<NameHandle>,
    token: &[u8],
    channel_bindings: Option<Box<[u8]>>,
) -> StepOut<CU> {
    let mut ctx_ptr = ctx.as_mut().map(ContextHandle::as_mut).unwrap_or_default();
    let mut minor = 0;
    let mut token_buf = gss_buffer_desc_struct {
        length: token.len(),
        value: token.as_ptr() as *mut c_void,
    };
    let mut channel_binding_buffer = channel_bindings.as_deref().map(as_channel_bindings);
    let mut next_token = empty_token();
    let mut attributes = 0;
    let mut remaining_seconds = 0;
    let mut delegated_cred_handle = std::ptr::null_mut();
    match unsafe {
        gss_accept_sec_context(
            &mut minor,
            &mut ctx_ptr,
            cred.as_raw().as_ptr(),
            &mut token_buf,
            channel_binding_buffer.as_mut().map_or(ptr::null_mut(), ptr::from_mut),
            &mut principal.as_mut().map_or(ptr::null_mut(), |n| n.as_mut()),
            ptr::null_mut(),
            &mut next_token,
            &mut attributes,
            &mut remaining_seconds,
            &mut delegated_cred_handle,
        )
    } {
        GSS_S_COMPLETE => {
            let Some(nn_ctx_ptr) = NonNull::new(ctx_ptr) else {
                panic!("GSS returned COMPLETE but didn't offer a new context")
            };
            let last_token = unsafe { Token::from_raw(next_token) };
            let context = ctx.unwrap_or_else(|| unsafe { ContextHandle::from_raw(nn_ctx_ptr) });
            let delegated_creds = NonNull::new(delegated_cred_handle).map(|ch| unsafe {
                Credentials::from_raw_components(ch, cred.mechanism(), Duration::from_secs(remaining_seconds.into()))
            });
            StepOut::Finished(ServerContext {
                cred,
                context,
                attributes,
                last_token,
                delegated_creds,
                _enc: PhantomData,
            })
        }
        stat if stat & GSS_S_CONTINUE_NEEDED != 0 => {
            let Some(x) = NonNull::new(ctx_ptr) else {
                panic!("GSS returned CONTINUE_NEEDED but didn't offer a new context");
            };
            let Some(next_token) = (unsafe { Token::from_raw(next_token) }) else {
                panic!("GSS returned CONTINUE_NEEDED but didn't offer a new token")
            };
            let context = ctx.unwrap_or_else(|| unsafe { ContextHandle::from_raw(x) });
            StepOut::Pending(PendingServerContext {
                context,
                cred,
                next_token,
                principal,
            })
        }
        code => todo!("Error code: {code:?}"),
    }
}

pub enum StepOut<CU> {
    Pending(PendingServerContext<CU>),
    Finished(ServerContext<CU, MaybeSigning, MaybeEncryption, MaybeDelegation>),
}
