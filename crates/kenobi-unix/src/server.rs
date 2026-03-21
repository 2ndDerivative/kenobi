use std::{
    ffi::c_void,
    marker::PhantomData,
    ptr::{self, NonNull},
    sync::Arc,
    time::Duration,
};

use kenobi_core::{
    cred::usage::{InboundUsable, Outbound},
    typestate::{MaybeDelegation, MaybeEncryption, MaybeSigning},
};
use libgssapi_sys::{GSS_S_COMPLETE, GSS_S_CONTINUE_NEEDED, gss_accept_sec_context, gss_buffer_desc_struct};

use crate::{
    buffer::{Token, as_channel_bindings, empty_token},
    context::ContextHandle,
    cred::Credentials,
    name::NameHandle,
};

pub struct ServerContext<Usage, S, E, D> {
    cred: Arc<Credentials<Usage>>,
    pub(crate) context: ContextHandle,
    attributes: u32,
    last_token: Option<Token>,
    delegated_creds: Option<Credentials<Outbound>>,
    _enc: PhantomData<(S, E, D)>,
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
