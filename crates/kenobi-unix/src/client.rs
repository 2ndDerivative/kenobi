use std::{
    ffi::c_void,
    marker::PhantomData,
    ptr::NonNull,
    time::{Duration, Instant},
};

use kenobi_core::cred::usage::OutboundUsable;
use libgssapi_sys::{
    _GSS_C_INDEFINITE, GSS_C_MUTUAL_FLAG, GSS_S_COMPLETE, GSS_S_CONTINUE_NEEDED, gss_buffer_desc,
    gss_buffer_desc_struct, gss_channel_bindings_struct, gss_delete_sec_context, gss_init_sec_context,
    gss_release_buffer,
};

use crate::{
    Error,
    client::typestate::{DelegationPolicy, delegation::Sealed as _, encrypt::Sealed as _, sign::Sealed as _},
    context::{ContextHandle, SessionKey},
    cred::Credentials,
    error::{GssErrorCode, MechanismErrorCode},
    name::NameHandle,
};
mod builder;
mod typestate;

pub use builder::ClientBuilder;
use kenobi_core::typestate::{Encryption, MaybeEncryption, MaybeSigning, NoEncryption, NoSigning, Signing};
pub use typestate::{Delegatable, EncryptionPolicy, MaybeDelegatable, NoDelegation, SignPolicy};

pub struct ClientContext<CU, S, E, D> {
    attributes: u32,
    cred: Credentials<CU>,
    pub(crate) context: ContextHandle,
    next_token: gss_buffer_desc,
    marker: PhantomData<(S, E, D)>,
}

impl<CU: OutboundUsable> ClientContext<CU, NoSigning, NoEncryption, NoDelegation> {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        cred: Credentials<CU>,
        target_principal: Option<&str>,
    ) -> Result<StepOut<CU, NoSigning, NoEncryption, NoDelegation>, Error> {
        ClientBuilder::new(cred, target_principal)?.initialize()
    }
}
impl<CU, E, D> ClientContext<CU, MaybeSigning, E, D> {
    #[allow(clippy::type_complexity)]
    pub fn check_signing(self) -> Result<ClientContext<CU, Signing, E, D>, ClientContext<CU, NoSigning, E, D>> {
        if self.attributes & MaybeSigning::REQUESTED_FLAGS != 0 {
            Ok(self.change_policy())
        } else {
            Err(self.change_policy())
        }
    }
}
impl<CU, S, D> ClientContext<CU, S, MaybeEncryption, D> {
    #[allow(clippy::type_complexity)]
    pub fn check_encryption(
        self,
    ) -> Result<ClientContext<CU, S, Encryption, D>, ClientContext<CU, S, NoEncryption, D>> {
        if self.attributes & MaybeEncryption::REQUESTED_FLAGS != 0 {
            Ok(self.change_policy())
        } else {
            Err(self.change_policy())
        }
    }
}
impl<CU, S, E> ClientContext<CU, S, E, MaybeDelegatable> {
    #[allow(clippy::type_complexity)]
    pub fn check_delegation(
        self,
    ) -> Result<ClientContext<CU, S, E, Delegatable>, ClientContext<CU, S, E, NoDelegation>> {
        if self.attributes & MaybeDelegatable::REQUESTED_FLAGS != 0 {
            Ok(self.change_policy())
        } else {
            Err(self.change_policy())
        }
    }
}
impl<CU, S1, E1, D1> ClientContext<CU, S1, E1, D1> {
    fn change_policy<S2, E2, D2>(self) -> ClientContext<CU, S2, E2, D2> {
        ClientContext {
            attributes: self.attributes,
            cred: self.cred,
            context: self.context,
            next_token: self.next_token,
            marker: PhantomData,
        }
    }
    pub fn last_token(&self) -> Option<&[u8]> {
        if self.next_token.length == 0 || self.next_token.value.is_null() {
            None
        } else {
            let slice =
                unsafe { std::slice::from_raw_parts(self.next_token.value as *const u8, self.next_token.length) };
            Some(slice)
        }
    }
    pub fn session_key(&self) -> Result<SessionKey, Error> {
        self.context.session_key()
    }
}

pub struct PendingClientContext<CU, S, E, D> {
    context: ContextHandle,
    cred: Credentials<CU>,
    next_token: Token,
    target_principal: Option<NameHandle>,
    requested_duration: Option<Duration>,
    channel_bindings: Option<Box<[u8]>>,
    #[expect(dead_code)]
    valid_until: Instant,
    marker: PhantomData<(S, E, D)>,
}
impl<CU: OutboundUsable, S: SignPolicy, E: EncryptionPolicy, D: DelegationPolicy> PendingClientContext<CU, S, E, D> {
    pub fn step(self, token: &[u8]) -> Result<StepOut<CU, S, E, D>, Error> {
        step(
            Some(self.context),
            self.cred,
            self.target_principal,
            Some(token),
            self.requested_duration,
            self.channel_bindings,
        )
    }
}
impl<CU, S: SignPolicy, E: EncryptionPolicy, D: DelegationPolicy> PendingClientContext<CU, S, E, D> {
    pub fn next_token(&self) -> &[u8] {
        self.next_token.as_slice()
    }
}

fn empty_token() -> gss_buffer_desc {
    gss_buffer_desc {
        length: 0,
        value: std::ptr::null_mut(),
    }
}

fn step<CU: OutboundUsable, S: SignPolicy, E: EncryptionPolicy, D: DelegationPolicy>(
    mut ctx: Option<ContextHandle>,
    cred: Credentials<CU>,
    mut target_principal: Option<NameHandle>,
    token: Option<&[u8]>,
    requested_duration: Option<Duration>,
    channel_bindings: Option<Box<[u8]>>,
) -> Result<StepOut<CU, S, E, D>, Error> {
    let mut ctx_ptr = ctx.as_mut().map(|c| std::ptr::from_mut(c.as_mut())).unwrap_or_default();
    let mut minor_status = 0;
    let mut remaining_seconds = 0;
    let mut attributes = 0;
    let mut next_token = empty_token();
    let mut mech_type = std::ptr::null_mut();
    let mut input_token = token
        .map(|slice| gss_buffer_desc_struct {
            length: slice.len(),
            value: slice.as_ptr() as *mut c_void,
        })
        .unwrap_or(gss_buffer_desc_struct {
            length: 0,
            value: std::ptr::null_mut(),
        });
    let mut channel_application_buffer = channel_bindings.as_deref().map(as_channel_bindings);
    match unsafe {
        gss_init_sec_context(
            &mut minor_status,
            NonNull::as_ptr(cred.cred_handle),
            &mut ctx_ptr,
            target_principal.as_mut().map_or(std::ptr::null_mut(), |nn| nn.as_mut()),
            std::ptr::null_mut(),
            GSS_C_MUTUAL_FLAG | S::REQUESTED_FLAGS | E::REQUESTED_FLAGS | D::REQUESTED_FLAGS,
            requested_duration.map_or(_GSS_C_INDEFINITE, |d| d.as_secs().min(u32::MAX.into()) as u32),
            channel_application_buffer
                .as_mut()
                .map_or(std::ptr::null_mut(), std::ptr::from_mut),
            &mut input_token,
            &mut mech_type,
            &mut next_token,
            &mut attributes,
            &mut remaining_seconds,
        )
    } {
        GSS_S_COMPLETE => Ok(StepOut::Finished(ClientContext {
            attributes,
            cred,
            context: ctx.unwrap_or_else(|| ContextHandle::new(NonNull::new(ctx_ptr).unwrap())),
            next_token,
            marker: PhantomData,
        })),
        stat if stat & GSS_S_CONTINUE_NEEDED != 0 => {
            let valid_until = Instant::now() + Duration::from_secs(remaining_seconds.into());
            Ok(StepOut::Pending(PendingClientContext {
                cred,
                context: ctx.unwrap_or_else(|| ContextHandle::new(NonNull::new(ctx_ptr).unwrap())),
                next_token: Token(next_token),
                target_principal,
                valid_until,
                requested_duration,
                channel_bindings,
                marker: PhantomData,
            }))
        }
        code => {
            if ctx.is_none() && !ctx_ptr.is_null() {
                let mut _s = 0;
                unsafe { gss_delete_sec_context(&mut _s, &mut ctx_ptr, std::ptr::null_mut()) };
            }
            if let Some(err) = MechanismErrorCode::new(minor_status) {
                return Err(err.into());
            };
            Err(GssErrorCode::new(code).unwrap().into())
        }
    }
}

pub enum StepOut<CU, S, E, D> {
    Pending(PendingClientContext<CU, S, E, D>),
    Finished(ClientContext<CU, S, E, D>),
}

struct Token(gss_buffer_desc);
impl Drop for Token {
    fn drop(&mut self) {
        let mut _min = 0;
        let _maj = unsafe { gss_release_buffer(&mut _min, &mut self.0) };
    }
}
impl Token {
    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.0.value as *const u8, self.0.length) }
    }
}

fn as_channel_bindings(arr: &[u8]) -> gss_channel_bindings_struct {
    gss_channel_bindings_struct {
        initiator_addrtype: 0,
        initiator_address: gss_buffer_desc_struct {
            length: 0,
            value: std::ptr::null_mut(),
        },
        acceptor_addrtype: 0,
        acceptor_address: gss_buffer_desc_struct {
            length: 0,
            value: std::ptr::null_mut(),
        },
        application_data: gss_buffer_desc_struct {
            length: arr.len(),
            value: arr.as_ptr() as *mut c_void,
        },
    }
}
