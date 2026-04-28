use std::{
    ffi::c_void,
    marker::PhantomData,
    ptr::{self, NonNull},
    sync::Arc,
    time::{Duration, Instant},
};

use kenobi_core::{cred::usage::OutboundUsable, flags::CapabilityFlags};
use libgssapi_sys::{
    _GSS_C_INDEFINITE, GSS_C_CONF_FLAG, GSS_C_DELEG_FLAG, GSS_C_INTEG_FLAG, GSS_C_MUTUAL_FLAG, GSS_S_COMPLETE,
    GSS_S_CONTINUE_NEEDED, gss_buffer_desc_struct, gss_delete_sec_context, gss_init_sec_context,
};

use crate::{
    Error,
    buffer::{Token, as_channel_bindings, empty_token},
    context::{ContextHandle, SessionKey},
    cred::Credentials,
    error::{GssErrorCode, MechanismErrorCode},
    mech_kerberos,
    name::NameHandle,
    sign_encrypt,
};
mod builder;
mod typestate;

pub use builder::ClientBuilder;
use kenobi_core::typestate::{
    Delegation, Encryption, MaybeDelegation, MaybeEncryption, MaybeSigning, NoDelegation, NoEncryption, NoSigning,
    Signing,
};
pub use typestate::{DelegationPolicy, EncryptionPolicy, SignPolicy};

pub struct ClientContext<CU, S, E, D> {
    attributes: u32,
    cred: Arc<Credentials<CU>>,
    context: ContextHandle,
    next_token: Option<Token>,
    marker: PhantomData<(S, E, D)>,
}

impl<CU: OutboundUsable> ClientContext<CU, NoSigning, NoEncryption, NoDelegation> {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(cred: Arc<Credentials<CU>>, target_principal: Option<&str>) -> Result<StepOut<CU>, Error> {
        ClientBuilder::new(cred, target_principal)?.initialize()
    }
}
impl<CU, E, D> ClientContext<CU, MaybeSigning, E, D> {
    #[allow(clippy::type_complexity)]
    /// Statically ensures the `ClientContext` is allowed to use signing operations
    ///
    /// # Errors
    /// an error is `GSS_C_INTEG_FLAG` not being set on the finished context, but gives back the context without Signing enabled
    pub fn check_signing(self) -> Result<ClientContext<CU, Signing, E, D>, ClientContext<CU, NoSigning, E, D>> {
        if self.attributes & GSS_C_INTEG_FLAG != 0 {
            Ok(self.change_policy())
        } else {
            Err(self.change_policy())
        }
    }
}
impl<CU, S, D> ClientContext<CU, S, MaybeEncryption, D> {
    #[allow(clippy::type_complexity)]
    /// Statically ensures the `ClientContext` is allowed to use encryption operations
    ///
    /// # Errors
    /// an error is `GSS_C_CONF_FLAG` not being set on the finished context, but gives back the context without Encryption enabled
    pub fn check_encryption(
        self,
    ) -> Result<ClientContext<CU, S, Encryption, D>, ClientContext<CU, S, NoEncryption, D>> {
        if self.attributes & GSS_C_CONF_FLAG != 0 {
            Ok(self.change_policy())
        } else {
            Err(self.change_policy())
        }
    }
}
impl<CU, S, E> ClientContext<CU, S, E, MaybeDelegation> {
    #[allow(clippy::type_complexity)]
    /// Statically ensures the `ClientContext` is set up to forwarding the TGT
    ///
    /// # Errors
    /// an error is `GSS_C_DELEG_FLAG` not being set on the finished context, but gives back the context without Delegation operations enabled
    pub fn check_delegation(
        self,
    ) -> Result<ClientContext<CU, S, E, Delegation>, ClientContext<CU, S, E, NoDelegation>> {
        if self.attributes & GSS_C_DELEG_FLAG != 0 {
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
    #[must_use]
    pub fn last_token(&self) -> Option<&[u8]> {
        self.next_token.as_ref().map(Token::as_slice)
    }
    /// # Errors
    /// Forwards the failure from `gss_inquire_sec_context_by_oid`
    pub fn session_key(&self) -> Result<SessionKey, Error> {
        self.context.session_key()
    }
}

impl<CU, E, D> ClientContext<CU, Signing, E, D> {
    /// # Errors
    /// - Error from the underlying `gss_wrap`
    pub fn sign(&mut self, message: &[u8]) -> Result<sign_encrypt::Signed, Error> {
        sign_encrypt::sign(&mut self.context, message)
    }

    /// # Errors
    /// - Error from the underlying `gss_unwrap`
    pub fn unwrap(&mut self, message: &[u8]) -> Result<sign_encrypt::Plaintext, Error> {
        sign_encrypt::unwrap_raw(&mut self.context, message)
    }
}
impl<CU, S, D> ClientContext<CU, S, Encryption, D> {
    /// # Errors
    /// - Error from the underlying `gss_wrap`
    pub fn encrypt(&mut self, message: &[u8]) -> Result<sign_encrypt::Encrypted, Error> {
        sign_encrypt::encrypt(&mut self.context, message)
    }
}

pub struct PendingClientContext<CU> {
    context: ContextHandle,
    cred: Arc<Credentials<CU>>,
    next_token: Token,
    flags: CapabilityFlags,
    target_principal: Option<NameHandle>,
    requested_duration: Option<Duration>,
    channel_bindings: Option<Box<[u8]>>,
    #[expect(dead_code)]
    valid_until: Instant,
}
impl<CU: OutboundUsable> PendingClientContext<CU> {
    pub fn step(self, token: &[u8]) -> Result<StepOut<CU>, Error> {
        step(
            Some(self.context),
            self.cred,
            self.flags,
            self.target_principal,
            Some(token),
            self.requested_duration,
            self.channel_bindings,
        )
    }
}
impl<CU> PendingClientContext<CU> {
    #[must_use]
    pub fn next_token(&self) -> &[u8] {
        self.next_token.as_slice()
    }
}

fn step<CU: OutboundUsable>(
    mut ctx: Option<ContextHandle>,
    cred: Arc<Credentials<CU>>,
    flags: CapabilityFlags,
    mut target_principal: Option<NameHandle>,
    token: Option<&[u8]>,
    requested_duration: Option<Duration>,
    channel_bindings: Option<Box<[u8]>>,
) -> Result<StepOut<CU>, Error> {
    let mut ctx_ptr = ctx.as_mut().map(ContextHandle::as_mut).unwrap_or_default();
    let mut minor_status = 0;
    let mut remaining_seconds = 0;
    let mut attributes = 0;
    let mut next_token = empty_token();
    let mut mech_type = ptr::null_mut();
    let mut input_token = token.map_or(
        gss_buffer_desc_struct {
            length: 0,
            value: ptr::null_mut(),
        },
        |slice| gss_buffer_desc_struct {
            length: slice.len(),
            value: slice.as_ptr() as *mut c_void,
        },
    );
    let mut channel_application_buffer = channel_bindings.as_deref().map(as_channel_bindings);
    match unsafe {
        gss_init_sec_context(
            &raw mut minor_status,
            cred.as_raw().as_ptr(),
            &raw mut ctx_ptr,
            target_principal.as_mut().map_or(ptr::null_mut(), NameHandle::as_mut),
            &mut mech_kerberos(),
            convert_flags(flags),
            requested_duration.map_or(_GSS_C_INDEFINITE, |d| d.as_secs().min(u32::MAX.into()) as u32),
            channel_application_buffer
                .as_mut()
                .map_or(ptr::null_mut(), ptr::from_mut),
            &raw mut input_token,
            &raw mut mech_type,
            &raw mut next_token,
            &raw mut attributes,
            &raw mut remaining_seconds,
        )
    } {
        GSS_S_COMPLETE => Ok(StepOut::Finished(ClientContext {
            attributes,
            cred,
            context: ctx.unwrap_or_else(|| unsafe { ContextHandle::from_raw(NonNull::new(ctx_ptr).unwrap()) }),
            next_token: unsafe { Token::from_raw(next_token) },
            marker: PhantomData,
        })),
        stat if stat & GSS_S_CONTINUE_NEEDED != 0 => {
            let valid_until = Instant::now() + Duration::from_secs(remaining_seconds.into());
            Ok(StepOut::Pending(PendingClientContext {
                cred,
                context: ctx.unwrap_or_else(|| unsafe { ContextHandle::from_raw(NonNull::new(ctx_ptr).unwrap()) }),
                next_token: unsafe { Token::from_raw(next_token).unwrap() },
                flags,
                target_principal,
                valid_until,
                requested_duration,
                channel_bindings,
            }))
        }
        code => {
            if ctx.is_none() && !ctx_ptr.is_null() {
                let mut s = 0;
                unsafe { gss_delete_sec_context(&raw mut s, &raw mut ctx_ptr, ptr::null_mut()) };
            }
            if let Some(err) = MechanismErrorCode::new(minor_status) {
                return Err(Error::new(err.into()));
            }
            Err(Error::new(
                GssErrorCode::new(code).expect("is not GSS_C_COMPLETE").into(),
            ))
        }
    }
}

pub enum StepOut<CU> {
    Pending(PendingClientContext<CU>),
    Finished(ClientContext<CU, MaybeSigning, MaybeEncryption, MaybeDelegation>),
}

fn convert_flags(flags: CapabilityFlags) -> u32 {
    let mut out = 0;
    if flags.contains_all(CapabilityFlags::MUTUAL_AUTH) {
        out |= GSS_C_MUTUAL_FLAG;
    }
    if flags.contains_all(CapabilityFlags::INTEGRITY) {
        out |= GSS_C_INTEG_FLAG;
    }
    if flags.contains_all(CapabilityFlags::CONFIDENTIALITY) {
        out |= GSS_C_CONF_FLAG;
    }
    if flags.contains_all(CapabilityFlags::DELEGATE) {
        out |= GSS_C_DELEG_FLAG;
    }
    out
}
