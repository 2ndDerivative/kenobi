pub use kenobi_core::cred::usage::{Both, Inbound, Outbound};
use kenobi_core::mech::Mechanism;
use std::{
    fmt::{Debug, Formatter, Result as FmtResult},
    marker::PhantomData,
    ptr::NonNull,
    time::{Duration, Instant},
};

use libgssapi_sys::{
    _GSS_C_INDEFINITE, _GSS_S_FAILURE, GSS_C_ACCEPT, GSS_C_BOTH, GSS_C_INITIATE, GSS_C_NT_HOSTBASED_SERVICE,
    GSS_C_NT_USER_NAME, gss_OID, gss_OID_set_desc, gss_acquire_cred, gss_cred_id_struct, gss_release_cred,
};

use crate::{
    Error,
    error::{ErrorKind, GssErrorCode, MechanismErrorCode},
    name::NameHandle,
};

pub struct Credentials<Usage = Outbound> {
    cred_handle: NonNull<gss_cred_id_struct>,
    mechanism: Mechanism,
    valid_until: Instant,
    _usage: PhantomData<Usage>,
}
// Valid, because Credentials does not expose any mutability and is the sole owner of the underlying memory
unsafe impl<Usage> Send for Credentials<Usage> {}
unsafe impl<Usage> Sync for Credentials<Usage> {}
impl<Usage: CredentialsUsage> Credentials<Usage> {
    fn new(
        principal: Option<&str>,
        time_required: Option<Duration>,
        mechanism: Mechanism,
        oid: gss_OID,
    ) -> Result<Self, super::Error> {
        let mut name = principal.map(|p| unsafe { NameHandle::import(p, oid) }).transpose()?;
        let mut minor = 0;
        let mut validity = 0;
        let mut cred_handle = std::ptr::null_mut();
        let mut mech = match mechanism {
            Mechanism::KerberosV5 => crate::mech_kerberos(),
            Mechanism::Spnego => crate::mech_spnego(),
        };
        let mut mech_set = gss_OID_set_desc {
            count: 1,
            elements: &raw mut mech,
        };
        if let Some(error) = GssErrorCode::new(unsafe {
            gss_acquire_cred(
                &raw mut minor,
                name.as_mut().map(NameHandle::as_mut).unwrap_or_default(),
                time_required.map_or(_GSS_C_INDEFINITE, |d| d.as_secs().try_into().unwrap_or(u32::MAX)),
                &raw mut mech_set,
                Usage::to_c(),
                &raw mut cred_handle,
                std::ptr::null_mut(),
                &raw mut validity,
            )
        }) {
            return Err(Error::new(error.into()));
        }
        if let Some(error) = MechanismErrorCode::new(minor) {
            return Err(Error::new(error.into()));
        }

        let valid_until = Instant::now() + Duration::from_secs(validity.into());
        let Some(cred_handle) = NonNull::new(cred_handle) else {
            return Err(Error::new(ErrorKind::gss(_GSS_S_FAILURE).unwrap()));
        };
        Ok(Self {
            cred_handle,
            mechanism,
            valid_until,
            _usage: PhantomData,
        })
    }
}
impl<Usage> Credentials<Usage> {
    pub(crate) fn as_raw(&self) -> NonNull<gss_cred_id_struct> {
        self.cred_handle
    }
    #[must_use]
    pub fn mechanism(&self) -> Mechanism {
        self.mechanism
    }
    #[must_use]
    pub fn valid_until(&self) -> Instant {
        self.valid_until
    }
    pub(crate) unsafe fn from_raw_components(
        handle: NonNull<gss_cred_id_struct>,
        mechanism: Mechanism,
        validity: Duration,
    ) -> Self {
        Self {
            cred_handle: handle,
            mechanism,
            valid_until: Instant::now() + validity,
            _usage: PhantomData,
        }
    }
}
impl Credentials<Inbound> {
    /// # Errors
    /// The underlying call to ``gss_acquire_cred`` failed
    pub fn inbound(
        principal: Option<&str>,
        time_required: Option<Duration>,
        mechanism: Mechanism,
    ) -> Result<Self, super::Error> {
        Self::new(principal, time_required, mechanism, unsafe {
            GSS_C_NT_HOSTBASED_SERVICE
        })
    }
}
impl Credentials<Outbound> {
    /// # Errors
    /// The underlying call to ``gss_acquire_cred`` failed
    pub fn outbound(
        principal: Option<&str>,
        time_required: Option<Duration>,
        mechanism: Mechanism,
    ) -> Result<Self, super::Error> {
        Self::new(principal, time_required, mechanism, unsafe { GSS_C_NT_USER_NAME })
    }
}
impl Credentials<Both> {
    /// # Errors
    /// The underlying call to ``gss_acquire_cred`` failed
    pub fn both(
        principal: Option<&str>,
        time_required: Option<Duration>,
        mechanism: Mechanism,
    ) -> Result<Self, super::Error> {
        Self::new(principal, time_required, mechanism, unsafe {
            GSS_C_NT_HOSTBASED_SERVICE
        })
    }
}
impl<T> Drop for Credentials<T> {
    fn drop(&mut self) {
        let mut s = 0;
        unsafe {
            gss_release_cred(&raw mut s, &mut NonNull::as_ptr(self.cred_handle));
        }
    }
}
impl<CU> Debug for Credentials<CU> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("Credentials")
            .field("mechanism", &self.mechanism)
            .field("valid_until", &self.valid_until)
            .finish()
    }
}
pub trait CredentialsUsage {
    fn to_c() -> i32;
}
impl CredentialsUsage for Inbound {
    fn to_c() -> i32 {
        GSS_C_ACCEPT.cast_signed()
    }
}
impl CredentialsUsage for Outbound {
    fn to_c() -> i32 {
        GSS_C_INITIATE.cast_signed()
    }
}
impl CredentialsUsage for Both {
    fn to_c() -> i32 {
        GSS_C_BOTH.cast_signed()
    }
}
