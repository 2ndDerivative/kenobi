pub enum CannotSign {}
pub enum MaybeSign {}
pub enum CanSign {}

pub(crate) mod sign {
    use libgssapi_sys::GSS_C_INTEG_FLAG;

    use super::{CannotSign, MaybeSign};

    pub trait Sealed {
        const REQUESTED_FLAGS: u32 = 0;
    }
    impl Sealed for CannotSign {}
    impl Sealed for MaybeSign {
        const REQUESTED_FLAGS: u32 = GSS_C_INTEG_FLAG;
    }
}

pub trait SignPolicy: sign::Sealed {}
impl<S: sign::Sealed> SignPolicy for S {}

pub enum CannotEncrypt {}
pub enum MaybeEncrypt {}
pub enum CanEncrypt {}

pub(crate) mod encrypt {
    use libgssapi_sys::GSS_C_CONF_FLAG;

    use super::{CannotEncrypt, MaybeEncrypt};
    pub trait Sealed {
        const REQUESTED_FLAGS: u32 = 0;
    }
    impl Sealed for CannotEncrypt {}
    impl Sealed for MaybeEncrypt {
        const REQUESTED_FLAGS: u32 = GSS_C_CONF_FLAG;
    }
}
pub trait EncryptionPolicy: encrypt::Sealed {}
impl<E: encrypt::Sealed> EncryptionPolicy for E {}

pub enum NoDelegation {}
pub enum MaybeDelegatable {}
pub enum Delegatable {}

pub(crate) mod delegation {
    use libgssapi_sys::GSS_C_DELEG_FLAG;

    use crate::client::typestate::{MaybeDelegatable, NoDelegation};

    pub trait Sealed {
        const REQUESTED_FLAGS: u32 = 0;
    }
    impl Sealed for NoDelegation {}
    impl Sealed for MaybeDelegatable {
        const REQUESTED_FLAGS: u32 = GSS_C_DELEG_FLAG;
    }
}

pub trait DelegationPolicy: delegation::Sealed {}
impl<D: delegation::Sealed> DelegationPolicy for D {}
