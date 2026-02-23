pub(crate) mod sign {
    use kenobi_core::typestate::{DeniedSigning, MaybeSigning, NoSigning};
    use libgssapi_sys::GSS_C_INTEG_FLAG;

    pub trait Sealed {
        const REQUESTED_FLAGS: u32 = 0;
    }
    impl Sealed for NoSigning {}
    impl Sealed for DeniedSigning {}
    impl Sealed for MaybeSigning {
        const REQUESTED_FLAGS: u32 = GSS_C_INTEG_FLAG;
    }
}

pub trait SignPolicy: sign::Sealed {}
impl<S: sign::Sealed> SignPolicy for S {}

pub(crate) mod encrypt {
    use kenobi_core::typestate::{MaybeEncryption, NoEncryption};
    use libgssapi_sys::GSS_C_CONF_FLAG;

    pub trait Sealed {
        const REQUESTED_FLAGS: u32 = 0;
    }
    impl Sealed for NoEncryption {}
    impl Sealed for MaybeEncryption {
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
