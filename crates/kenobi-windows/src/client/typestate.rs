use kenobi_core::typestate::{DeniedSigning, MaybeEncryption, MaybeSigning, NoEncryption, NoSigning};
use windows::Win32::Security::Authentication::Identity::{
    ISC_REQ_CONFIDENTIALITY, ISC_REQ_FLAGS, ISC_REQ_INTEGRITY, ISC_REQ_NO_INTEGRITY, ISC_RET_CONFIDENTIALITY,
    ISC_RET_INTEGRITY,
};

pub(crate) mod signing {
    use windows::Win32::Security::Authentication::Identity::ISC_REQ_FLAGS;

    pub trait Sealed: Sized {
        const REMOVE_MUTUAL_AUTH_FLAG: bool = false;
        const ADDED_REQ_FLAGS: ISC_REQ_FLAGS = ISC_REQ_FLAGS(0);
        fn requirements_met_manual(_attr: u32) -> bool;
    }
}

impl<T: signing::Sealed> SigningPolicy for T {}
pub trait SigningPolicy: signing::Sealed {}
impl signing::Sealed for DeniedSigning {
    const REMOVE_MUTUAL_AUTH_FLAG: bool = true;
    const ADDED_REQ_FLAGS: ISC_REQ_FLAGS = ISC_REQ_NO_INTEGRITY;
    fn requirements_met_manual(_attr: u32) -> bool {
        unreachable!()
    }
}
impl signing::Sealed for NoSigning {
    fn requirements_met_manual(_attr: u32) -> bool {
        unreachable!()
    }
}
impl signing::Sealed for MaybeSigning {
    const ADDED_REQ_FLAGS: ISC_REQ_FLAGS = ISC_REQ_INTEGRITY;
    fn requirements_met_manual(attr: u32) -> bool {
        attr & ISC_RET_INTEGRITY == ISC_RET_INTEGRITY
    }
}

pub(crate) mod encryption {
    use windows::Win32::Security::Authentication::Identity::ISC_REQ_FLAGS;

    pub trait Sealed: Sized {
        const ADDED_REQ_FLAGS: ISC_REQ_FLAGS = ISC_REQ_FLAGS(0);
        fn requirements_met_manual(_attr: u32) -> bool;
    }
}

impl<T: encryption::Sealed> EncryptionPolicy for T {}
pub trait EncryptionPolicy: encryption::Sealed {}
impl encryption::Sealed for NoEncryption {
    fn requirements_met_manual(_attr: u32) -> bool {
        unreachable!()
    }
}
impl encryption::Sealed for MaybeEncryption {
    const ADDED_REQ_FLAGS: ISC_REQ_FLAGS = ISC_REQ_CONFIDENTIALITY;
    fn requirements_met_manual(attr: u32) -> bool {
        attr & ISC_RET_CONFIDENTIALITY == ISC_RET_CONFIDENTIALITY
    }
}

pub(crate) mod delegate {
    use kenobi_core::typestate::{MaybeDelegation, NoDelegation};
    use windows::Win32::Security::Authentication::Identity::{ISC_REQ_DELEGATE, ISC_REQ_FLAGS};

    pub trait Sealed {
        const ADDED_REQ_FLAGS: ISC_REQ_FLAGS = ISC_REQ_FLAGS(0);
        const RETURN_FLAGS: u32 = 0;
    }
    impl Sealed for NoDelegation {}
    impl Sealed for MaybeDelegation {
        const ADDED_REQ_FLAGS: ISC_REQ_FLAGS = ISC_REQ_DELEGATE;
    }
}

pub trait DelegationPolicy: delegate::Sealed {}
impl<T: delegate::Sealed> DelegationPolicy for T {}
