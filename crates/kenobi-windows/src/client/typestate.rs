use kenobi_core::typestate::{MaybeEncryption, MaybeSigning, NoEncryption, NoSigning};
use windows::Win32::Security::Authentication::Identity::{ISC_RET_CONFIDENTIALITY, ISC_RET_INTEGRITY};

pub(crate) mod signing {
    pub trait Sealed: Sized {
        fn requirements_met_manual(_attr: u32) -> bool;
    }
}

impl<T: signing::Sealed> SigningPolicy for T {}
pub trait SigningPolicy: signing::Sealed {}
impl signing::Sealed for NoSigning {
    fn requirements_met_manual(_attr: u32) -> bool {
        unreachable!()
    }
}
impl signing::Sealed for MaybeSigning {
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
    fn requirements_met_manual(attr: u32) -> bool {
        attr & ISC_RET_CONFIDENTIALITY == ISC_RET_CONFIDENTIALITY
    }
}

pub(crate) mod delegate {
    use kenobi_core::typestate::{MaybeDelegation, NoDelegation};
    pub trait Sealed {
        const RETURN_FLAGS: u32 = 0;
    }
    impl Sealed for NoDelegation {}
    impl Sealed for MaybeDelegation {}
}

pub trait DelegationPolicy: delegate::Sealed {}
impl<T: delegate::Sealed> DelegationPolicy for T {}
