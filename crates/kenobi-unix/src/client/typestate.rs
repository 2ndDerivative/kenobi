pub(crate) mod sign {
    use kenobi_core::typestate::{MaybeSigning, NoSigning};

    pub trait Sealed {}
    impl Sealed for NoSigning {}
    impl Sealed for MaybeSigning {}
}

pub trait SignPolicy: sign::Sealed {}
impl<S: sign::Sealed> SignPolicy for S {}

pub(crate) mod encrypt {
    use kenobi_core::typestate::{MaybeEncryption, NoEncryption};

    pub trait Sealed {}
    impl Sealed for NoEncryption {}
    impl Sealed for MaybeEncryption {}
}
pub trait EncryptionPolicy: encrypt::Sealed {}
impl<E: encrypt::Sealed> EncryptionPolicy for E {}

pub(crate) mod delegation {
    use kenobi_core::typestate::{MaybeDelegation, NoDelegation};

    pub trait Sealed {}
    impl Sealed for NoDelegation {}
    impl Sealed for MaybeDelegation {}
}

pub trait DelegationPolicy: delegation::Sealed {}
impl<D: delegation::Sealed> DelegationPolicy for D {}
