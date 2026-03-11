use kenobi_core::typestate::{
    Delegation, Encryption, MaybeDelegation, MaybeEncryption, MaybeSigning, NoDelegation, NoEncryption, NoSigning,
    Signing,
};

pub(crate) mod sealed {
    pub trait SigningSealed {}
    impl SigningSealed for super::NoSigning {}
    impl SigningSealed for super::MaybeSigning {}
    impl SigningSealed for super::Signing {}

    pub trait EncryptionSealed {}
    impl EncryptionSealed for super::NoEncryption {}
    impl EncryptionSealed for super::MaybeEncryption {}
    impl EncryptionSealed for super::Encryption {}

    pub trait DelegationSealed {}
    impl DelegationSealed for super::NoDelegation {}
    impl DelegationSealed for super::MaybeDelegation {}
    impl DelegationSealed for super::Delegation {}
}

/// Trait for signing markers which can occur after negotiation has finished
pub trait SigningState: sealed::SigningSealed {}
impl SigningState for NoSigning {}
impl SigningState for MaybeSigning {}
impl SigningState for Signing {}

/// Trait for encryption markers which can occur after negotiation has finished
pub trait EncryptionState: sealed::EncryptionSealed {}
impl EncryptionState for NoEncryption {}
impl EncryptionState for MaybeEncryption {}
impl EncryptionState for Encryption {}

pub trait DelegationState: sealed::DelegationSealed {}

impl DelegationState for NoDelegation {}

impl DelegationState for MaybeDelegation {}

impl DelegationState for Delegation {}
