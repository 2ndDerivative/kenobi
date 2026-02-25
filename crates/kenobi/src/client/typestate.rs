use kenobi_core::typestate::{
    Delegation, DeniedSigning, Encryption, MaybeDelegation, MaybeEncryption, MaybeSigning, NoDelegation, NoEncryption,
    NoSigning, Signing,
};

pub(crate) mod sealed {
    #[cfg(windows)]
    pub trait UnfinishedSigningSealed: kenobi_windows::client::SigningPolicy {}
    #[cfg(unix)]
    pub trait UnfinishedSigningSealed: kenobi_unix::client::SignPolicy {}
    impl UnfinishedSigningSealed for super::NoSigning {}
    impl UnfinishedSigningSealed for super::MaybeSigning {}
    impl UnfinishedSigningSealed for super::DeniedSigning {}

    #[cfg(windows)]
    pub trait UnfinishedEncryptionSealed: kenobi_windows::client::EncryptionPolicy {}
    #[cfg(unix)]
    pub trait UnfinishedEncryptionSealed: kenobi_unix::client::EncryptionPolicy {}
    impl UnfinishedEncryptionSealed for super::NoEncryption {}
    impl UnfinishedEncryptionSealed for super::MaybeEncryption {}

    #[cfg(windows)]
    pub trait UnfinishedDelegationSealed: kenobi_windows::client::DelegationPolicy {}
    #[cfg(unix)]
    pub trait UnfinishedDelegationSealed: kenobi_unix::client::DelegationPolicy {}
    impl UnfinishedDelegationSealed for super::NoDelegation {}
    impl UnfinishedDelegationSealed for super::MaybeDelegation {}

    pub trait SigningSealed {}
    impl SigningSealed for super::NoSigning {}
    impl SigningSealed for super::DeniedSigning {}
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
/// Trait for signing markers which can occur before negotiation has finished
/// (signing cannot be guaranteed to be possible before the context has finished)
pub trait UnfinishedSigningState: SigningState + sealed::UnfinishedSigningSealed {}

impl SigningState for NoSigning {}
impl UnfinishedSigningState for NoSigning {}

impl SigningState for DeniedSigning {}
impl UnfinishedSigningState for DeniedSigning {}

impl SigningState for MaybeSigning {}
impl UnfinishedSigningState for MaybeSigning {}

impl SigningState for Signing {}

/// Trait for encryption markers which can occur after negotiation has finished
pub trait EncryptionState: sealed::EncryptionSealed {}
/// Trait for encryption markers which can occur before negotiation has finished
/// (encryption cannot be guaranteed to be allowed before the context has finished)
pub trait UnfinishedEncryptionState: EncryptionState + sealed::UnfinishedEncryptionSealed {}

impl EncryptionState for NoEncryption {}
impl UnfinishedEncryptionState for NoEncryption {}

impl EncryptionState for MaybeEncryption {}
impl UnfinishedEncryptionState for MaybeEncryption {}

impl EncryptionState for Encryption {}

pub trait DelegationState: sealed::DelegationSealed {}
pub trait UnfinishedDelegationState: DelegationState + sealed::UnfinishedDelegationSealed {}

impl DelegationState for NoDelegation {}
impl UnfinishedDelegationState for NoDelegation {}

impl DelegationState for MaybeDelegation {}
impl UnfinishedDelegationState for MaybeDelegation {}

impl DelegationState for Delegation {}
