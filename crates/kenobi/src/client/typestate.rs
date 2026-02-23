use kenobi_core::typestate::{Encryption, MaybeEncryption, MaybeSigning, NoEncryption, NoSigning, Signing};

pub(crate) mod sealed {
    #[cfg(windows)]
    pub trait UnfinishedSigningSealed: super::SigningState<Inner: kenobi_windows::client::SigningPolicy> {}
    #[cfg(unix)]
    pub trait UnfinishedSigningSealed: super::SigningState<Inner: kenobi_unix::client::SignPolicy> {}
    impl UnfinishedSigningSealed for super::NoSigning {}
    impl UnfinishedSigningSealed for super::MaybeSigning {}

    #[cfg(windows)]
    pub trait UnfinishedEncryptionSealed:
        super::EncryptionState<Win: kenobi_windows::client::EncryptionPolicy>
    {
    }
    #[cfg(unix)]
    pub trait UnfinishedEncryptionSealed: super::EncryptionState<Inner: kenobi_unix::client::EncryptionPolicy> {}
    impl UnfinishedEncryptionSealed for super::NoEncryption {}
    impl UnfinishedEncryptionSealed for super::MaybeEncryption {}

    pub trait SigningSealed {
        type Inner;
    }
    impl SigningSealed for super::NoSigning {
        type Inner = kenobi_core::typestate::NoSigning;
    }
    impl SigningSealed for super::MaybeSigning {
        type Inner = kenobi_core::typestate::MaybeSigning;
    }
    impl SigningSealed for super::Signing {
        type Inner = kenobi_core::typestate::Signing;
    }

    pub trait EncryptionSealed {
        type Inner;
    }
    impl EncryptionSealed for super::NoEncryption {
        type Inner = kenobi_core::typestate::NoEncryption;
    }
    impl EncryptionSealed for super::MaybeEncryption {
        type Inner = kenobi_core::typestate::MaybeEncryption;
    }
    impl EncryptionSealed for super::Encryption {
        type Inner = kenobi_core::typestate::Encryption;
    }
}

/// Trait for signing markers which can occur after negotiation has finished
pub trait SigningState: sealed::SigningSealed {}
/// Trait for signing markers which can occur before negotiation has finished
/// (signing cannot be guaranteed to be possible before the context has finished)
pub trait UnfinishedSigningState: sealed::UnfinishedSigningSealed {}

impl SigningState for NoSigning {}
impl UnfinishedSigningState for NoSigning {}

impl SigningState for MaybeSigning {}
impl UnfinishedSigningState for MaybeSigning {}

impl SigningState for Signing {}

/// Trait for encryption markers which can occur after negotiation has finished
pub trait EncryptionState: sealed::EncryptionSealed {}
/// Trait for encryption markers which can occur before negotiation has finished
/// (encryption cannot be guaranteed to be allowed before the context has finished)
pub trait UnfinishedEncryptionState: sealed::UnfinishedEncryptionSealed {}

impl EncryptionState for NoEncryption {}
impl UnfinishedEncryptionState for NoEncryption {}

impl EncryptionState for MaybeEncryption {}
impl UnfinishedEncryptionState for MaybeEncryption {}

impl EncryptionState for Encryption {}
