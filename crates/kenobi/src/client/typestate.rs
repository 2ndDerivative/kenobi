pub(crate) mod sealed {
    #[cfg(windows)]
    pub trait UnfinishedSigningSealed: super::SigningState<Win: kenobi_windows::client::SigningPolicy> {}
    #[cfg(unix)]
    pub trait UnfinishedSigningSealed: super::SigningState<Unix: kenobi_unix::client::SignPolicy> {}
    impl UnfinishedSigningSealed for super::NoSigning {}
    impl UnfinishedSigningSealed for super::MaybeSigning {}

    #[cfg(windows)]
    pub trait UnfinishedEncryptionSealed:
        super::EncryptionState<Win: kenobi_windows::client::EncryptionPolicy>
    {
    }
    #[cfg(unix)]
    pub trait UnfinishedEncryptionSealed: super::EncryptionState<Unix: kenobi_unix::client::EncryptionPolicy> {}
    impl UnfinishedEncryptionSealed for super::NoEncryption {}
    impl UnfinishedEncryptionSealed for super::MaybeEncryption {}

    pub trait SigningSealed {
        #[cfg(windows)]
        type Win;
        #[cfg(unix)]
        type Unix;
    }
    impl SigningSealed for super::NoSigning {
        #[cfg(unix)]
        type Unix = kenobi_unix::client::CannotSign;
        #[cfg(windows)]
        type Win = kenobi_windows::client::CannotSign;
    }
    impl SigningSealed for super::MaybeSigning {
        #[cfg(unix)]
        type Unix = kenobi_unix::client::MaybeSign;
        #[cfg(windows)]
        type Win = kenobi_windows::client::MaybeSign;
    }
    impl SigningSealed for super::Signing {
        #[cfg(unix)]
        type Unix = kenobi_unix::client::CanSign;
        #[cfg(windows)]
        type Win = kenobi_windows::client::CanSign;
    }

    pub trait EncryptionSealed {
        #[cfg(windows)]
        type Win;
        #[cfg(unix)]
        type Unix;
    }
    impl EncryptionSealed for super::NoEncryption {
        #[cfg(unix)]
        type Unix = kenobi_unix::client::CannotEncrypt;
        #[cfg(windows)]
        type Win = kenobi_windows::client::CannotEncrypt;
    }
    impl EncryptionSealed for super::MaybeEncryption {
        #[cfg(unix)]
        type Unix = kenobi_unix::client::MaybeEncrypt;
        #[cfg(windows)]
        type Win = kenobi_windows::client::MaybeEncrypt;
    }
    impl EncryptionSealed for super::Encryption {
        #[cfg(unix)]
        type Unix = kenobi_unix::client::CanEncrypt;
        #[cfg(windows)]
        type Win = kenobi_windows::client::CanEncrypt;
    }
}

/// Trait for signing markers which can occur after negotiation has finished
pub trait SigningState: sealed::SigningSealed {}
/// Trait for signing markers which can occur before negotiation has finished
/// (signing cannot be guaranteed to be possible before the context has finished)
pub trait UnfinishedSigningState: sealed::UnfinishedSigningSealed {}

pub enum NoSigning {}
impl SigningState for NoSigning {}
impl UnfinishedSigningState for NoSigning {}

pub enum MaybeSigning {}
impl SigningState for MaybeSigning {}
impl UnfinishedSigningState for MaybeSigning {}

pub enum Signing {}
impl SigningState for Signing {}

/// Trait for encryption markers which can occur after negotiation has finished
pub trait EncryptionState: sealed::EncryptionSealed {}
/// Trait for encryption markers which can occur before negotiation has finished
/// (encryption cannot be guaranteed to be allowed before the context has finished)
pub trait UnfinishedEncryptionState: sealed::UnfinishedEncryptionSealed {}

pub enum NoEncryption {}
impl EncryptionState for NoEncryption {}
impl UnfinishedEncryptionState for NoEncryption {}

pub enum MaybeEncryption {}
impl EncryptionState for MaybeEncryption {}
impl UnfinishedEncryptionState for MaybeEncryption {}

pub enum Encryption {}
impl EncryptionState for Encryption {}
