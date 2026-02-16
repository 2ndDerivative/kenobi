pub(crate) mod sealed {
    #[cfg(windows)]
    use crate::client::EncryptionState;
    use crate::client::SigningState;

    #[cfg(windows)]
    pub trait SigningSealed: SigningState<Win: kenobi_windows::client::SigningPolicy> {}
    #[cfg(unix)]
    pub trait SigningSealed: SigningState<Win: kenobi_unix::client::SignPolicy> {}
    impl SigningSealed for super::NoSigning {}
    impl SigningSealed for super::MaybeSigning {}

    #[cfg(windows)]
    pub trait EncryptionSealed: EncryptionState<Win: kenobi_windows::client::EncryptionPolicy> {}
    #[cfg(unix)]
    pub trait EncryptionSealed: EncryptionState<Win: kenobi_unix::client::EncryptionPolicy> {}
    impl EncryptionSealed for super::NoEncryption {}
    impl EncryptionSealed for super::MaybeEncryption {}
}

pub trait SigningState {
    #[cfg(windows)]
    type Win;
    #[cfg(unix)]
    type Unix;
}

pub trait UnfinishedSigningState: sealed::SigningSealed {}

pub enum NoSigning {}
impl UnfinishedSigningState for NoSigning {}
impl SigningState for NoSigning {
    #[cfg(unix)]
    type Unix = kenobi_unix::client::CannotSign;
    #[cfg(windows)]
    type Win = kenobi_windows::client::CannotSign;
}
pub enum MaybeSigning {}
impl UnfinishedSigningState for MaybeSigning {}
impl SigningState for MaybeSigning {
    #[cfg(unix)]
    type Unix = kenobi_unix::client::MaybeSign;
    #[cfg(windows)]
    type Win = kenobi_windows::client::MaybeSign;
}
pub enum Signing {}
impl SigningState for Signing {
    #[cfg(unix)]
    type Unix = kenobi_unix::client::CanSign;
    #[cfg(windows)]
    type Win = kenobi_windows::client::CanSign;
}

pub trait EncryptionState {
    #[cfg(windows)]
    type Win;
    #[cfg(unix)]
    type Unix;
}
pub trait UnfinishedEncryptionState: sealed::EncryptionSealed {}

pub enum NoEncryption {}
impl UnfinishedEncryptionState for NoEncryption {}
impl EncryptionState for NoEncryption {
    #[cfg(unix)]
    type Unix = kenobi_unix::client::CannotEncrypt;
    #[cfg(windows)]
    type Win = kenobi_windows::client::CannotEncrypt;
}
pub enum MaybeEncryption {}
impl UnfinishedEncryptionState for MaybeEncryption {}
impl EncryptionState for MaybeEncryption {
    #[cfg(unix)]
    type Unix = kenobi_unix::client::MaybeEncrypt;
    #[cfg(windows)]
    type Win = kenobi_windows::client::MaybeEncrypt;
}
pub enum Encryption {}
impl EncryptionState for Encryption {
    #[cfg(unix)]
    type Unix = kenobi_unix::client::CanEncrypt;
    #[cfg(windows)]
    type Win = kenobi_windows::client::CanEncrypt;
}
