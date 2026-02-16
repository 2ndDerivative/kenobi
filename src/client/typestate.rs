pub trait SigningState {
    #[cfg(windows)]
    type Win;
    #[cfg(unix)]
    type Unix;
}

pub enum NoSigning {}
impl SigningState for NoSigning {
    #[cfg(unix)]
    type Unix = kenobi_unix::client::CannotSign;
    #[cfg(windows)]
    type Win = kenobi_windows::client::CannotSign;
}
pub enum MaybeSigning {}
impl SigningState for MaybeSigning {
    #[cfg(unix)]
    type Unix = kenobi_unix::client::MaybeSign;
    #[cfg(windows)]
    type Win = kenobi_windows::client::MaybeSign;
}

pub trait EncryptionState {
    #[cfg(windows)]
    type Win;
    #[cfg(unix)]
    type Unix;
}

pub enum NoEncryption {}
impl EncryptionState for NoEncryption {
    #[cfg(unix)]
    type Unix = kenobi_unix::client::CannotEncrypt;
    #[cfg(windows)]
    type Win = kenobi_windows::client::CannotEncrypt;
}
pub enum MaybeEncryption {}
impl EncryptionState for MaybeEncryption {
    #[cfg(unix)]
    type Unix = kenobi_unix::client::MaybeEncrypt;
    #[cfg(windows)]
    type Win = kenobi_windows::client::MaybeEncrypt;
}
