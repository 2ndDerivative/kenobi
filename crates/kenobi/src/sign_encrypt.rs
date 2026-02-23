use std::fmt::Display;

pub struct Signature {
    #[cfg(windows)]
    pub(crate) win: kenobi_windows::sign_encrypt::Signature,
    #[cfg(unix)]
    pub(crate) unix: kenobi_unix::sign_encrypt::Signed,
}
#[cfg(windows)]
impl Signature {
    pub(crate) fn from_inner(win: kenobi_windows::sign_encrypt::Signature) -> Self {
        Self { win }
    }
}
#[cfg(unix)]
impl Signature {
    pub(crate) fn from_inner(unix: kenobi_unix::sign_encrypt::Signed) -> Self {
        Self { unix }
    }
}
impl Signature {
    #[cfg(windows)]
    pub fn as_slice(&self) -> &[u8] {
        &self.win
    }
    #[cfg(unix)]
    pub fn as_slice(&self) -> &[u8] {
        self.unix.as_slice()
    }
}

#[derive(Debug)]
pub struct WrapError {
    #[cfg(windows)]
    pub(crate) inner: kenobi_windows::sign_encrypt::WrapError,
}
impl std::error::Error for WrapError {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        Some(&self.inner)
    }
}
impl Display for WrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

#[cfg(windows)]
impl From<kenobi_windows::sign_encrypt::WrapError> for WrapError {
    fn from(inner: kenobi_windows::sign_encrypt::WrapError) -> Self {
        WrapError { inner }
    }
}
