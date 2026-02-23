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
    #[cfg(unix)]
    pub(crate) inner: kenobi_unix::Error,
}
impl WrapError {
    #[cfg(windows)]
    pub(crate) fn from_inner(inner: kenobi_windows::sign_encrypt::WrapError) -> Self {
        Self { inner }
    }
    #[cfg(unix)]
    pub(crate) fn from_inner(inner: kenobi_unix::Error) -> Self {
        Self { inner }
    }
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

#[derive(Debug)]
pub struct UnwrapError {
    #[cfg(windows)]
    pub(crate) inner: kenobi_windows::sign_encrypt::Altered,
    #[cfg(unix)]
    pub(crate) inner: kenobi_unix::Error,
}
impl UnwrapError {
    #[cfg(windows)]
    pub(crate) fn from_inner(inner: kenobi_windows::sign_encrypt::Altered) -> Self {
        Self { inner }
    }
    #[cfg(unix)]
    pub(crate) fn from_inner(inner: kenobi_unix::Error) -> Self {
        Self { inner }
    }
}
impl std::error::Error for UnwrapError {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        Some(&self.inner)
    }
}
impl Display for UnwrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}
