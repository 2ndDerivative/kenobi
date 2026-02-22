pub struct Signature {
    #[cfg(windows)]
    pub(crate) win: kenobi_windows::sign::Signature,
    #[cfg(unix)]
    pub(crate) unix: kenobi_unix::sign_encrypt::Signed,
}
#[cfg(windows)]
impl Signature {
    pub(crate) fn from_inner(win: kenobi_windows::sign::Signature) -> Self {
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
