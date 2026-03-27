use std::{fmt::Display, num::NonZero};

use libgssapi_sys::{
    _GSS_S_BAD_BINDINGS, _GSS_S_BAD_NAME, _GSS_S_BAD_NAMETYPE, _GSS_S_BAD_SIG, _GSS_S_CONTEXT_EXPIRED,
    _GSS_S_CREDENTIALS_EXPIRED, _GSS_S_DEFECTIVE_CREDENTIAL, _GSS_S_DEFECTIVE_TOKEN, _GSS_S_FAILURE, _GSS_S_NO_CONTEXT,
    _GSS_S_NO_CRED, GSS_C_GSS_CODE, GSS_C_MECH_CODE, GSS_S_DUPLICATE_TOKEN, GSS_S_OLD_TOKEN, gss_buffer_desc_struct,
    gss_display_status, gss_release_buffer,
};

#[derive(Clone, Copy, Debug)]
pub struct MechanismErrorCode(NonZero<u32>);
impl MechanismErrorCode {
    pub fn new(val: u32) -> Option<Self> {
        NonZero::new(val).map(Self)
    }
}
impl Display for MechanismErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_from_u32(self.0.into(), GSS_C_MECH_CODE as i32, f)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct GssErrorCode(NonZero<u32>);
impl GssErrorCode {
    pub fn new(val: u32) -> Option<Self> {
        NonZero::new(val).map(Self)
    }
    pub fn kind_initialize(self) -> Option<GssInitErrorKind> {
        use GssInitErrorKind as Kind;
        match u32::from(self.0) {
            0 => unreachable!(),
            _GSS_S_BAD_BINDINGS => Some(Kind::BadBindings),
            _GSS_S_BAD_NAME => Some(Kind::BadName),
            _GSS_S_BAD_NAMETYPE => Some(Kind::BadNameType),
            _GSS_S_BAD_SIG => Some(Kind::BadSignature),
            _GSS_S_FAILURE => Some(Kind::Failure),
            _GSS_S_NO_CRED => Some(Kind::NoCredentials),
            _GSS_S_NO_CONTEXT => Some(Kind::NoContext),
            _GSS_S_DEFECTIVE_TOKEN => Some(Kind::DefectiveToken),
            _GSS_S_DEFECTIVE_CREDENTIAL => Some(Kind::DefectiveCredentials),
            _GSS_S_CREDENTIALS_EXPIRED => Some(Kind::CredentialsExpired),
            _GSS_S_CONTEXT_EXPIRED => Some(Kind::ContextExpired),
            _ => None,
        }
    }
    pub fn kind_accept(self) -> Option<GssAccErrorKind> {
        use GssAccErrorKind as Kind;
        match u32::from(self.0) {
            0 => unreachable!(),
            _GSS_S_BAD_BINDINGS => Some(Kind::BadBindings),
            _GSS_S_BAD_SIG => Some(Kind::BadSignature),
            GSS_S_DUPLICATE_TOKEN => Some(Kind::DuplicateToken),
            GSS_S_OLD_TOKEN => Some(Kind::OldToken),
            _GSS_S_FAILURE => Some(Kind::Failure),
            _GSS_S_NO_CRED => Some(Kind::NoCredentials),
            _GSS_S_NO_CONTEXT => Some(Kind::NoContext),
            _GSS_S_DEFECTIVE_TOKEN => Some(Kind::DefectiveToken),
            _GSS_S_DEFECTIVE_CREDENTIAL => Some(Kind::DefectiveCredentials),
            _GSS_S_CREDENTIALS_EXPIRED => Some(Kind::CredentialsExpired),
            _ => None,
        }
    }
}
impl Display for GssErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_from_u32(self.0.into(), GSS_C_GSS_CODE as i32, f)
    }
}

fn write_from_u32(val: u32, mechanism: i32, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let mut minor_status = 0;
    let mut more = 0;
    let mut string = gss_buffer_desc_struct {
        length: 0,
        value: std::ptr::null_mut(),
    };
    unsafe {
        gss_display_status(
            &mut minor_status,
            val,
            mechanism,
            std::ptr::null_mut(),
            &mut more,
            &mut string,
        )
    };
    if !string.value.is_null() {
        let bytes = unsafe { std::slice::from_raw_parts(string.value as *const u8, string.length) };
        let string = std::str::from_utf8(bytes).unwrap();
        write!(f, "{string}")?;
    } else {
        write!(f, "")?;
    }
    let mut _s = 0;
    unsafe { gss_release_buffer(&mut _s, &mut string) };
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub enum Error {
    Gss(GssErrorCode),
    Mechanism(MechanismErrorCode),
}
impl Error {
    pub(crate) fn gss(val: u32) -> Option<Self> {
        GssErrorCode::new(val).map(Error::Gss)
    }
    pub(crate) fn mechanism(val: u32) -> Option<Self> {
        MechanismErrorCode::new(val).map(Error::Mechanism)
    }
}
impl std::error::Error for Error {}
impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gss(gss) => gss.fmt(f),
            Self::Mechanism(mech) => mech.fmt(f),
        }
    }
}
impl From<GssErrorCode> for Error {
    fn from(value: GssErrorCode) -> Self {
        Self::Gss(value)
    }
}
impl From<MechanismErrorCode> for Error {
    fn from(value: MechanismErrorCode) -> Self {
        Self::Mechanism(value)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum GssInitErrorKind {
    BadBindings,
    BadName,
    BadNameType,
    BadSignature,
    ContextExpired,
    CredentialsExpired,
    DefectiveCredentials,
    DefectiveToken,
    Failure,
    NoCredentials,
    NoContext,
}

#[derive(Clone, Copy, Debug)]
pub enum GssAccErrorKind {
    BadBindings,
    BadSignature,
    CredentialsExpired,
    DefectiveToken,
    DefectiveCredentials,
    DuplicateToken,
    Failure,
    NoCredentials,
    NoContext,
    OldToken,
}
