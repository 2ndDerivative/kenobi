use std::{
    ffi::c_void,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    ptr::NonNull,
};

use libgssapi_sys::{
    gss_OID, gss_OID_desc_struct, gss_buffer_desc_struct, gss_buffer_t, gss_display_name, gss_name_struct,
    gss_release_buffer, gss_release_name,
};

use crate::{
    Error,
    error::{ErrorKind, GssErrorCode, MechanismErrorCode},
};

pub struct NameHandle {
    name: NonNull<gss_name_struct>,
}
unsafe impl Send for NameHandle {}
unsafe impl Sync for NameHandle {}
impl NameHandle {
    pub unsafe fn import(principal: &str, oid: *mut gss_OID_desc_struct) -> Result<Self, Error> {
        let name = unsafe { import_name(principal, oid)? };
        Ok(NameHandle { name })
    }
    pub(crate) unsafe fn from_raw(name: NonNull<gss_name_struct>) -> Self {
        Self { name }
    }
    pub fn as_mut(&mut self) -> *mut gss_name_struct {
        self.name.as_ptr()
    }
}
impl Drop for NameHandle {
    fn drop(&mut self) {
        let mut s = 0;
        unsafe { gss_release_name(&raw mut s, &mut NonNull::as_ptr(self.name)) };
    }
}
impl Debug for NameHandle {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "NameHandle")
    }
}
impl Display for NameHandle {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let mut minor = 0;
        let mut buffer = gss_buffer_desc_struct {
            length: 0,
            value: std::ptr::null_mut(),
        };
        let major = unsafe {
            gss_display_name(
                &raw mut minor,
                NonNull::as_ptr(self.name),
                &raw mut buffer,
                std::ptr::null_mut(),
            )
        };
        if let Some(_gss_err) = ErrorKind::gss(major) {
            return Ok(());
        }
        if let Some(_mech_err) = ErrorKind::mechanism(minor) {
            return Ok(());
        }
        let sl = unsafe { std::slice::from_raw_parts(buffer.value.cast(), buffer.length) };
        let Ok(str) = std::str::from_utf8(sl) else {
            return Ok(());
        };
        write!(f, "{str}")?;
        let mut min = 0;
        let _maj = unsafe { gss_release_buffer(&raw mut min, &raw mut buffer) };
        Ok(())
    }
}

unsafe fn import_name(principal: &str, oid: gss_OID) -> Result<NonNull<gss_name_struct>, Error> {
    let mut minor = 0;
    let mut namebuffer = gss_buffer_desc_struct {
        length: principal.len(),
        value: principal.as_ptr() as *mut c_void,
    };
    let mut name = std::ptr::null_mut::<gss_name_struct>();
    if let Some(error) = GssErrorCode::new(unsafe {
        libgssapi_sys::gss_import_name(&raw mut minor, &mut namebuffer as gss_buffer_t, oid, &raw mut name)
    }) {
        return Err(Error::new(error.into()));
    }
    if let Some(err) = MechanismErrorCode::new(minor) {
        return Err(Error::new(err.into()));
    }
    Ok(NonNull::new(name).unwrap())
}
