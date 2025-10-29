use std::{
    ffi::{c_void, OsString},
    mem::MaybeUninit,
    os::windows::ffi::OsStringExt,
};

use windows::{
    core::PCWSTR,
    Win32::{
        Globalization::lstrlenW,
        Security::Authentication::Identity::{
            QueryContextAttributesExW, SecPkgContext_AccessToken, SecPkgContext_ClientSpecifiedTarget,
            SecPkgContext_NamesW, SecPkgContext_NativeNamesW, SECPKG_ATTR, SECPKG_ATTR_ACCESS_TOKEN,
            SECPKG_ATTR_CLIENT_SPECIFIED_TARGET, SECPKG_ATTR_NAMES, SECPKG_ATTR_NATIVE_NAMES,
        },
    },
};

use super::{access_token::AccessToken, step::ContextHandle};

pub fn client_target(sec_handle: &ContextHandle) -> Result<OsString, String> {
    let target = get_attribute::<SecPkgContext_ClientSpecifiedTarget>(sec_handle)?;
    Ok(unsafe { string_from_wstr(target.sTargetName) })
}

pub fn client_name(sec_handle: &ContextHandle) -> Result<OsString, String> {
    let target = get_attribute::<SecPkgContext_NamesW>(sec_handle)?;
    Ok(unsafe { string_from_wstr(target.sUserName) })
}

pub fn client_native_name(sec_handle: &ContextHandle) -> Result<OsString, String> {
    let target = get_attribute::<SecPkgContext_NativeNamesW>(sec_handle)?;
    Ok(unsafe { string_from_wstr(target.sClientName) })
}
pub fn server_native_name(sec_handle: &ContextHandle) -> Result<OsString, String> {
    let target = get_attribute::<SecPkgContext_NativeNamesW>(sec_handle)?;
    Ok(unsafe { string_from_wstr(target.sServerName) })
}
pub fn access_token(sec_handle: &ContextHandle) -> Result<AccessToken, String> {
    let target = get_attribute::<SecPkgContext_AccessToken>(sec_handle)?;
    Ok(AccessToken::new(target))
}

fn get_attribute<T: SecPkgAttribute>(sec_handle: &ContextHandle) -> Result<T, String> {
    let mut target: MaybeUninit<T> = MaybeUninit::uninit();
    // # Safety
    //
    // Memory being valid for the specific type is enforced in the SecPkgAttribute trait
    #[cfg(feature = "tracing")]
    tracing::debug!(package = T::SEC_PKG_ATTRIBUTE, "Extracting security package attribute");
    unsafe {
        QueryContextAttributesExW(
            sec_handle.as_ref(),
            T::SEC_PKG_ATTRIBUTE,
            target.as_mut_ptr() as *mut c_void,
            size_of::<MaybeUninit<T>>() as u32,
        )
        .map_err(|e| e.message())?;
        #[cfg(feature = "tracing")]
        tracing::debug!("Security package extraction returned OK");
        Ok(target.assume_init())
    }
}

/// # Safety
///
/// Constant has to match datatype's returned attribute, or the windows API will initialize bad memory
unsafe trait SecPkgAttribute {
    const SEC_PKG_ATTRIBUTE: SECPKG_ATTR;
}
unsafe impl SecPkgAttribute for SecPkgContext_NamesW {
    const SEC_PKG_ATTRIBUTE: SECPKG_ATTR = SECPKG_ATTR_NAMES;
}
unsafe impl SecPkgAttribute for SecPkgContext_NativeNamesW {
    const SEC_PKG_ATTRIBUTE: SECPKG_ATTR = SECPKG_ATTR_NATIVE_NAMES;
}
unsafe impl SecPkgAttribute for SecPkgContext_ClientSpecifiedTarget {
    const SEC_PKG_ATTRIBUTE: SECPKG_ATTR = SECPKG_ATTR_CLIENT_SPECIFIED_TARGET;
}
unsafe impl SecPkgAttribute for SecPkgContext_AccessToken {
    const SEC_PKG_ATTRIBUTE: SECPKG_ATTR = SECPKG_ATTR_ACCESS_TOKEN;
}

/// # Safety
///
/// Target pointer has to be start of a valid zero-terminated UTF16 string
unsafe fn string_from_wstr(s: *mut u16) -> OsString {
    let slen = lstrlenW(PCWSTR(s));
    let slice = std::slice::from_raw_parts(s, slen as usize);
    OsString::from_wide(slice)
}
