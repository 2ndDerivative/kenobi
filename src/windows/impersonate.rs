use std::{marker::PhantomData, mem::MaybeUninit};

use windows::{
    core::PSTR,
    Win32::{
        Foundation::{HANDLE, STATUS_NO_SUCH_PACKAGE},
        Security::Authentication::Identity::{
            LsaConnectUntrusted, LsaLookupAuthenticationPackage, LSA_STRING, MICROSOFT_KERBEROS_NAME_A,
        },
    },
};

use crate::{windows::FinishedContext, SecurityInfo};

impl FinishedContext {
    pub fn impersonate(&'_ self) -> Result<ImpersonationGuard<'_>, ImpersonationFailed> {
        let mut lsa_handle: MaybeUninit<HANDLE> = MaybeUninit::uninit();
        let lsa_status = unsafe { LsaConnectUntrusted(lsa_handle.as_mut_ptr()) };
        if lsa_status.is_err() {
            panic!("Failed with LSA status {}", lsa_status.0);
        }
        println!("Successfully connected to LSA");
        let lsa_handle = unsafe { lsa_handle.assume_init() };
        let mut package_id = 0;
        let package_name = kerberos_static_name().ok_or(ImpersonationFailed::KerberosNameConstantMissing)?;
        let lsa_package_status = unsafe { LsaLookupAuthenticationPackage(lsa_handle, &package_name, &mut package_id) };
        if lsa_package_status.is_err() {
            if lsa_package_status == STATUS_NO_SUCH_PACKAGE {
                return Err(ImpersonationFailed::KerberosPackageDoesntExist);
            } else {
                unreachable!("Status name too long shouldnt be able to happen, server returned {lsa_package_status:?}")
            }
        }
        let client_name = self.security_info().0.client_name().unwrap();
        println!(r#"Found authentication package "Kerberos""#);
        Ok(ImpersonationGuard {
            _marker: PhantomData,
            context: self,
        })
    }
}

fn kerberos_static_name() -> Option<LSA_STRING> {
    if MICROSOFT_KERBEROS_NAME_A.is_null() {
        return None;
    }
    let package_name_raw = unsafe { std::ffi::CStr::from_ptr(MICROSOFT_KERBEROS_NAME_A.0 as *const i8) };
    let length = package_name_raw.to_bytes().len() as u16;
    Some(LSA_STRING {
        Length: length,
        MaximumLength: length + 1,
        Buffer: PSTR(MICROSOFT_KERBEROS_NAME_A.0 as *mut u8),
    })
}

pub struct ImpersonationGuard<'ig> {
    _marker: PhantomData<*const ()>,
    context: &'ig FinishedContext,
}

#[derive(Debug)]
pub enum ImpersonationFailed {
    KerberosNameConstantMissing,
    KerberosPackageDoesntExist,
}
