use std::{
    ffi::{c_void, OsString},
    mem::MaybeUninit,
    os::windows::ffi::OsStringExt,
};

use windows::{
    core::PWSTR,
    Win32::{
        Foundation::{LocalFree, HANDLE, HLOCAL},
        Globalization::lstrlenW,
        Security::{
            Authentication::Identity::SecPkgContext_AccessToken,
            Authorization::ConvertSidToStringSidW, GetTokenInformation, TokenUser, TOKEN_USER,
        },
    },
};

pub struct AccessToken(SecPkgContext_AccessToken);
impl AccessToken {
    pub(crate) fn new(access_token: SecPkgContext_AccessToken) -> Self {
        Self(access_token)
    }
    pub fn get_sid(&self) -> Result<OsString, String> {
        let handle: HANDLE = HANDLE(self.0.AccessToken);
        let mut token_information = MaybeUninit::uninit();
        let p = &mut token_information as *mut MaybeUninit<TOKEN_USER>;
        let mut out_len = 0;
        let user: TOKEN_USER = unsafe {
            GetTokenInformation(
                handle,
                TokenUser,
                Some(p as *mut c_void),
                size_of::<TOKEN_USER>() as u32,
                &mut out_len,
            )
            .unwrap();
            token_information.assume_init()
        };
        let sid = user.User.Sid;
        let mut out: MaybeUninit<PWSTR> = MaybeUninit::uninit();
        let os_str = unsafe {
            ConvertSidToStringSidW(sid, out.as_mut_ptr()).unwrap();
            let init_pwstr = out.assume_init();
            let len = lstrlenW(init_pwstr);
            let str = OsString::from_wide(std::slice::from_raw_parts(init_pwstr.0, len as usize));
            LocalFree(Some(HLOCAL(init_pwstr.0 as *mut c_void)));
            str
        };
        Ok(os_str)
    }
}
