pub mod client;
mod context;
pub mod cred;
mod error;

use std::ffi::c_void;

pub use error::Error;
use libgssapi_sys::gss_OID_desc;
mod name;
pub mod sign_encrypt;

static MECH_KERBEROS: &[u8] = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02";
static MECH_SPNEGO: &[u8] = b"\x2b\x06\x01\x05\x05\x02";

fn oid(mech: &'static [u8]) -> gss_OID_desc {
    gss_OID_desc {
        length: mech.len() as u32,
        elements: mech.as_ptr() as *mut c_void,
    }
}
fn mech_kerberos() -> gss_OID_desc {
    oid(MECH_KERBEROS)
}
#[expect(unused)]
fn mech_spnego() -> gss_OID_desc {
    oid(MECH_SPNEGO)
}

pub mod typestate {
    pub use kenobi_core::typestate::{
        DeniedSigning, Encryption, MaybeEncryption, MaybeSigning, NoEncryption, NoSigning, Signing,
    };
}
