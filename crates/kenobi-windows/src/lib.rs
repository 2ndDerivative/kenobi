use windows::core::{PCWSTR, w};

mod buffer;
pub mod client;
pub mod context;
pub mod cred;
pub mod server;
pub mod sign_encrypt;

const NEGOTIATE: PCWSTR = w!("Negotiate");

fn to_wide(s: &str) -> Box<[u16]> {
    s.chars()
        .map(|c| u16::try_from(c as u32).expect("char out of UTF16 range"))
        .chain(std::iter::once(0))
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

pub mod typestate {
    pub use kenobi_core::typestate::{Encryption, MaybeEncryption, MaybeSigning, NoEncryption, NoSigning, Signing};
}
