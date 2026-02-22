use windows::core::{PCWSTR, w};

mod buffer;
pub mod client;
pub mod context;
mod context_handle;
pub mod cred;
pub mod server;
pub mod sign;

const NEGOTIATE: PCWSTR = w!("Negotiate");

fn to_wide(s: &str) -> Box<[u16]> {
    s.chars()
        .map(|c| u16::try_from(c as u32).unwrap())
        .chain(std::iter::once(0))
        .collect::<Vec<_>>()
        .into_boxed_slice()
}
