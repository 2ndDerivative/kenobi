use std::ffi::OsString;

use kenobi::{new_server_context, ServerSettings};

fn main() {
    let spn = OsString::from("http/niclas.klugmann.com");
    let context = new_server_context(&spn, ServerSettings::default().let_sspi_allocate(), b"gibberish").unwrap();
}
