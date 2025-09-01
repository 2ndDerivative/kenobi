use std::ffi::OsString;

use kenobi::{new_server_context, ServerSettings, StepOk};

fn main() {
    let spn = OsString::from("http/niclas.klugmann.com");
    let context = new_server_context(&spn, ServerSettings::default().let_sspi_allocate(), b"gibberish").unwrap();
    match context {
        StepOk::Finished(mut f) => {
            let g = f.impersonate_client().unwrap();
            g.revert();
        }
        _ => todo!(),
    }
}
