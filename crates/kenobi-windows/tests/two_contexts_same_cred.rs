use std::sync::Arc;

use kenobi_windows::{client::ClientBuilder, cred::Credentials};

fn main() {
    let cred = Arc::new(Credentials::outbound(None).unwrap());

    let ctx_a = ClientBuilder::new_from_credentials(cred.clone(), Some("test/example.com")).allow_delegation();
    let ctx_b = ClientBuilder::new_from_credentials(cred, Some("test/other.example.com"))
        .allow_delegation()
        .request_encryption();

    let _pending_a = ctx_a.initialize();
    let _pending_b = ctx_b.initialize();
}
