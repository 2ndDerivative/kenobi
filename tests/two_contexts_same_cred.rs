use windows_native_negotiate::{
    client::ClientBuilder,
    credentials::{Credentials, CredentialsUsage},
};

fn main() {
    let cred = Credentials::acquire_default(CredentialsUsage::Outbound, None);

    let ctx_a = ClientBuilder::new_from_credentials(&cred, Some("test/example.com")).allow_delegation();
    let ctx_b = ClientBuilder::new_from_credentials(&cred, Some("test/other.example.com"))
        .allow_delegation()
        .enforce_encryption();

    let _pending_a = ctx_a.initialize(None);
    let _pending_b = ctx_b.initialize(None);
}
