use kenobi_unix::{
    client::{ClientContext, StepOut},
    cred::Credentials,
};

#[test]
fn main() {
    let client_name = std::env::var("KERBEROS_TEST_USER_PRINCIPAL").ok();
    let service_principal = std::env::var("KERBEROS_TEST_SERVICE_PRINCIPAL").unwrap();
    let cred = match Credentials::outbound(client_name.as_deref(), None) {
        Ok(cred) => cred,
        Err(err) => {
            eprintln!("Error: {err}");
            panic!()
        }
    };
    let mut _ctx = match ClientContext::new(cred, Some(service_principal.as_str())) {
        Ok(StepOut::Finished(_)) => return,
        Ok(StepOut::Pending(pending)) => pending,
        Err(err) => {
            eprintln!("Error initiating: {err}");
            panic!()
        }
    };
    todo!();
}
