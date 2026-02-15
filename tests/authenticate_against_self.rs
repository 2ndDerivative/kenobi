use std::sync::{
    Arc,
    mpsc::{Receiver, Sender, channel},
};

use windows_native_negotiate::{
    client::{ClientBuilder, StepOut as ClientStepOut},
    credentials::{Credentials, CredentialsUsage},
    server::{ServerContext, StepOut as ServerStepOut},
};

enum Message {
    Token(Vec<u8>),
    Data(Vec<u8>),
}

const MESSAGE: &[u8] = b"Hi, Server!";
#[test]
fn main() {
    let principal: Arc<str> = std::env::var("TARGET_PRINCIPAL").unwrap().into();
    let (send, recv) = channel::<Message>();
    let (return_send, return_recv) = channel::<Vec<u8>>();

    let server_principal = principal.clone();
    let join_handle = std::thread::spawn(|| {
        let p = server_principal;
        server(recv, return_send, &p)
    });

    let creds = Credentials::acquire_default(CredentialsUsage::Outbound, None);
    let ClientStepOut::Pending(mut client) = ClientBuilder::new_from_credentials(&creds, Some(&principal))
        .initialize(None)
        .unwrap()
    else {
        todo!()
    };
    let mut token = client.next_token().to_vec();
    let finished_ctx = loop {
        eprintln!("[CLIENT] Setting up response channel");
        eprintln!("[CLIENT] Sending Negotiate token");
        send.send(Message::Token(token.clone())).unwrap();

        let answer = return_recv.recv().unwrap();
        eprintln!("[CLIENT] Negotiate answer message received");
        client = match client.step(&answer).unwrap() {
            ClientStepOut::Completed(c) => {
                eprintln!("[CLIENT] Context completed");
                break c;
            }
            ClientStepOut::Pending(p) => {
                eprintln!("[CLIENT] Context incomplete");
                p
            }
        };
        token = client.next_token().to_vec();
    };
    assert!(finished_ctx.is_mutually_authenticated());

    send.send(Message::Data(MESSAGE.to_vec())).unwrap();

    join_handle.join().unwrap();
}

fn server(recv: Receiver<Message>, return_sender: Sender<Vec<u8>>, _principal: &str) {
    let server_cred = Credentials::acquire_default(CredentialsUsage::Inbound, None);

    let mut token = match recv.recv().unwrap() {
        Message::Token(outgoing_payload) => outgoing_payload,
        Message::Data(_) => todo!("not authenticated yet"),
    };
    let my_server_ctx: ServerContext<_> = 'ctx: {
        let mut pending = match ServerContext::initialize(&server_cred, &token).unwrap() {
            ServerStepOut::Pending(p) => p,
            ServerStepOut::Completed(f) => break 'ctx f,
        };
        loop {
            token = match recv.recv().unwrap() {
                Message::Token(outgoing_payload) => outgoing_payload,
                Message::Data(_) => todo!("not authenticated yet"),
            };
            eprintln!("[SERVER] Negotiate token received");

            pending = match pending.step(&token).unwrap() {
                ServerStepOut::Pending(p) => p,
                ServerStepOut::Completed(c) => break c,
            };
            return_sender.send(pending.next_token().to_vec()).unwrap();
        }
    };
    eprintln!("[SERVER] context completed");

    if let Some(token) = my_server_ctx.last_token() {
        return_sender.send(token.to_vec()).unwrap();
        eprintln!("[SERVER] Mutual auth token sent");
    }

    let Message::Data(data) = recv.recv().unwrap() else {
        panic!()
    };
    assert_eq!(data, MESSAGE);
}
