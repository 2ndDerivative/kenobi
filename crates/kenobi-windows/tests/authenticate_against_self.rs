use std::sync::{
    Arc,
    mpsc::{Receiver, Sender, channel},
};

use kenobi_windows::{
    client::{ClientBuilder, StepOut as ClientStepOut},
    cred::Credentials,
    server::{ServerBuilder, ServerContext, StepOut as ServerStepOut},
};

#[derive(Debug)]
enum Message {
    Token(Vec<u8>),
    Data(Vec<u8>),
    Signature(Vec<u8>),
}

const MESSAGE: &[u8] = b"Hi, Server!";
#[test]
fn main() {
    let server_principal: Arc<str> = std::env::var("SERVER_PRINCIPAL").unwrap().into();
    let client_principal: Arc<str> = std::env::var("CLIENT_PRINCIPAL").unwrap().into();
    let (send, recv) = channel::<Message>();
    let (return_send, return_recv) = channel::<Vec<u8>>();

    let srv = server_principal.clone();
    let join_handle = std::thread::spawn(|| {
        let p = srv;
        server(recv, return_send, &p)
    });

    let creds = Credentials::outbound(Some(&client_principal)).unwrap();
    let ClientStepOut::Pending(mut client) = ClientBuilder::new_from_credentials(creds, Some(&server_principal))
        .request_signing()
        .initialize()
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
    if let Some(token) = finished_ctx.last_token() {
        send.send(Message::Token(token.to_vec())).unwrap();
    }

    let Ok(finished_ctx) = finished_ctx.check_signing() else {
        panic!("Signing not possible")
    };

    eprintln!("[CLIENT] Encrypting message");
    let signed = finished_ctx.sign_message(MESSAGE);
    send.send(Message::Data(MESSAGE.to_vec())).unwrap();
    send.send(Message::Signature(signed.to_vec())).unwrap();

    join_handle.join().unwrap();
}

fn server(recv: Receiver<Message>, return_sender: Sender<Vec<u8>>, _principal: &str) {
    let server_cred = Credentials::inbound(Some(_principal)).unwrap();
    eprintln!("[SERVER] Waiting for token");
    let mut token = match recv.recv().unwrap() {
        Message::Token(outgoing_payload) => outgoing_payload,
        Message::Data(_) | Message::Signature(_) => todo!("not authenticated yet"),
    };
    eprintln!("[Server] Received initial token, setting up");
    let my_server_ctx: ServerContext<_, _> = 'ctx: {
        let mut pending = match ServerBuilder::new_from_credentials(server_cred)
            .offer_signing()
            .initialize(&token)
            .unwrap()
        {
            ServerStepOut::Pending(p) => p,
            ServerStepOut::Completed(f) => break 'ctx f,
        };
        return_sender.send(pending.next_token().to_vec()).unwrap();
        eprintln!("[SERVER] created security context");
        loop {
            token = match recv.recv().unwrap() {
                Message::Token(outgoing_payload) => outgoing_payload,
                Message::Data(_) | Message::Signature(_) => todo!("not authenticated yet"),
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
    let Ok(my_server_ctx) = my_server_ctx.check_signing() else {
        panic!("Didn't negotiate signing");
    };

    let please_data = recv.recv().unwrap();
    let please_signature = recv.recv().unwrap();
    let (Message::Data(data), Message::Signature(_sig)) = (please_data, please_signature) else {
        panic!("Invalid data sent after successful auth")
    };
    assert!(my_server_ctx.verify_message(&_sig).is_ok());
    assert_eq!(data, MESSAGE);
}
