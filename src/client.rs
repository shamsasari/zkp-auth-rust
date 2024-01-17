#![deny(unused_must_use)]

use std::env;
use std::process::exit;

use num_bigint::BigUint;
use rpassword::prompt_password;
use text_io::read;

use zkp_auth_rust::ChaumPedersen;

use crate::proto::BigUintExt;
use crate::proto::Vecu8Ext;
use crate::zkp_auth::{AuthenticationAnswerRequest, AuthenticationChallengeRequest, ParamsRequest, RegisterRequest};
use crate::zkp_auth::auth_client::AuthClient;

mod proto;

pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

#[tokio::main]
async fn main() {
    let address = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Please specify auth server address");
        exit(1);
    });
    let mut client = AuthClient::connect(address).await.unwrap_or_else(|_| {
        eprintln!("Unable to connect to auth server");
        exit(1);
    });

    println!("Connected to auth server");

    let response = client.get_params(ParamsRequest::default()).await.unwrap_or_else(|status| {
        eprintln!("Unable to get ZKP parameters: {}", status);
        exit(1);
    }).into_inner();

    let user = prompt("User");
    let password = BigUint::from_bytes_be(prompt_password("Password: ").unwrap().as_bytes());

    let cp = ChaumPedersen {
        p: response.p.deserialise_big_uint(),
        q: response.q.deserialise_big_uint(),
        g: response.g.deserialise_big_uint(),
        h: response.h.deserialise_big_uint()
    };

    let (y1, y2) = cp.generate_pair(&password);

    client.register(RegisterRequest {
        user: user.to_string(),
        y1: y1.serialise(),
        y2: y2.serialise()
    }).await.unwrap_or_else(|status| {
        eprintln!("Unable to register: {}", status);
        exit(1);
    });
    println!("Registered with server");

    let password = BigUint::from_bytes_be(prompt_password("Password: ").unwrap().as_bytes());

    let k = cp.generate_q_random();
    let (r1, r2) = cp.generate_pair(&k);

    let response = client.create_authentication_challenge(AuthenticationChallengeRequest {
        user: user.to_string(),
        r1: r1.serialise(),
        r2: r2.serialise()
    }).await.unwrap_or_else(|status| {
        eprintln!("Unable to create authentication challenge: {}", status);
        exit(1);
    }).into_inner();

    let auth_id = response.auth_id;
    let c = response.c.deserialise_big_uint();

    println!("Received authentication challenge");

    let s = cp.solve(&k, &c, &password);
    let response = client.verify_authentication(AuthenticationAnswerRequest {
        auth_id,
        s: s.serialise()
    }).await.unwrap_or_else(|status| {
        eprintln!("Authentication failed: {}", status.message());
        exit(1);
    }).into_inner();

    println!("Successfully authenticated!");
    println!("session_id={}", &response.session_id);
}

fn prompt(prompt: &str) -> String {
    print!("{}: ", prompt);
    read!()
}
