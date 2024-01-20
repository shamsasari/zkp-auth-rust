#![deny(unused_must_use)]

use std::env;
use std::process::exit;
use std::str::FromStr;

use num_bigint::BigUint;
use rpassword::prompt_password;
use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter, EnumString};
use text_io::read;
use tonic::transport::Channel;

use zkp_auth_rust::ChaumPedersen;

use crate::proto::BigUintExt;
use crate::proto::Vecu8Ext;
use crate::zkp_auth::{AuthenticationAnswerRequest, AuthenticationChallengeRequest, ParamsRequest, RegisterRequest};
use crate::zkp_auth::auth_client::AuthClient;

mod proto;

pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

#[derive(EnumString, EnumIter, Display)]
#[strum(serialize_all = "mixed_case")]
enum Mode {
    Register,
    Authenticate
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    let modes: Vec<String> = Mode::iter().map(|m| m.to_string()).collect();
    let help_message = format!("client <address> {}", modes.join("|"));

    let address = args.get(1).unwrap_or_else(|| {
        eprintln!("Missing server address: {}", &help_message);
        exit(1);
    });

    let mode = args.get(2).unwrap_or_else(|| {
        eprintln!("Missing mode: {}", &help_message);
        exit(1);
    });

    let mode = Mode::from_str(mode).unwrap_or_else(|_| {
        eprintln!("Invalid mode: {}", &help_message);
        exit(1);
    });

    let mut client = AuthClient::connect(address.clone()).await.unwrap_or_else(|_| {
        eprintln!("Unable to connect to server");
        exit(1);
    });

    let response = client.get_params(ParamsRequest::default()).await.unwrap_or_else(|status| {
        eprintln!("Unable to get ZKP parameters: {}", status);
        exit(1);
    }).into_inner();

    print!("User name: ");
    let user_name = read!();
    let password = BigUint::from_bytes_be(prompt_password("Password: ").unwrap().as_bytes());

    let cp = ChaumPedersen {
        p: response.p.deserialise_big_uint(),
        q: response.q.deserialise_big_uint(),
        g: response.g.deserialise_big_uint(),
        h: response.h.deserialise_big_uint()
    };

    match mode {
        Mode::Register => register(&cp, &user_name, &password, &mut client).await,
        Mode::Authenticate => authenticate(&cp, &user_name, &password, &mut client).await
    }
}

async fn register(cp: &ChaumPedersen, user_name: &String, password: &BigUint, client: &mut AuthClient<Channel>) {
    let (y1, y2) = cp.generate_pair(&password);

    client.register(RegisterRequest {
        user_name: user_name.clone(),
        y1: y1.serialise(),
        y2: y2.serialise()
    }).await.unwrap_or_else(|status| {
        eprintln!("Unable to register: {}", status.message());
        exit(1);
    });

    println!("Registered with server");
}

async fn authenticate(cp: &ChaumPedersen, user_name: &String, password: &BigUint, client: &mut AuthClient<Channel>) {
    let k = cp.generate_q_random();
    let (r1, r2) = cp.generate_pair(&k);

    let response = client.create_authentication_challenge(AuthenticationChallengeRequest {
        user_name: user_name.to_string(),
        r1: r1.serialise(),
        r2: r2.serialise()
    }).await.unwrap_or_else(|status| {
        eprintln!("Unable to create authentication challenge: {}", status.message());
        exit(1);
    }).into_inner();

    let correlation_id = response.correlation_id;
    let c = response.c.deserialise_big_uint();

    let s = cp.solve_challenge(&k, &c, &password);
    let response = client.verify_authentication(AuthenticationAnswerRequest {
        correlation_id,
        s: s.serialise()
    }).await.unwrap_or_else(|status| {
        eprintln!("Authentication failed: {}", status.message());
        exit(1);
    }).into_inner();

    println!("Successfully authenticated! session_id={}", &response.session_id);
}
