#![deny(unused_must_use)]

use std::env;
use std::process::exit;

use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;
use rpassword::prompt_password;
use text_io::read;

use zkp_auth_rust::ChaumPedersen;

use crate::zkp_auth::auth_client::AuthClient;
use crate::zkp_auth::{AuthenticationAnswerRequest, AuthenticationChallengeRequest, RegisterRequest};

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

    let user = prompt("User");
    let password = BigUint::from_bytes_be(prompt_password("Password: ").unwrap().as_bytes());
    let p = BigUint::from_bytes_be(prompt("Prime").as_bytes());
    let q = BigUint::from_bytes_be(prompt("Order").as_bytes());  // TODO Can we not calculate this??
    let alpha = BigUint::from_bytes_be(prompt("Generator").as_bytes());

    let beta = alpha.modpow(&thread_rng().gen_biguint_below(&q), &p);
    let cp = ChaumPedersen { p, q, alpha, beta };
    let (y1, y2) = cp.generate_pair(&password);

    client.register(RegisterRequest {
        user: user.to_string(),
        p: cp.p.to_bytes_be(),
        q: cp.q.to_bytes_be(),
        alpha: cp.alpha.to_bytes_be(),
        beta: cp.beta.to_bytes_be(),
        y1: y1.to_bytes_be(),
        y2: y2.to_bytes_be()
    }).await.unwrap_or_else(|status| {
        eprintln!("Unable to register: {}", status);
        exit(1);
    });
    println!("Registered with server");

    let k = cp.generate_q_random();
    let (r1, r2) = cp.generate_pair(&k);

    let response = client.create_authentication_challenge(AuthenticationChallengeRequest {
        user: user.to_string(),
        r1: r1.to_bytes_be(),
        r2: r2.to_bytes_be()
    }).await.unwrap_or_else(|status| {
        eprintln!("Unable to create authentication challenge: {}", status);
        exit(1);
    }).into_inner();

    let auth_id = response.auth_id;
    let c = BigUint::from_bytes_be(&response.c);

    println!("Received authentication challenge");

    let s = cp.solve(&k, &c, &password);
    let response = client.verify_authentication(AuthenticationAnswerRequest {
        auth_id,
        s: s.to_bytes_be()
    }).await.unwrap_or_else(|status| {
        eprintln!("Authentication failed: {}", status);
        exit(1);
    }).into_inner();

    println!("Successfully authenticated!");
    println!("session_id={}", &response.session_id);
}

fn prompt(prompt: &str) -> String {
    print!("{}: ", prompt);
    read!()
}
