#![deny(unused_must_use)]

use std::{env, fs};
use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::process::exit;
use std::sync::Mutex;

use num::Num;
use num_bigint::{BigUint, ParseBigIntError};
use toml::Table;
use tonic::{Code, Request, Response, Status};
use tonic::transport::Server;
use uuid::Uuid;

use zkp_auth_rust::ChaumPedersen;

use crate::proto::BigUintExt;
use crate::proto::Vecu8Ext;
use crate::zkp_auth::{AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest, AuthenticationChallengeResponse, ParamsRequest, ParamsResponse, RegisterRequest, RegisterResponse};
use crate::zkp_auth::auth_server::{Auth, AuthServer};

mod proto;

pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

#[derive(Debug, Default)]
struct UserInfo {
    user_name: String,
    y1: BigUint,
    y2: BigUint,
    r1: BigUint,
    r2: BigUint,
    c: BigUint,
    session_id: String
}

impl UserInfo {
    fn verify<'a>(&'a self, cp: &'a ChaumPedersen, s: &BigUint) -> Result<(), &str> {
        cp.verify(&self.r1, &self.r2, &self.y1, &self.y2, &self.c, s)
    }
}

#[derive(Debug)]
struct AuthImpl {
    cp: ChaumPedersen,
    user_infos: Mutex<HashMap<String, UserInfo>>,
    auth_ids: Mutex<HashMap<String, String>>
}

#[tonic::async_trait]
impl Auth for AuthImpl {
    async fn get_params(&self, _: Request<ParamsRequest>) -> Result<Response<ParamsResponse>, Status> {
        println!("Processing get_params request");

        Ok(Response::new(ParamsResponse {
            p: self.cp.p.serialise(),
            q: self.cp.q.serialise(),
            g: self.cp.g.serialise(),
            h: self.cp.h.serialise(),
        }))
    }

    async fn register(&self, request: Request<RegisterRequest>) -> Result<Response<RegisterResponse>, Status> {
        println!("Processing register request: {:?}", request);
        let request = request.into_inner();

        let mut user_info = UserInfo::default();
        user_info.user_name = request.user;
        user_info.y1 = request.y1.deserialise_big_uint();
        user_info.y2 = request.y2.deserialise_big_uint();

        let mut user_infos = self.user_infos.lock().unwrap();
        user_infos.insert(user_info.user_name.clone(), user_info);

        Ok(Response::new(RegisterResponse { }))
    }

    async fn create_authentication_challenge(&self, request: Request<AuthenticationChallengeRequest>) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        println!("Processing authentication challenge request: {:?}", request);
        let request = request.into_inner();

        let mut user_infos = self.user_infos.lock().unwrap();
        let user_info = user_infos
            .get_mut(&request.user)
            .ok_or_else(|| Status::new(Code::NotFound, format!("User {} not found", &request.user)))?;

        user_info.r1 = request.r1.deserialise_big_uint();
        user_info.r2 = request.r2.deserialise_big_uint();
        user_info.c = self.cp.generate_q_random();

        let auth_id = Uuid::new_v4().to_string();
        self.auth_ids.lock().unwrap().insert(auth_id.clone(), request.user);
        return Ok(Response::new(AuthenticationChallengeResponse {
            auth_id,
            c: user_info.c.serialise()
        }))
    }

    async fn verify_authentication(&self, request: Request<AuthenticationAnswerRequest>) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        println!("Processing authentication verify request: {:?}", request);
        let request = request.into_inner();

        let auth_ids = self.auth_ids.lock().unwrap();
        let user_name = auth_ids
            .get(&request.auth_id)
            .ok_or_else(|| Status::new(Code::Unauthenticated, "User not authenticated"))?;

        let user_infos = self.user_infos.lock().unwrap();
        let user_info = user_infos
            .get(user_name.as_str())
            .ok_or_else(|| Status::new(Code::Unauthenticated, "User not authenticated"))?;

        user_info.verify(&self.cp, &request.s.deserialise_big_uint())
            .map_err(|msg| Status::new(Code::PermissionDenied, msg))?;

        Ok(Response::new(AuthenticationAnswerResponse {
            session_id: Uuid::new_v4().to_string()
        }))
    }
}

impl AuthImpl {
    fn new(cp: ChaumPedersen) -> Self {
        AuthImpl {
            cp,
            user_infos: Mutex::default(),
            auth_ids: Mutex::default()
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    let help_message = "server <address> <params file>";

    let address = args.get(1)
        .unwrap_or_else(|| {
            eprintln!("Missing address: {}", help_message);
            exit(1);
        })
        .parse::<SocketAddr>()
        .unwrap_or_else(|_| {
            eprintln!("Invalid address: {}", help_message);
            exit(1);
        });

    let params_file = args.get(2).unwrap_or_else(|| {
        eprintln!("Missing params file: {}", help_message);
        exit(1);
    });

    let config = fs::read_to_string(params_file)?.parse::<Table>()?;
    let p = get_big_unit(&config, "p")?;
    let q = get_big_unit(&config, "q")?;
    let g = get_big_unit(&config, "g")?;
    let h = g.modpow(&q, &p);  // TODO Is it OK to use q as the exponent to get another generator?

    let auth_impl = AuthImpl::new(ChaumPedersen { p, q, g, h });

    let future = Server::builder().add_service(AuthServer::new(auth_impl)).serve(address);

    println!("Listening on {}", address);

    future.await?;
    return Ok(());
}

fn get_big_unit(config: &Table, key: &str) -> Result<BigUint, Box<dyn Error>> {
    let value = config.get(key)
        .ok_or_else(|| format!("Params file missing key '{}'", key))?
        .as_str()
        .ok_or_else(|| format!("Key '{}' in params file is not a string", key))?;
    let big_unit = parse_columnar_hex(value).map_err(|_| format!("Key '{}' in params file is not a hex value", key))?;
    Ok(big_unit)
}

fn parse_columnar_hex(str: &str) -> Result<BigUint, ParseBigIntError> {
    BigUint::from_str_radix(str.replace(&[' ', '\n'][..], "").as_str(), 16)
}
