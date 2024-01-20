#![deny(unused_must_use)]

use std::{env, fs};
use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::process::exit;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

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

#[derive(Debug)]
struct User {
    user_name: String,
    y1: BigUint,
    y2: BigUint
}

#[derive(Debug)]
struct InProgressAuthentication {
    user: Arc<User>,
    r1: BigUint,
    r2: BigUint,
    c: BigUint,
    time_stamp: SystemTime  // TODO Use this to delete old entries
}

impl InProgressAuthentication {
    fn verify<'a>(&'a self, cp: &'a ChaumPedersen, s: &BigUint) -> Result<(), &str> {
        cp.verify_solution(&self.r1, &self.r2, &self.user.y1, &self.user.y2, &self.c, s)
    }
}

#[derive(Debug)]
struct AuthImpl {
    cp: ChaumPedersen,
    users: Mutex<HashMap<String, Arc<User>>>,
    in_progress_authentications: Mutex<HashMap<String, InProgressAuthentication>>,
}

impl AuthImpl {
    fn new(cp: ChaumPedersen) -> Self {
        AuthImpl { cp, users: Mutex::default(), in_progress_authentications: Mutex::default() }
    }
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

        let mut users = self.users.lock().unwrap();
        if users.contains_key(&request.user_name) {
            return Err(Status::new(Code::AlreadyExists, format!("User name '{}' already exists", &request.user_name)));
        }

        users.insert(
            request.user_name.clone(),
            Arc::from(User {
                user_name: request.user_name,
                y1: request.y1.deserialise_big_uint(),
                y2: request.y2.deserialise_big_uint()
            })
        );

        Ok(Response::new(RegisterResponse { }))
    }

    async fn create_authentication_challenge(&self, request: Request<AuthenticationChallengeRequest>) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        println!("Processing authentication challenge request: {:?}", request);
        let request = request.into_inner();

        let users = self.users.lock().unwrap();
        let user = users
            .get(&request.user_name)
            .ok_or_else(|| Status::new(Code::NotFound, format!("User '{}' not found", &request.user_name)))?;

        let c = self.cp.generate_q_random();
        let c_serialised = c.serialise();

        let authentication = InProgressAuthentication {
            user: Arc::clone(user),
            r1: request.r1.deserialise_big_uint(),
            r2: request.r2.deserialise_big_uint(),
            c,
            time_stamp: SystemTime::now()
        };

        let correlation_id = Uuid::new_v4().to_string();
        self.in_progress_authentications.lock().unwrap().insert(correlation_id.clone(), authentication);
        return Ok(Response::new(AuthenticationChallengeResponse {
            correlation_id,
            c: c_serialised
        }))
    }

    async fn verify_authentication(&self, request: Request<AuthenticationAnswerRequest>) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        println!("Processing authentication verify request: {:?}", request);
        let request = request.into_inner();

        let mut in_progress_authentications = self.in_progress_authentications.lock().unwrap();
        let authentication = in_progress_authentications
            .remove(&request.correlation_id)
            .ok_or_else(|| Status::new(Code::NotFound, "Unknown authentication correlation ID"))?;

        authentication.verify(&self.cp, &request.s.deserialise_big_uint())
            .map_err(|msg| Status::new(Code::PermissionDenied, msg))?;

        Ok(Response::new(AuthenticationAnswerResponse {
            session_id: Uuid::new_v4().to_string()
        }))
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
