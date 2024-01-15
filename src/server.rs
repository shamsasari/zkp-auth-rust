#![deny(unused_must_use)]

use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::process::exit;
use std::sync::Mutex;

use num_bigint::{BigUint, RandBigInt};
use tonic::{Code, Request, Response, Status};
use tonic::transport::Server;
use uuid::Uuid;

use zkp_auth_rust::ChaumPedersen;

use crate::zkp_auth::{AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest, AuthenticationChallengeResponse, RegisterRequest, RegisterResponse};
use crate::zkp_auth::auth_server::{Auth, AuthServer};

pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

#[derive(Debug, Default)]
struct UserInfo {
    user_name: String,
    cp: ChaumPedersen,
    y1: BigUint,
    y2: BigUint,
    r1: BigUint,
    r2: BigUint,
    c: BigUint,
    session_id: String
}

impl UserInfo {
    fn verify(&self, s: &BigUint) -> Result<(), &str> {
        return self.cp.verify(&self.r1, &self.r2, &self.y1, &self.y2, &self.c, &s);
    }
}

#[derive(Debug, Default)]
struct AuthImpl {
    user_infos: Mutex<HashMap<String, UserInfo>>,
    auth_ids: Mutex<HashMap<String, String>>
}

#[tonic::async_trait]
impl Auth for AuthImpl {
    async fn register(&self, request: Request<RegisterRequest>) -> Result<Response<RegisterResponse>, Status> {
        println!("Processing register request: {:?}", request);
        let request = request.into_inner();

        let mut user_info = UserInfo::default();
        user_info.user_name = request.user;
        user_info.cp = ChaumPedersen {
            p: BigUint::from_bytes_be(&request.p),
            q: BigUint::from_bytes_be(&request.q),
            alpha: BigUint::from_bytes_be(&request.alpha),
            beta: BigUint::from_bytes_be(&request.beta)
        };
        user_info.y2 = BigUint::from_bytes_be(&request.y2);
        user_info.y2 = BigUint::from_bytes_be(&request.y2);

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

        user_info.r1 = BigUint::from_bytes_be(&request.r1);
        user_info.r2 = BigUint::from_bytes_be(&request.r2);
        let c = user_info.cp.generate_q_random();

        let auth_id = Uuid::new_v4().to_string();
        self.auth_ids.lock().unwrap().insert(auth_id.clone(), request.user);
        return Ok(Response::new(AuthenticationChallengeResponse {
            auth_id,
            c: c.to_bytes_be()
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

        user_info.verify(&BigUint::from_bytes_be(&request.s))
            .map_err(|msg| Status::new(Code::PermissionDenied, msg))?;

        Ok(Response::new(AuthenticationAnswerResponse {
            session_id: Uuid::new_v4().to_string()
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let address = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Please specify auth server address");
        exit(1);
    });

    let auth_impl = AuthImpl::default();

    Server::builder()
        .add_service(AuthServer::new(auth_impl))
        .serve(address.parse()?)
        .await?;

    return Ok(());
}
