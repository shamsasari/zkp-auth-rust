use std::collections::HashMap;
use std::sync::Mutex;

use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;
use tonic::{Code, Request, Response, Status};
use tonic::transport::Server;
use uuid::Uuid;

use crate::zkp_auth::{AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest, AuthenticationChallengeResponse, RegisterRequest, RegisterResponse};
use crate::zkp_auth::auth_server::{Auth, AuthServer};

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
    s: BigUint,
    session_id: String
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
        user_info.y1 = BigUint::from_bytes_be(&request.y1);
        user_info.y2 = BigUint::from_bytes_be(&request.y2);

        let mut user_infos = self.user_infos.lock().unwrap();
        user_infos.insert(user_info.user_name.clone(), user_info);

        Ok(Response::new(RegisterResponse { }))
    }

    async fn create_authentication_challenge(&self, request: Request<AuthenticationChallengeRequest>) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        println!("Processing authentication challenge request: {:?}", request);

        let request = request.into_inner();

        let mut user_infos = self.user_infos.lock().unwrap();
        return if let Some(user_info) = user_infos.get_mut(&request.user) {
            user_info.r1 = BigUint::from_bytes_be(&request.r1);
            user_info.r2 = BigUint::from_bytes_be(&request.r2);
            let c = thread_rng().gen_biguint(256);  // TODO Should use q
            let auth_id = Uuid::new_v4().to_string();
            self.auth_ids.lock().unwrap().insert(auth_id.clone(), request.user);
            Ok(Response::new(AuthenticationChallengeResponse {
                auth_id,
                c: c.to_bytes_be()
            }))
        } else {
            Err(Status::new(Code::NotFound, format!("User {} not found", &request.user)))
        }
    }

    async fn verify_authentication(&self, request: Request<AuthenticationAnswerRequest>) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        println!("Processing authentication verify request: {:?}", request);

        let request = request.into_inner();

        return if let Some(user_name) = self.auth_ids.lock().unwrap().get(&request.auth_id) {
            if let Some(user_info) = self.user_infos.lock().unwrap().get(&user_name) {

                Ok(Response::new(AuthenticationAnswerResponse {
                    session_id: Uuid::new_v4().to_string()
                }))
            } else {
                Err(Status::new(Code::Unauthenticated, "User not authenticated"))
            }
        } else {
            Err(Status::new(Code::Unauthenticated, "User not authenticated"))
        }
    }
}

#[tokio::main]
async fn main() {
    let address = "127.0.0.1:50051";

    let auth_impl = AuthImpl::default();

    Server::builder()
        .add_service(AuthServer::new(auth_impl))
        .serve(address.parse().unwrap())
        .await
        .unwrap();
}
