use crate::http::error::HTTPError;
use crate::http::method::HTTPRequestMethod;
use crate::http::response;
use crate::http::response::{
    build_aptos_hackathon_mock_query_information_response,
    build_aptos_hackathon_mock_verification_response, AptosHackathonRandomResponse,
    AptosHackathonVerificationResponse, HealthResponse,
};
use crate::package::aptos::{upload_ipfs, verify_signature_by_public_key_aptos, verify_signature_by_public_key_ethereum};
use actix_web::http::StatusCode;
use actix_web::{get, post, web, HttpResponse, Responder};
use actix_web::cookie::time::macros::time;
use ibc_proto::cosmos::bank::v1beta1::{
    query_client::QueryClient, QueryAllBalancesRequest, QueryBalanceRequest, QueryBalanceResponse,
};
use ibc_proto::ibc::core::channel::v1::acknowledgement::Response::Error;
use reqwest::{Client, Response, Version};
use serde::{Deserialize, Serialize};
use tonic::codegen::Body;
use crate::AppState;

#[derive(Deserialize)]
pub struct ChainType {
    chain_name: String,
}

#[derive(Deserialize)]
pub struct ChainTypeQuery {
    chain_name: String,
    address: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignatureInfo {
    pub(crate) ethereum_public_key: String, // optional
    pub(crate) ethereum_address: String,
    pub(crate) aptos_public_key: String,
    pub(crate) aptos_address: String,
    pub(crate) message: String,
    pub(crate) ethereum_signature: String,
    pub(crate) aptos_signature: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignatureSavedInfo {
    pub(crate) ethereum_public_key: String, // optional
    pub(crate) ethereum_address: String,
    pub(crate) aptos_public_key: String,
    pub(crate) aptos_address: String,
    pub(crate) random_value: String,
    pub(crate) ethereum_signature: String,
    pub(crate) aptos_signature: String,
    pub(crate) ipfs_hash: String,
    pub(crate) timestamp: String,
}

pub struct SignatureInfoList {
    pub list: Vec<SignatureSavedInfo>,
}

impl SignatureInfoList {
    pub fn new() -> Self {
        Self { list: Vec::new() }
    }

    pub fn add(&mut self, signature_info: SignatureSavedInfo) {
        self.list.push(signature_info.clone());
    }

    pub fn find_element_by_aptos_address(&self, aptos_address: &str) -> Option<&SignatureSavedInfo> {
        self.list.iter().find(|&x| x.aptos_address == aptos_address)
    }
}

#[get("/random")]
pub async fn aptos_random_value() -> Result<HttpResponse, HTTPError> {
    let random_value = "aptosgazua";
    Ok(HttpResponse::Ok().json(AptosHackathonRandomResponse {
        random_value: random_value.to_string(),
    }))
}

#[post("/signature")]
pub async fn verify_signatures(
    data: web::Data<AppState>,
    info: web::Query<ChainType>,
    signature_data: web::Json<SignatureInfo>,
) -> Result<HttpResponse, HTTPError> {
    let chain = &info.chain_name;
    println!("target_chain: {}", chain);

    let signature_info = &signature_data.into_inner();
    let ethereum_public_key = &signature_info.ethereum_public_key;
    // 0x01725BE700413D34bCC5e961de1d0C777d3A52F4
    let ethereum_address = &signature_info.ethereum_address;
    // e.g. "0x917e745db1b1edc9ce62a8ed62b1cfcf261b4a5a21d58b167874e6cf6fa68aa3"
    let aptos_public_key = &signature_info.aptos_public_key;
    // e.g. "0x470196fa19f82ece3bfe1f4658c12098f752c5ae01a43a4f57cb46fbf05c1011"
    let aptos_address = &signature_info.aptos_address;
    let message = &signature_info.message;
    // 71bcbc3edb59e4182c7d8dddf38df23d5220194fbe0e6f4577d4137c91c678a00825785fee253b93944c05202e339109e295cc523818995e5307813a8282e3cc1b
    let ethereum_signature = &signature_info.ethereum_signature;
    // e.g. "2b5f492d76c0c5a7c65eb8832168e14a506386f5a2cf1ad90ae12a121ad4a0ab8c04c4872e841239b608f2ec2fc01244221b3610c41eb0bdd974632320eef207"
    let aptos_signature = &signature_info.aptos_signature;

    let ethereum_result =
        verify_signature_by_public_key_ethereum(ethereum_signature, ethereum_address);
    let aptos_result =
        verify_signature_by_public_key_aptos(message, aptos_signature, aptos_public_key);
    let mut signature_info_list = data.signature_info_list.list.clone();
    if ethereum_result == true && aptos_result == true {
        println!("Both signatures are valid");
        // let database_response = store_database(data, signature_info);
        let serialized_data = serde_json::to_string(&signature_info).unwrap();
        let ipfs_response = upload_ipfs(serialized_data).await;
        let ipfs_response = ipfs_response.unwrap_or_else(|_| "".to_string());

        let signature_saved_info = SignatureSavedInfo {
            ethereum_public_key: ethereum_public_key.to_string(),
            ethereum_address: ethereum_address.to_string(),
            aptos_public_key: aptos_public_key.to_string(),
            aptos_address: aptos_address.to_string(),
            random_value: message.to_string(),
            ethereum_signature: ethereum_signature.to_string(),
            aptos_signature: aptos_signature.to_string(),
            ipfs_hash: ipfs_response,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .to_string(),
        };
        signature_info_list.push(signature_saved_info.clone());
        // signature_info_list.add(signature_saved_info.clone());
        Ok(HttpResponse::Ok().json(signature_saved_info))
    } else {
        println!("One of the signatures is invalid");
        // TODO: not adding in the case
        let signature_saved_info = SignatureSavedInfo {
            ethereum_public_key: ethereum_public_key.to_string(),
            ethereum_address: ethereum_address.to_string(),
            aptos_public_key: aptos_public_key.to_string(),
            aptos_address: aptos_address.to_string(),
            random_value: message.to_string(),
            ethereum_signature: ethereum_signature.to_string(),
            aptos_signature: aptos_signature.to_string(),
            ipfs_hash: "".to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .to_string(),
        };
        signature_info_list.push(signature_saved_info.clone());
        // signature_info_list.add(signature_saved_info.clone());
        // let database_response = store_database(data, signature_info);
        // println!("database_response: {:?}", database_response);
        let response = AptosHackathonVerificationResponse {
            status: "failed".to_string(),
            ipfs_hash: "".to_string(),
        };
        Ok(HttpResponse::build(StatusCode::BAD_REQUEST).json(response))
    }
}

// AptosHackathonQueryResponse
#[derive(Debug, Serialize, Deserialize)]
pub struct AptosHackathonQueryResponse {
    pub status: String,
    pub ethereum_public_key: String,
    pub ethereum_address: String,
    pub aptos_public_key: String,
    pub aptos_address: String,
    pub random_value: String,
    pub ethereum_signature: String,
    pub aptos_signature: String,
    pub ipfs_hash: String,
    pub timestamp: String,
}

#[get("/signature")]
pub async fn query_signatures(data: web::Data<AppState>, info: web::Query<ChainTypeQuery>) -> Result<HttpResponse, HTTPError> {
    let chain = &info.chain_name;
    let aptos_address = &info.address;
    println!("target_chain: {}", chain);
    println!("target_address: {}", aptos_address);
    // find_element_by_aptos_signature
    let signature_info_list = &data.signature_info_list;
    let response = signature_info_list.clone();
    // find by find_element_by_aptos_signature
    let response = signature_info_list.find_element_by_aptos_address(aptos_address);
    // if response is None, return failed
    if !response.is_some() {
        let response = AptosHackathonQueryResponse {
            status: "failed".to_string(),
            ethereum_public_key: "".to_string(),
            ethereum_address: "".to_string(),
            aptos_public_key: "".to_string(),
            aptos_address: "".to_string(),
            random_value: "".to_string(),
            ethereum_signature: "".to_string(),
            aptos_signature: "".to_string(),
            ipfs_hash: "".to_string(),
            timestamp: "".to_string(),
        };
        return Ok(HttpResponse::build(StatusCode::BAD_REQUEST).json(response));
    }
    let response = response.unwrap();
    let response = AptosHackathonQueryResponse {
        status: "success".to_string(),
        ethereum_public_key: response.ethereum_public_key.clone(),
        ethereum_address: response.ethereum_address.clone(),
        aptos_public_key: response.aptos_public_key.clone(),
        aptos_address: response.aptos_address.clone(),
        random_value: response.random_value.clone(),
        ethereum_signature: response.ethereum_signature.clone(),
        aptos_signature: response.aptos_signature.clone(),
        ipfs_hash: response.ipfs_hash.clone(),
        timestamp: response.timestamp.clone(),
    };
    Ok(HttpResponse::build(StatusCode::OK).json(response))
}
