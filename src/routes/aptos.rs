use crate::http::error::HTTPError;
use crate::http::method::HTTPRequestMethod;
use crate::http::response;
use crate::http::response::{
    build_aptos_hackathon_mock_query_information_response,
    build_aptos_hackathon_mock_verification_response, AptosHackathonRandomResponse, HealthResponse,
};
use crate::package::aptos::{
    verify_signature_by_public_key_aptos, verify_signature_by_public_key_ethereum,
};
use actix_web::http::StatusCode;
use actix_web::{get, post, web, HttpResponse, Responder};
use ibc_proto::cosmos::bank::v1beta1::{
    query_client::QueryClient, QueryAllBalancesRequest, QueryBalanceRequest, QueryBalanceResponse,
};
use ibc_proto::ibc::core::channel::v1::acknowledgement::Response::Error;
use reqwest::{Client, Response, Version};
use serde::Deserialize;
use tonic::codegen::Body;

#[derive(Deserialize)]
pub struct ChainType {
    chain_name: String,
}

#[derive(Deserialize)]
pub struct SignatureInfo {
    ethereum_public_key: String,
    ethereum_address: String,
    aptos_public_key: String,
    aptos_address: String,
    message: String,
    ethereum_signature: String,
    aptos_signature: String,
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
    info: web::Query<ChainType>,
    signature_data: web::Json<SignatureInfo>,
) -> Result<HttpResponse, HTTPError> {
    let chain = &info.chain_name;
    println!("target_chain: {}", chain);

    let signature_info = &signature_data.into_inner();
    let ethereum_public_key = &signature_info.ethereum_public_key;
    let ethereum_address = &signature_info.ethereum_address;
    // e.g. "0x917e745db1b1edc9ce62a8ed62b1cfcf261b4a5a21d58b167874e6cf6fa68aa3"
    let aptos_public_key = &signature_info.aptos_public_key;
    // e.g. "0x470196fa19f82ece3bfe1f4658c12098f752c5ae01a43a4f57cb46fbf05c1011"
    let aptos_address = &signature_info.aptos_address;
    let message = &signature_info.message;
    let ethereum_signature = &signature_info.ethereum_signature;
    // e.g. "2b5f492d76c0c5a7c65eb8832168e14a506386f5a2cf1ad90ae12a121ad4a0ab8c04c4872e841239b608f2ec2fc01244221b3610c41eb0bdd974632320eef207"
    let aptos_signature = &signature_info.aptos_signature;

    let ethereum_result =
        verify_signature_by_public_key_ethereum(ethereum_signature, ethereum_public_key);
    let aptos_result = verify_signature_by_public_key_aptos(message, aptos_signature, aptos_public_key);

    if ethereum_result == true && aptos_result == true {
        println!("Both signatures are valid");
    } else {
        println!("One of the signatures is invalid");
    }

    build_aptos_hackathon_mock_verification_response().await
}

#[get("/signature")]
pub async fn query_signatures(info: web::Query<ChainType>) -> Result<HttpResponse, HTTPError> {
    let chain = &info.chain_name;
    println!("target_chain: {}", chain);
    build_aptos_hackathon_mock_query_information_response().await
}
