use crate::http::error::HTTPError;
use crate::http::method::HTTPRequestMethod;
use crate::http::response;
use crate::http::response::{AptosHackathonRandomResponse, HealthResponse};
use actix_web::http::StatusCode;
use actix_web::{get, post, web, HttpResponse, Responder};
use ibc_proto::cosmos::bank::v1beta1::{
    query_client::QueryClient, QueryAllBalancesRequest, QueryBalanceRequest, QueryBalanceResponse,
};
use ibc_proto::ibc::core::channel::v1::acknowledgement::Response::Error;
use reqwest::{Client, Response, Version};
use tonic::codegen::Body;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct ChainType {
    chain_name: String,
}

#[get("/random")]
pub async fn aptos_random_value() -> Result<HttpResponse, HTTPError> {
    let random_value = "aptosgazua";
    Ok(HttpResponse::Ok().json(AptosHackathonRandomResponse {
        random_value: random_value.to_string(),
    }))
}

#[post("/signature")]
pub async fn verify_signatures(info: web::Query<ChainType>) -> Result<HttpResponse, HTTPError> {
    let chain = &info.chain_name;
    Ok(HttpResponse::Ok().json(AptosHackathonRandomResponse {
        random_value: chain.to_string(),
    }))
}

#[get("/signature")]
pub async fn query_signatures(info: web::Query<ChainType>) -> Result<HttpResponse, HTTPError> {
    let chain = &info.chain_name;
    Ok(HttpResponse::Ok().json(AptosHackathonRandomResponse {
        random_value: chain.to_string(),
    }))
}
