use crate::http::error::HTTPError;
use crate::http::method::HTTPRequestMethod;
use crate::http::response;
use crate::http::response::{AptosHackathonRandomResponse, HealthResponse};
use actix_web::http::StatusCode;
use actix_web::{get, web, HttpResponse, Responder};
use ibc_proto::cosmos::bank::v1beta1::{
    query_client::QueryClient, QueryAllBalancesRequest, QueryBalanceRequest, QueryBalanceResponse,
};
use ibc_proto::ibc::core::channel::v1::acknowledgement::Response::Error;
use reqwest::{Client, Response, Version};
use tonic::codegen::Body;

#[get("/random")]
pub async fn aptos_random_value() -> Result<HttpResponse, HTTPError> {
    let random_value = "aptosgazua";
    Ok(HttpResponse::Ok().json(AptosHackathonRandomResponse {
        random_value: random_value.to_string(),
    }))
}
