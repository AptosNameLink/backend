use crate::http::error::HTTPError;
use actix_web::http::StatusCode;
use actix_web::HttpResponse;
use ibc_proto::cosmos::bank::v1beta1::QueryBalanceResponse;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use serde_json::map::Values;
use serde_json::Value;

#[derive(Serialize, Deserialize)]
pub(crate) struct AptosHackathonRandomResponse {
    pub(crate) random_value: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct AptosHackathonVerificationResponse {
    pub(crate) status: String,
    pub(crate) ipfs_hash: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct AptosHackathonQueryInformationResponse {
    pub(crate) ethereum_address: String,
    pub(crate) aptos_address: String,
    pub(crate) ethereum_public_key: String,
    pub(crate) aptos_public_key: String,
    pub(crate) random_value: String,
    pub(crate) timestamp: String,
    pub(crate) ethereum_signature: String,
    pub(crate) aptos_signature: String,
    pub(crate) ipfs_hash: String,
}

pub async fn build_aptos_hackathon_mock_verification_response() -> Result<HttpResponse, HTTPError> {
    let mock_response = AptosHackathonVerificationResponse {
        status: "success".to_string(),
        ipfs_hash: "QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn".to_string(),
    };
    let response = HttpResponse::build(StatusCode::OK).json(mock_response);
    Ok(response)
}

pub async fn build_aptos_hackathon_mock_query_information_response(
) -> Result<HttpResponse, HTTPError> {
    let mock_response = AptosHackathonQueryInformationResponse {
        ethereum_address: "0x54Ec3614921C851898d11Ce14a8c88d2d00119B2".to_string(),
        aptos_address: "0xb96455a118a0e0bd3ddf3e56345607f17579882d41a302f48bab2eecc69f8c0a".to_string(),
        ethereum_public_key: "63FaC9201494f0bd17B9892B9fae4d52fe3BD377".to_string(),
        aptos_public_key: "0xb96455a118a0e0bd3ddf3e56345607f17579882d41a302f48bab2eecc69f8c0a".to_string(),
        random_value: "aptosgazua".to_string(),
        timestamp: "2023-02-01T13:39:57-08:00".to_string(),
        ethereum_signature: "0xb8982e27551952e8a3d454e2cf8601f840891346ba4b12b76ed59807d26df05f66fb1f7df823dbffe4089389c9908b3a5a721d4a78ead2cdc911ec451f0656161b".to_string(),
        aptos_signature: "65c46ccb59fe75fd539800559451f114ba1c576d030e56916078b342b088a5b26fd75dcc557bd57502fecb5294797afd99ff197a614e4e715d8ea9e0982d0002".to_string(),
        ipfs_hash: "QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn".to_string(),
    };
    let response = HttpResponse::build(StatusCode::OK).json(mock_response);
    Ok(response)
}

#[derive(Serialize, Deserialize)]
pub(crate) struct HealthResponse {
    pub(crate) status: u16,
    pub(crate) message: String,
    pub(crate) data: Option<Value>,
}

pub async fn build_health_response(
    res: Option<Response>,
    val: Value,
) -> Result<HttpResponse, HTTPError> {
    // TODO: refactor - make sedre_json to be possible at the method level, not from outside
    if !val.is_null() {
        let response = HealthResponse {
            status: 200,
            message: "now working".to_string(),
            data: Some(val),
        };

        Ok(HttpResponse::Ok().json(response))
    } else if let Some(res) = res {
        if res.status().is_success() {
            let body = res.text().await.map_err(|_| HTTPError::Timeout)?;
            let data: serde_json::Value =
                serde_json::from_str(&body).map_err(|_| HTTPError::BadRequest)?;
            let ok_response = HealthResponse {
                status: 200,
                message: "now working".to_string(),
                data: Some(data),
            };
            Ok(HttpResponse::Ok().json(ok_response))
        } else {
            let err_response = HealthResponse {
                status: res.status().as_u16(),
                message: "service is not working well".to_string(),
                data: None,
            };

            let response = HttpResponse::build(StatusCode::from_u16(err_response.status).unwrap())
                .json(err_response);

            Ok(response)
        }
    } else {
        let err_response = HealthResponse {
            status: 500,
            message: "service is not working well".to_string(),
            data: None,
        };

        let response = HttpResponse::build(StatusCode::from_u16(err_response.status).unwrap())
            .json(err_response);

        Ok(response)
    }
}
