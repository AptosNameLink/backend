use std::sync::Arc;
use actix_web::web::Data;
use actix_web::{middleware, web, App, HttpRequest, HttpServer};
use gluesql::prelude::*;
use std::sync::Mutex;
use actix_cors::Cors;

mod client;
mod http;
mod package;
mod routes;

#[macro_use]
extern crate json;

use crate::routes::aptos::{aptos_random_value, query_signatures, SignatureInfoList, verify_signatures};
use crate::routes::health::{evmos_health, osmosis_health, polygon_health};
use crate::routes::query::{query_balance, track_messages};

async fn index(req: HttpRequest) -> &'static str {
    println!("REQ: {req:?}");
    "James Web3!"
}

pub struct AppState {
    // glue: Arc<Mutex<Glue<MemoryStorage>>>,
    signature_info_list: SignatureInfoList,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "debug");
    env_logger::init();

    let storage = MemoryStorage::default();
    let glue = Arc::new(Mutex::new(Glue::new(storage)));
    let app_state = web::Data::new(AppState {
        // glue: glue.clone(),
        signature_info_list: SignatureInfoList::new(),
    });

    HttpServer::new(move || {
        let cors = Cors::default().allow_any_origin().send_wildcard();

        let health_controller = web::scope("/health")
            .app_data(Data::new(reqwest::Client::new()))
            .service(osmosis_health)
            .service(polygon_health)
            .service(evmos_health);
        let query_controller = web::scope("/query")
            .app_data(Data::new(reqwest::Client::new()))
            .service(query_balance)
            .service(track_messages);
        let hackathon_controller = web::scope("/aptos")
            .app_data(Data::new(reqwest::Client::new()))
            .app_data(app_state.clone())
            .service(verify_signatures)
            .service(query_signatures)
            .service(aptos_random_value);

        App::new()
            .wrap(middleware::Logger::default())
            .wrap(cors)
            .service(health_controller)
            .service(query_controller)
            .service(hackathon_controller)
            .service(web::resource("/index.html").to(|| async { "Hello world!" }))
            .service(web::resource("/").to(index))
    })
    .bind(("0.0.0.0", 80))?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use crate::http::response::HealthResponse;
    use actix_web::{body::to_bytes, dev::Service, http, test, web, App, Error};

    use super::*;

    #[actix_web::test]
    async fn test_index() -> Result<(), Error> {
        let app = App::new().route("/", web::get().to(index));
        let app = test::init_service(app).await;

        let req = test::TestRequest::get().uri("/").to_request();
        let resp = app.call(req).await?;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let response_body = resp.into_body();
        assert_eq!(to_bytes(response_body).await?, r##"Parachute Drop!"##);

        Ok(())
    }
}
