#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use actix_web::{
        test,
        web::{self, Data},
        App, HttpRequest, HttpResponse, HttpServer, Responder,
    };
    use tokio::sync::Mutex;

    use crate::{
        config::AegisConfig,
        handlers::{utils::proxy, AegisState},
    };

    async fn index(data: Data<AegisState>, req: HttpRequest) -> HttpResponse {
        proxy(data, req).await
    }

    async fn upstream() -> impl Responder {
        HttpResponse::Ok().body("Hello world!")
    }

    #[actix_web::test]
    async fn test_proxy() {
        let config: AegisConfig = AegisConfig::new("http://localhost:4000".to_string());
        // Init http client
        let http_client = reqwest::Client::new();

        let listen_address = config.server.address.clone();

        // Start upstream server
        tokio::spawn(async move {
            HttpServer::new(|| App::new().default_service(web::to(upstream)))
                .bind((listen_address, 4000))
                .unwrap()
                .run()
                .await
        });

        // Init AegisState
        let state: AegisState = AegisState {
            config: Arc::new(Mutex::new(config)),
            redis_client: None,
            http_client,
            metrics: None,
        };

        let app = test::init_service(
            App::new()
                .app_data(Data::new(state))
                .route("/", web::get().to(index)),
        )
        .await;
        let req = test::TestRequest::default().to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }
}
