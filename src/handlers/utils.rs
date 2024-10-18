use actix_web::{http::StatusCode, web::Data, HttpRequest, HttpResponse};
use url::Url;

use super::AegisState;

pub async fn proxy(data: Data<AegisState>, req: HttpRequest) -> HttpResponse {
    let http_client = data.http_client.clone();
    let config = data.config.lock().await;

    // Use a different URL for the proxy
    let upstream_url = format!(
        "{}{}",
        config.upstream,
        req.uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/")
    );

    let upstream_url = match Url::parse(&upstream_url).map_err(|err| {
        tracing::error!("Failed to parse upstream url: {:?}", err);
    }) {
        Ok(url) => url,
        Err(_) => return HttpResponse::InternalServerError().body("Error from Aegis"),
    };

    let req_method = match reqwest::Method::from_bytes(req.method().as_str().as_bytes()) {
        Ok(method) => method,
        Err(_) => return HttpResponse::InternalServerError().body("Error from Aegis"),
    };
    let mut reqwest_request = data.http_client.request(req_method, upstream_url);

    let req_headers = req.headers().clone();
    for (key, value) in req_headers.iter() {
        reqwest_request = reqwest_request.header(
            key.as_str(),
            match reqwest::header::HeaderValue::from_str(value.to_str().unwrap_or("")) {
                Ok(val) => val,
                Err(_) => return HttpResponse::InternalServerError().body("Error from Aegis"),
            },
        );
    }

    let reqwest_request = match reqwest_request.build() {
        Ok(req) => req,
        Err(_) => return HttpResponse::InternalServerError().body("Error from Aegis"),
    };

    let res = match http_client.execute(reqwest_request).await.map_err(|err| {
        tracing::error!("Failed to fetch from upstream: {:?}", err);
    }) {
        Ok(res) => res,
        Err(_) => return HttpResponse::InternalServerError().body("Failed to fetch from upstream"),
    };

    let proxy_status = match StatusCode::from_u16(res.status().as_u16()) {
        Ok(code) => code,
        Err(_) => {
            return HttpResponse::InternalServerError().body("Invalid status code from upstream")
        }
    };
    let mut proxy_res = HttpResponse::build(proxy_status);
    for (name, value) in res.headers().iter() {
        proxy_res.insert_header((name.as_str(), value.to_str().unwrap_or("")));
    }

    // Return the response body
    let body = match res.bytes().await {
        Ok(bytes) => bytes,
        Err(_) => return HttpResponse::InternalServerError().body("Error reading response body"),
    };
    proxy_res.body(body)
}
