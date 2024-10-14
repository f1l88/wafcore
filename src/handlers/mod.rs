use std::sync::Arc;

use actix_web::{http::StatusCode, web::Data, HttpRequest, HttpResponse};
use tokio::sync::Mutex;
use url::Url;

use crate::{clients, config::AegisConfig};

use actix_web::cookie::Cookie;
use regex::Regex;
use std::collections::HashMap;

use crate::config::{
    AegisRule, RegularRuleCondition, RegularRuleStatementInspect,
    RegularRuleStatementInspectTypeContentFilter, RegularRuleStatementInspectTypeScope,
    RegularRuleStatementMatchType, RuleAction,
};

#[derive(Clone, Debug)]
pub struct AegisState {
    pub config: Arc<Mutex<AegisConfig>>,
    pub redis_client: Option<clients::redis::RedisClient>,
    pub http_client: reqwest::Client,
}

const REDIS_FIREWALL_BLOCK_KEY: &str = "blocked_requests";

#[derive(Debug)]
pub enum RegularRuleStatementInspectValue {
    Single(String),
    All(Vec<String>),
}

pub async fn root(data: Data<AegisState>, req: HttpRequest) -> HttpResponse {
    let config = data.config.lock().await.clone();
    for rule in config.rules.clone() {
        let action = match rule {
            AegisRule::Regular {
                action,
                condition,
                statements,
            } => {
                let mut statement_results: Vec<bool> = vec![];
                for statement in statements {
                    let value = fetch_statement_inspect(&statement.inspect, &req).await;

                    let statement_match = match statement.match_type {
                        RegularRuleStatementMatchType::StartsWith => match value {
                            RegularRuleStatementInspectValue::Single(val) => {
                                val.starts_with(&statement.match_string)
                            }
                            RegularRuleStatementInspectValue::All(vec) => vec
                                .iter()
                                .all(|val| val.starts_with(&statement.match_string)),
                        },
                        RegularRuleStatementMatchType::EndsWith => match value {
                            RegularRuleStatementInspectValue::Single(val) => {
                                val.ends_with(&statement.match_string)
                            }
                            RegularRuleStatementInspectValue::All(vec) => {
                                vec.iter().all(|val| val.ends_with(&statement.match_string))
                            }
                        },
                        RegularRuleStatementMatchType::Contains => match value {
                            RegularRuleStatementInspectValue::Single(val) => {
                                val.contains(&statement.match_string)
                            }
                            RegularRuleStatementInspectValue::All(vec) => {
                                vec.iter().all(|val| val.contains(&statement.match_string))
                            }
                        },
                        RegularRuleStatementMatchType::Exact => match value {
                            RegularRuleStatementInspectValue::Single(val) => {
                                val == statement.match_string
                            }
                            RegularRuleStatementInspectValue::All(vec) => {
                                vec.iter().all(|val| *val == statement.match_string)
                            }
                        },
                        RegularRuleStatementMatchType::Regex => match value {
                            RegularRuleStatementInspectValue::Single(val) => {
                                if let Ok(re) = Regex::new(&format!(r"{}", statement.match_string))
                                {
                                    re.is_match(&val)
                                } else {
                                    false
                                }
                            }
                            RegularRuleStatementInspectValue::All(vec) => vec.iter().all(|val| {
                                if let Ok(re) = Regex::new(&format!(r"{}", statement.match_string))
                                {
                                    re.is_match(&val)
                                } else {
                                    false
                                }
                            }),
                        },
                    };

                    // Negate statement if stated in config
                    let rule_match = if statement.negate_statement {
                        !statement_match
                    } else {
                        statement_match
                    };

                    statement_results.push(rule_match);
                }

                let is_match = match condition {
                    RegularRuleCondition::One => statement_results.iter().any(|r| *r == true),
                    RegularRuleCondition::All => statement_results.iter().all(|r| *r == true),
                    RegularRuleCondition::None => !statement_results.iter().all(|r| *r != true),
                };

                if is_match {
                    action
                } else {
                    match action {
                        RuleAction::Count => continue,
                        _ => action.negate(),
                    }
                }
            }
            AegisRule::RateBased { .. } => {
                // let client_ip = addr.ip().to_string();
                // tracing::info!("{:?}", addr);
                RuleAction::Allow
            }
        };

        match action {
            RuleAction::Allow => {
                let res = proxy(data, req).await;
                return res;
            }
            RuleAction::Block => {
                return HttpResponse::Forbidden().body("Request blocked by firewall")
            }

            RuleAction::Count => {
                if let Some(ref client) = data.redis_client {
                    // If an error occured while counting a request it should not result in a failure
                    let _ = client.incr(REDIS_FIREWALL_BLOCK_KEY.to_string(), 1).await;
                }
                continue;
            }
        }
    }

    match config.default_action {
        RuleAction::Allow => {
            let res = proxy(data, req).await;
            return res;
        }
        RuleAction::Block => return HttpResponse::Forbidden().body("Request blocked by firewall"),

        _ => return HttpResponse::Forbidden().body("Request blocked by firewall"),
    }
}

async fn fetch_statement_inspect(
    inspect_type: &RegularRuleStatementInspect,
    request: &HttpRequest,
) -> RegularRuleStatementInspectValue {
    match inspect_type {
        RegularRuleStatementInspect::Header { key } => {
            if let Some(value) = request.headers().get(key) {
                return RegularRuleStatementInspectValue::Single(
                    value.to_str().unwrap_or("").to_string(),
                );
            } else {
                return RegularRuleStatementInspectValue::Single("".to_string());
            }
        }
        RegularRuleStatementInspect::QueryParameter { key } => request
            .uri()
            .query()
            .and_then(|query_value| Url::parse(&format!("http://localhost?{}", query_value)).ok())
            .and_then(|url| {
                let params: HashMap<_, _> = url.query_pairs().into_owned().collect();
                return params
                    .get(key)
                    .map(|v| RegularRuleStatementInspectValue::Single(v.to_string()));
            })
            .unwrap_or(RegularRuleStatementInspectValue::Single("".to_string())),
        RegularRuleStatementInspect::HttpMethod => {
            return RegularRuleStatementInspectValue::Single(request.method().as_str().to_string())
        }
        RegularRuleStatementInspect::UriPath => {
            RegularRuleStatementInspectValue::Single(request.uri().path().to_string())
        }
        RegularRuleStatementInspect::QueryString => RegularRuleStatementInspectValue::Single(
            request.uri().query().unwrap_or("").to_string(),
        ),
        RegularRuleStatementInspect::AllHeaders {
            scope,
            content_filter,
        } => {
            let filtered_values: Vec<String> = match scope {
                RegularRuleStatementInspectTypeScope::All => {
                    let mut keys: Vec<String> = request
                        .headers()
                        .keys()
                        .filter_map(|h| filter_inspect_content(content_filter, h.to_string()))
                        .collect();
                    let values: Vec<String> = request
                        .headers()
                        .iter()
                        .map(|v| v.1.to_str().unwrap_or("").to_string())
                        .collect();

                    keys.extend_from_slice(&values);
                    keys
                }
                RegularRuleStatementInspectTypeScope::Keys => request
                    .headers()
                    .keys()
                    .filter_map(|k| filter_inspect_content(content_filter, k.to_string()))
                    .collect(),
                RegularRuleStatementInspectTypeScope::Values => request
                    .headers()
                    .iter()
                    .map(|v| v.1.to_str().unwrap_or("").to_string())
                    .collect(),
            };

            RegularRuleStatementInspectValue::All(filtered_values)
        }
        RegularRuleStatementInspect::Cookies {
            scope,
            content_filter,
        } => {
            let filtered_values: Vec<String> = match scope {
                RegularRuleStatementInspectTypeScope::All => {
                    let cookies: Vec<Cookie> = match request.cookies() {
                        Ok(cookies) => cookies.to_vec(),
                        Err(_) => return RegularRuleStatementInspectValue::All(Vec::new()),
                    };
                    let mut keys: Vec<String> = cookies
                        .iter()
                        .filter_map(|c| {
                            filter_inspect_content(content_filter, c.name().to_string())
                        })
                        .collect();
                    let values: Vec<String> =
                        cookies.iter().map(|c| c.value().to_string()).collect();

                    keys.extend_from_slice(&values);
                    keys
                }
                RegularRuleStatementInspectTypeScope::Keys => {
                    let cookies: Vec<Cookie> = match request.cookies() {
                        Ok(cookies) => cookies.to_vec(),
                        Err(_) => return RegularRuleStatementInspectValue::All(Vec::new()),
                    };
                    cookies
                        .iter()
                        .filter_map(|c| filter_inspect_content(content_filter, c.to_string()))
                        .collect()
                }
                RegularRuleStatementInspectTypeScope::Values => {
                    let cookies: Vec<Cookie> = match request.cookies() {
                        Ok(cookies) => cookies.to_vec(),
                        Err(_) => return RegularRuleStatementInspectValue::All(Vec::new()),
                    };
                    cookies.iter().map(|c| c.to_string()).collect()
                }
            };

            RegularRuleStatementInspectValue::All(filtered_values)
        }
    }
}

fn filter_inspect_content(
    content_filter: &RegularRuleStatementInspectTypeContentFilter,
    h: String,
) -> Option<String> {
    match content_filter {
        RegularRuleStatementInspectTypeContentFilter::Exclude { key } => {
            if h == *key {
                None
            } else {
                Some(h)
            }
        }
        RegularRuleStatementInspectTypeContentFilter::All => Some(h),
        RegularRuleStatementInspectTypeContentFilter::Include { key } => {
            if h != *key {
                None
            } else {
                Some(h)
            }
        }
    }
}

async fn proxy(data: Data<AegisState>, req: HttpRequest) -> HttpResponse {
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
        Err(_) => return HttpResponse::InternalServerError().body("Failed to fetch upstream url"),
    };

    let proxy_status = match StatusCode::from_u16(res.status().as_u16()) {
        Ok(code) => code,
        Err(_) => return HttpResponse::InternalServerError().body("Error from Aegis"),
    };
    let mut proxy_res = HttpResponse::build(proxy_status);
    for (name, value) in res.headers().iter() {
        proxy_res.insert_header((name.as_str(), value.to_str().unwrap_or("")));
    }

    // Copy the body from the target server's response
    let body = res.bytes().await.unwrap_or_default();
    proxy_res.body(body)
}
