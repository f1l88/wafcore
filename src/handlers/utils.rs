use std::collections::HashMap;

use actix_web::{
    cookie::Cookie,
    http::{
        header::{HeaderName, HeaderValue},
        StatusCode,
    },
    web::Data,
    HttpRequest, HttpResponse,
};
use regex::Regex;
use url::Url;

use crate::config::{
    RegularRuleStatement, RegularRuleStatementInspect,
    RegularRuleStatementInspectTypeContentFilter, RegularRuleStatementInspectTypeScope,
    RegularRuleStatementIpSetSource, RegularRuleStatementIpSetSourcePosition,
    RegularRuleStatementMatchType,
};

use super::{AegisState, RegularRuleStatementInspectValue};

pub fn check_statement_match(
    value: RegularRuleStatementInspectValue,
    statement: RegularRuleStatement,
) -> bool {
    match statement.match_type {
        RegularRuleStatementMatchType::StartsWith => match value {
            RegularRuleStatementInspectValue::Single(val) => {
                val.starts_with(&statement.match_string)
            }
            RegularRuleStatementInspectValue::All(vec) => {
                if vec.is_empty() {
                    false
                } else {
                    vec.iter()
                        .all(|val| val.starts_with(&statement.match_string))
                }
            }
            RegularRuleStatementInspectValue::Any(vec) => vec
                .iter()
                .any(|val| val.starts_with(&statement.match_string)),
        },
        RegularRuleStatementMatchType::EndsWith => match value {
            RegularRuleStatementInspectValue::Single(val) => val.ends_with(&statement.match_string),
            RegularRuleStatementInspectValue::All(vec) => {
                if vec.is_empty() {
                    false
                } else {
                    vec.iter().all(|val| val.ends_with(&statement.match_string))
                }
            }
            RegularRuleStatementInspectValue::Any(vec) => {
                vec.iter().any(|val| val.ends_with(&statement.match_string))
            }
        },
        RegularRuleStatementMatchType::Contains => match value {
            RegularRuleStatementInspectValue::Single(val) => val.contains(&statement.match_string),
            RegularRuleStatementInspectValue::All(vec) => {
                if vec.is_empty() {
                    false
                } else {
                    vec.iter().all(|val| val.contains(&statement.match_string))
                }
            }
            RegularRuleStatementInspectValue::Any(vec) => {
                vec.iter().any(|val| val.contains(&statement.match_string))
            }
        },
        RegularRuleStatementMatchType::Exact => match value {
            RegularRuleStatementInspectValue::Single(val) => val == statement.match_string,
            RegularRuleStatementInspectValue::All(vec) => {
                if vec.is_empty() {
                    false
                } else {
                    vec.iter().all(|val| *val == statement.match_string)
                }
            }
            RegularRuleStatementInspectValue::Any(vec) => {
                vec.iter().any(|val| *val == statement.match_string)
            }
        },
        RegularRuleStatementMatchType::Regex => match value {
            RegularRuleStatementInspectValue::Single(val) => {
                if let Ok(re) = Regex::new(&format!(r"{}", statement.match_string)) {
                    re.is_match(&val)
                } else {
                    false
                }
            }
            RegularRuleStatementInspectValue::All(vec) => vec.iter().all(|val| {
                if vec.is_empty() {
                    false
                } else {
                    if let Ok(re) = Regex::new(&format!(r"{}", statement.match_string)) {
                        re.is_match(&val)
                    } else {
                        false
                    }
                }
            }),
            RegularRuleStatementInspectValue::Any(vec) => vec.iter().any(|val| {
                if let Ok(re) = Regex::new(&format!(r"{}", statement.match_string)) {
                    re.is_match(&val)
                } else {
                    false
                }
            }),
        },
    }
}

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

    let body = res.bytes().await.unwrap_or_default();
    proxy_res.body(body)
}

pub async fn fetch_statement_inspect(
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
                    // filter the headers first if we are matching against all keys and values
                    let filtered_headers: Vec<(&HeaderName, &HeaderValue)> = request
                        .headers()
                        .iter()
                        .filter_map(|h| {
                            if let Some(_) =
                                filter_inspect_header_content(content_filter, h.0.to_string())
                            {
                                Some(h)
                            } else {
                                None
                            }
                        })
                        .collect();
                    let mut keys: Vec<String> =
                        filtered_headers.iter().map(|h| h.0.to_string()).collect();
                    let values: Vec<String> = filtered_headers
                        .iter()
                        .map(|h| h.1.to_str().unwrap_or("").to_string())
                        .collect();

                    keys.extend_from_slice(&values);
                    keys
                }
                RegularRuleStatementInspectTypeScope::Keys => request
                    .headers()
                    .keys()
                    .filter_map(|k| filter_inspect_header_content(content_filter, k.to_string()))
                    .collect(),
                RegularRuleStatementInspectTypeScope::Values => {
                    let filtered_headers: Vec<(&HeaderName, &HeaderValue)> = request
                        .headers()
                        .iter()
                        .filter_map(|h| {
                            if let Some(_) =
                                filter_inspect_header_content(content_filter, h.0.to_string())
                            {
                                Some(h)
                            } else {
                                None
                            }
                        })
                        .collect();

                    filtered_headers
                        .iter()
                        .map(|h| h.1.to_str().unwrap_or("").to_string())
                        .collect()
                }
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
                            filter_inspect_header_content(content_filter, c.name().to_string())
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
                        .filter_map(|c| {
                            filter_inspect_header_content(content_filter, c.to_string())
                        })
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
        RegularRuleStatementInspect::IpSet { source } => match source {
            RegularRuleStatementIpSetSource::SourceIp => {
                if let Some(ip_addr) = request.peer_addr() {
                    RegularRuleStatementInspectValue::Single(ip_addr.ip().to_string())
                } else {
                    RegularRuleStatementInspectValue::Single(String::new())
                }
            }
            RegularRuleStatementIpSetSource::Header { name, position } => {
                let value = match request.headers().get(name) {
                    Some(v) => v,
                    None => return RegularRuleStatementInspectValue::Single(String::new()),
                };

                let ips = match value.to_str() {
                    Ok(v) => v
                        .split(",")
                        .map(|v| v.trim().to_string())
                        .collect::<Vec<String>>(),
                    Err(_) => return RegularRuleStatementInspectValue::Single(String::new()),
                };

                match position {
                    RegularRuleStatementIpSetSourcePosition::First => {
                        RegularRuleStatementInspectValue::Single(
                            ips.first().unwrap_or(&String::new()).to_string(),
                        )
                    }
                    RegularRuleStatementIpSetSourcePosition::Last => {
                        RegularRuleStatementInspectValue::Single(
                            ips.last().unwrap_or(&String::new()).to_string(),
                        )
                    }
                    RegularRuleStatementIpSetSourcePosition::Any => {
                        RegularRuleStatementInspectValue::Any(ips)
                    }
                }
            }
        },
    }
}

pub fn filter_inspect_header_content(
    content_filter: &RegularRuleStatementInspectTypeContentFilter,
    h: String,
) -> Option<String> {
    // We need to convert the key to lowercase because actix web reads headers as lowercase
    match content_filter {
        RegularRuleStatementInspectTypeContentFilter::Exclude { key } => {
            if h == *key.to_lowercase() {
                None
            } else {
                Some(h)
            }
        }
        RegularRuleStatementInspectTypeContentFilter::All => Some(h),
        RegularRuleStatementInspectTypeContentFilter::Include { key } => {
            if h != *key.to_lowercase() {
                None
            } else {
                Some(h)
            }
        }
    }
}
