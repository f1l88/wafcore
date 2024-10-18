use std::sync::Arc;

use actix_web::{web::Data, HttpRequest, HttpResponse};
use tokio::sync::Mutex;
use tokio::time;
use utils::proxy;

use crate::clients;

use crate::config::{AegisConfig, AegisRule, RuleAction};
use crate::rules::rate_based::check_rate_based_rule_match;
use crate::rules::regular::check_regular_rule_match;

mod tests;
mod utils;

#[derive(Clone, Debug)]
pub struct AegisState {
    pub config: Arc<Mutex<AegisConfig>>,
    pub redis_client: Option<clients::redis::RedisClient>,
    pub http_client: reqwest::Client,
    pub metrics: Option<clients::metrics::AegisMetrics>,
}

pub async fn root(data: Data<AegisState>, req: HttpRequest) -> HttpResponse {
    let req_start_time = time::Instant::now();
    if let Some(metrics_client) = &data.metrics {
        metrics_client.total_requests_counter.add(1, &[]);
    };
    let config = data.config.lock().await.clone();
    for rule in config.rules.clone() {
        let action = match rule {
            AegisRule::Regular {
                action,
                condition,
                statements,
            } => {
                let regular_rule_statement_match =
                    check_regular_rule_match(&req, condition, statements).await;

                if regular_rule_statement_match {
                    action
                } else {
                    continue;
                }
            }
            AegisRule::RateBased {
                limit,
                evaluation_window_seconds,
                key,
            } => {
                if let Some(action) =
                    check_rate_based_rule_match(&data, &req, limit, evaluation_window_seconds, key)
                        .await
                {
                    // Calculate the duration in milliseconds
                    let duration = req_start_time.elapsed().as_secs_f64() * 1000.0;
                    if let Some(metrics_client) = &data.metrics {
                        metrics_client.rate_limited_requests_counter.add(1, &[]);
                        metrics_client
                            .request_duration_histogram
                            .record(duration, &[]);
                    };
                    action
                } else {
                    continue;
                }
            }
        };

        match action {
            RuleAction::Allow => {
                // Calculate the duration in milliseconds
                let duration = req_start_time.elapsed().as_secs_f64() * 1000.0;
                if let Some(metrics_client) = &data.metrics {
                    metrics_client.allowed_requests_counter.add(1, &[]);
                    metrics_client
                        .request_duration_histogram
                        .record(duration, &[]);
                };
                let res: HttpResponse = proxy(data, req).await;
                return res;
            }
            RuleAction::Block => {
                // Calculate the duration in milliseconds
                let duration = req_start_time.elapsed().as_secs_f64() * 1000.0;
                if let Some(metrics_client) = &data.metrics {
                    metrics_client.blocked_requests_counter.add(1, &[]);
                    metrics_client
                        .request_duration_histogram
                        .record(duration, &[]);
                };
                return HttpResponse::Forbidden().body("Request blocked by firewall");
            }

            RuleAction::Count => {
                if let Some(metrics_client) = &data.metrics {
                    metrics_client.blocked_requests_counter.add(1, &[]);
                };
                continue;
            }
        }
    }

    match config.default_action {
        RuleAction::Allow => {
            // Calculate the duration in milliseconds
            let duration = req_start_time.elapsed().as_secs_f64() * 1000.0;
            if let Some(metrics_client) = &data.metrics {
                metrics_client.allowed_requests_counter.add(1, &[]);
                metrics_client
                    .request_duration_histogram
                    .record(duration, &[]);
            };
            let res: HttpResponse = proxy(data, req).await;
            res
        }
        RuleAction::Block => {
            // Calculate the duration in milliseconds
            let duration = req_start_time.elapsed().as_secs_f64() * 1000.0;
            if let Some(metrics_client) = &data.metrics {
                metrics_client.blocked_requests_counter.add(1, &[]);
                metrics_client
                    .request_duration_histogram
                    .record(duration, &[]);
            };
            HttpResponse::Forbidden().body("Request blocked by firewall")
        }

        _ => {
            // Calculate the duration in milliseconds
            let duration = req_start_time.elapsed().as_secs_f64() * 1000.0;
            if let Some(metrics_client) = &data.metrics {
                metrics_client.blocked_requests_counter.add(1, &[]);
                metrics_client
                    .request_duration_histogram
                    .record(duration, &[]);
            };
            HttpResponse::Forbidden().body("Request blocked by firewall")
        }
    }
}
