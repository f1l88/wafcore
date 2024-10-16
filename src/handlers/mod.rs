use std::sync::Arc;

use actix_web::{web::Data, HttpRequest, HttpResponse};
use tokio::sync::Mutex;
use utils::proxy;

use crate::clients;

use crate::config::{AegisConfig, AegisRule, RuleAction};
use crate::rules::rate_based::check_rate_based_rule_match;
use crate::rules::regular::check_regular_rule_match;

mod utils;
mod tests;

// Constants
const REDIS_FIREWALL_BLOCK_KEY: &str = "blocked_requests";

#[derive(Clone, Debug)]
pub struct AegisState {
    pub config: Arc<Mutex<AegisConfig>>,
    pub redis_client: Option<clients::redis::RedisClient>,
    pub http_client: reqwest::Client,
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
                    action
                } else {
                    continue;
                }
            }
        };

        match action {
            RuleAction::Allow => {
                let res: HttpResponse = proxy(data, req).await;
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
            let res: HttpResponse = proxy(data, req).await;
            res
        }
        RuleAction::Block => HttpResponse::Forbidden().body("Request blocked by firewall"),

        _ => HttpResponse::Forbidden().body("Request blocked by firewall"),
    }
}
