use std::sync::Arc;

use actix_web::{web::Data, HttpRequest, HttpResponse};
use tokio::sync::Mutex;
use utils::{check_statement_match, fetch_statement_inspect, proxy};

use crate::clients;

use crate::config::{AegisConfig, AegisRule, RateBasedRuleKey, RegularRuleCondition, RuleAction};

mod utils;

// Constants
const REDIS_FIREWALL_BLOCK_KEY: &str = "blocked_requests";

#[derive(Clone, Debug)]
pub struct AegisState {
    pub config: Arc<Mutex<AegisConfig>>,
    pub redis_client: Option<clients::redis::RedisClient>,
    pub http_client: reqwest::Client,
}

#[derive(Debug)]
enum RegularRuleStatementInspectValue {
    Single(String),
    All(Vec<String>),
    Any(Vec<String>),
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
                    let value: RegularRuleStatementInspectValue =
                        fetch_statement_inspect(&statement.inspect, &req).await;
                    let statement_match: bool = check_statement_match(value, statement.clone());

                    // Negate statement if stated in config
                    let rule_match: bool = if statement.negate_statement {
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
                    continue;
                }
            }
            AegisRule::RateBased {
                limit,
                evaluation_window_seconds,
                key,
            } => {
                match key {
                    RateBasedRuleKey::SourceIp => {
                        let action = if let Some(ip_addr) = req.peer_addr() {
                            let ip = ip_addr.ip().to_string();
                            // try to set rate limit key in redis
                            if let Some(redis_client) = &data.redis_client {
                                // If error occurs while setting key in redis, skip this rule
                                let set_key = match redis_client.setnx(ip.clone(), limit).await {
                                    Ok(set_key) => set_key,
                                    Err(err) => {
                                        tracing::error!(
                                            "Error occured while setting key in redis: {}",
                                            err.to_string()
                                        );
                                        continue;
                                    }
                                };
                                if set_key {
                                    let set_key_expiry = match redis_client
                                        .expire(ip.clone(), evaluation_window_seconds)
                                        .await
                                    {
                                        Ok(set_key_expiry) => set_key_expiry,
                                        Err(err) => {
                                            tracing::error!("Error occured while setting key expiry in redis: {}", err.to_string());
                                            continue;
                                        }
                                    };
                                    if set_key_expiry {
                                        RuleAction::Allow
                                    } else {
                                        continue;
                                    }
                                } else {
                                    let remaining_limit =
                                        match redis_client.decr(ip.clone(), 1).await {
                                            Ok(remaining_limit) => remaining_limit,
                                            Err(err) => {
                                                tracing::error!(
                                                "Error occured while decrementing key in redis: {}",
                                                err.to_string()
                                            );
                                                continue;
                                            }
                                        };

                                    if remaining_limit <= 0 {
                                        RuleAction::Block
                                    } else {
                                        RuleAction::Allow
                                    }
                                }
                            } else {
                                continue; // Skip this rule if redis isnt configured
                            }
                        } else {
                            continue; // Skip this rule if we cant fetch the ip
                        };

                        action
                    }
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
            return res;
        }
        RuleAction::Block => return HttpResponse::Forbidden().body("Request blocked by firewall"),

        _ => return HttpResponse::Forbidden().body("Request blocked by firewall"),
    }
}
