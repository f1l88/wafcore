use actix_web::{web::Data, HttpRequest};

use crate::{
    config::{RateBasedRuleKey, RuleAction},
    handlers::AegisState,
};

pub async fn check_rate_based_rule_match(
    data: &Data<AegisState>,
    req: &HttpRequest,
    limit: i64,
    evaluation_window_seconds: i64,
    key: RateBasedRuleKey,
) -> Option<RuleAction> {
    let action = match key {
        RateBasedRuleKey::SourceIp => {
            if let Some(ip_addr) = req.peer_addr() {
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
                            return None;
                        }
                    };
                    if set_key {
                        let set_key_expiry = match redis_client
                            .expire(ip.clone(), evaluation_window_seconds)
                            .await
                        {
                            Ok(set_key_expiry) => set_key_expiry,
                            Err(err) => {
                                tracing::error!(
                                    "Error occured while setting key expiry in redis: {}",
                                    err.to_string()
                                );
                                return None;
                            }
                        };
                        if set_key_expiry {
                            RuleAction::Allow
                        } else {
                            return None;
                        }
                    } else {
                        let remaining_limit = match redis_client.decr(ip.clone(), 1).await {
                            Ok(remaining_limit) => remaining_limit,
                            Err(err) => {
                                tracing::error!(
                                    "Error occured while decrementing key in redis: {}",
                                    err.to_string()
                                );
                                return None;
                            }
                        };

                        if remaining_limit <= 0 {
                            RuleAction::Block
                        } else {
                            RuleAction::Allow
                        }
                    }
                } else {
                    return None; // Skip this rule if redis isnt configured
                }
            } else {
                return None; // Skip this rule if we cant fetch the ip
            }
        }
    };

    Some(action)
}
