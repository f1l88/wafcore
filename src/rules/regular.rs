use actix_web::HttpRequest;

use crate::config::{RegularRuleCondition, RegularRuleStatement};

use super::statements::{
    check_statement_match, fetch_statement_inspect, RegularRuleStatementInspectValue,
};

pub async fn check_regular_rule_match(
    req: &HttpRequest,
    condition: RegularRuleCondition,
    statements: Vec<RegularRuleStatement>,
) -> bool {
    let mut statement_results: Vec<bool> = vec![];
    for statement in statements {
        let value: RegularRuleStatementInspectValue =
            fetch_statement_inspect(&statement.inspect, req).await;

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
        RegularRuleCondition::One => statement_results.iter().any(|r| *r),
        RegularRuleCondition::All => statement_results.iter().all(|r| *r),
        RegularRuleCondition::None => !statement_results.iter().all(|r| !(*r)),
    };

    is_match
}
