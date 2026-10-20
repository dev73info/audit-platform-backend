//! 规则求值引擎：把规则组 DSL 求值成审核结论。
//!
//! 纯函数模块：不碰数据库、不碰网络。管理端的「规则试跑」与后台的「真实执行」
//! 都调用这里的 [`evaluate`]，保证试跑结果与线上结果一致。
//!
//! 语义见 `doc/API.md` 第四章：
//!
//! - 规则组按 `priority` 升序求值，`stop_on_hit` 为真时命中即停。
//! - 规则组 `logic` 为 `AND`（全部条件项命中）或 `OR`（任一条件项命中）。
//! - 单组出错（操作符未知、逻辑非法等）时跳过该组继续下一组，不影响其他组。
//! - 全部未命中时取 `default_result`。

use std::cmp::Ordering;

use serde_json::Value;

use crate::models::rule::{
    EvalContext, OPERATORS, RuleGroupSpec, RuleGroupTrace, RuleItemSpec, RuleItemTrace,
};

/// 正则表达式最大长度。超长直接判定为不命中，避免 ReDoS。
const MAX_REGEX_LEN: usize = 512;

/// 求值全部规则组，返回 `(最终结论, 求值轨迹)`。
///
/// 规则组按 `priority` 升序求值（优先级数字小者在前）。命中且 `stop_on_hit` 为真时
/// 立即停止后续规则组，被跳过的组在轨迹里标记 `skipped`。
pub fn evaluate(
    groups: &[RuleGroupSpec],
    context: &EvalContext,
    default_result: &str,
) -> (String, Vec<RuleGroupTrace>) {
    let mut traces: Vec<RuleGroupTrace> = Vec::with_capacity(groups.len());

    // 稳定排序：优先级相同时保持配置里的先后顺序。
    let mut ordered: Vec<&RuleGroupSpec> = groups.iter().collect();
    ordered.sort_by_key(|group| group.priority);

    let mut final_result = default_result.to_string();

    for group in ordered {
        // 非 ACTIVE 的规则组不参与求值。
        if !is_group_enabled(group) {
            traces.push(skipped_trace(group));
            continue;
        }

        // 规则组配置有问题：跳过该组，继续下一组。
        if let Err(reason) = validate_group(group) {
            tracing::warn!(rule = %group.name, reason = %reason, "规则组配置有误，已跳过该组");
            traces.push(skipped_trace(group));
            continue;
        }

        let items = evaluate_items(group, context);
        let hit = match group.logic.trim().to_ascii_uppercase().as_str() {
            "OR" => items.iter().any(|item| item.hit),
            _ => items.iter().all(|item| item.hit),
        };

        traces.push(RuleGroupTrace {
            rule_id: group.id,
            rule: group.name.clone(),
            logic: group.logic.clone(),
            hit,
            skipped: false,
            items,
        });

        if hit {
            final_result = group.on_hit_result.clone();
            if group.stop_on_hit {
                break;
            }
        }
    }

    (final_result, traces)
}

/// 求值单个条件项。操作符未知时返回 `None`（视为配置错误）。
pub fn evaluate_item(item: &RuleItemSpec, context: &EvalContext) -> Option<RuleItemTrace> {
    let operator = item.operator.trim().to_ascii_lowercase();
    if !OPERATORS.contains(&operator.as_str()) {
        return None;
    }

    let actual = context.resolve(item.field.trim());
    let mut hit = apply_operator(&operator, actual.as_ref(), &item.value, item.case_sensitive);
    if item.negate {
        hit = !hit;
    }

    Some(RuleItemTrace {
        field: item.field.clone(),
        operator: item.operator.clone(),
        actual: actual.unwrap_or(Value::Null),
        expected: item.value.clone(),
        hit,
    })
}

/// 规则组是否参与求值。状态缺省视为启用。
fn is_group_enabled(group: &RuleGroupSpec) -> bool {
    match group.status.as_deref() {
        None => true,
        Some(status) => status.trim().eq_ignore_ascii_case("ACTIVE"),
    }
}

/// 规则组级别的配置校验。通过返回 `Ok(())`，否则给出中文原因。
fn validate_group(group: &RuleGroupSpec) -> Result<(), String> {
    let logic = group.logic.trim().to_ascii_uppercase();
    if logic != "AND" && logic != "OR" {
        return Err(format!(
            "规则逻辑只能是 AND 或 OR，当前为「{}」",
            group.logic
        ));
    }
    if group.items.is_empty() {
        return Err("规则组至少要有一个条件项".to_string());
    }
    for item in &group.items {
        let operator = item.operator.trim().to_ascii_lowercase();
        if !OPERATORS.contains(&operator.as_str()) {
            return Err(format!("不支持的操作符「{}」", item.operator));
        }
    }
    Ok(())
}

/// 构造一条「被跳过」的轨迹。
fn skipped_trace(group: &RuleGroupSpec) -> RuleGroupTrace {
    RuleGroupTrace {
        rule_id: group.id,
        rule: group.name.clone(),
        logic: group.logic.clone(),
        hit: false,
        skipped: true,
        items: Vec::new(),
    }
}

/// 求值规则组里的全部条件项。
fn evaluate_items(group: &RuleGroupSpec, context: &EvalContext) -> Vec<RuleItemTrace> {
    let mut items = Vec::with_capacity(group.items.len());
    for item in &group.items {
        if let Some(trace) = evaluate_item(item, context) {
            items.push(trace);
        }
    }
    items
}

/// 按操作符分派。
fn apply_operator(
    operator: &str,
    actual: Option<&Value>,
    expected: &Value,
    case_sensitive: bool,
) -> bool {
    match operator {
        // 空值
        "is_null" => actual.is_none_or(|value| value.is_null()),
        "is_not_null" => actual.is_some_and(|value| !value.is_null()),
        "is_empty" => is_empty(actual),
        "is_not_empty" => !is_empty(actual),

        // 比较
        "eq" => loose_eq(actual, expected, case_sensitive),
        "ne" => !loose_eq(actual, expected, case_sensitive),
        "gt" | "gte" | "lt" | "lte" => compare_general(actual, expected, operator, case_sensitive),
        "between" => between(actual, expected, case_sensitive),

        // 集合
        "in" | "label_in" | "risk_in" => in_list(actual, expected, case_sensitive),
        "not_in" => !in_list(actual, expected, case_sensitive),
        "contains" => contains(actual, expected, case_sensitive),
        "not_contains" => !contains(actual, expected, case_sensitive),
        "contains_any" => contains_any(actual, expected, case_sensitive),
        "contains_all" => contains_all(actual, expected, case_sensitive),

        // 文本
        "starts_with" => starts_or_ends(actual, expected, case_sensitive, true),
        "ends_with" => starts_or_ends(actual, expected, case_sensitive, false),
        "regex" => regex_match(actual, expected, case_sensitive),
        "length_gt" | "length_lt" => compare_length(actual, expected, operator),

        // 模型
        "score_gt" | "score_lt" => compare_general(actual, expected, operator, case_sensitive),

        _ => false,
    }
}

/// 空值判定：缺失、空字符串、空数组、空对象都算空。
fn is_empty(actual: Option<&Value>) -> bool {
    match actual {
        None => true,
        Some(Value::Null) => true,
        Some(Value::String(text)) => text.is_empty(),
        Some(Value::Array(items)) => items.is_empty(),
        Some(Value::Object(fields)) => fields.is_empty(),
        Some(_) => false,
    }
}

/// 宽松相等：数字按数字比，字符串按字符串比（可忽略大小写），其余按结构比。
fn loose_eq(actual: Option<&Value>, expected: &Value, case_sensitive: bool) -> bool {
    let Some(left) = actual else {
        // 字段缺失时，只有期望值是 null 才算相等。
        return expected.is_null();
    };
    let right = expected;

    if let (Some(left_num), Some(right_num)) = (as_number(left), as_number(right)) {
        return left_num == right_num;
    }

    match (left, right) {
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len()
                && a.iter()
                    .zip(b.iter())
                    .all(|(x, y)| loose_eq(Some(x), y, case_sensitive))
        }
        (Value::Object(a), Value::Object(b)) => a == b,
        (Value::Null, Value::Null) => true,
        _ => {
            let left_text = as_text(left);
            let right_text = as_text(right);
            if case_sensitive {
                left_text == right_text
            } else {
                left_text.eq_ignore_ascii_case(&right_text)
            }
        }
    }
}

/// 通用比较：两边都能当数字就比数字，否则比字符串。
fn compare_general(
    actual: Option<&Value>,
    expected: &Value,
    operator: &str,
    case_sensitive: bool,
) -> bool {
    let Some(order) = compare_values(actual, expected, case_sensitive) else {
        return false;
    };
    match operator {
        "gt" | "score_gt" => order == Ordering::Greater,
        "gte" => order != Ordering::Less,
        "lt" | "score_lt" => order == Ordering::Less,
        "lte" => order != Ordering::Greater,
        _ => false,
    }
}

/// 比较两个值，返回 `None` 表示无法比较（缺值或类型不可比）。
fn compare_values(
    actual: Option<&Value>,
    expected: &Value,
    case_sensitive: bool,
) -> Option<Ordering> {
    let left = actual?;
    if let (Some(left_num), Some(right_num)) = (as_number(left), as_number(expected)) {
        return left_num.partial_cmp(&right_num);
    }
    let left_text = as_text(left);
    let right_text = as_text(expected);
    let (left_text, right_text) = if case_sensitive {
        (left_text, right_text)
    } else {
        (left_text.to_lowercase(), right_text.to_lowercase())
    };
    Some(left_text.cmp(&right_text))
}

/// `between`：期望值是 `[下限, 上限]` 数组，闭区间。
fn between(actual: Option<&Value>, expected: &Value, case_sensitive: bool) -> bool {
    let Some(bounds) = expected.as_array() else {
        return false;
    };
    if bounds.len() != 2 {
        return false;
    }
    let lower = compare_values(actual, &bounds[0], case_sensitive);
    let upper = compare_values(actual, &bounds[1], case_sensitive);
    match (lower, upper) {
        (Some(lower), Some(upper)) => lower != Ordering::Less && upper != Ordering::Greater,
        _ => false,
    }
}

/// `in` / `label_in` / `risk_in`：期望值是数组，实际值命中其中之一。
fn in_list(actual: Option<&Value>, expected: &Value, case_sensitive: bool) -> bool {
    let Some(items) = expected.as_array() else {
        return false;
    };
    let Some(left) = actual else {
        return false;
    };
    items
        .iter()
        .any(|item| loose_eq(Some(left), item, case_sensitive))
}

/// `contains`：实际值是字符串时做子串匹配；实际值是数组时做元素匹配。
fn contains(actual: Option<&Value>, expected: &Value, case_sensitive: bool) -> bool {
    let Some(left) = actual else {
        return false;
    };
    match left {
        Value::Array(items) => items
            .iter()
            .any(|item| loose_eq(Some(item), expected, case_sensitive)),
        _ => {
            let left_text = as_text(left);
            let right_text = as_text(expected);
            if case_sensitive {
                left_text.contains(&right_text)
            } else {
                left_text
                    .to_lowercase()
                    .contains(&right_text.to_lowercase())
            }
        }
    }
}

/// `contains_any`：期望值是数组，实际值命中其中任意一个即成立。
fn contains_any(actual: Option<&Value>, expected: &Value, case_sensitive: bool) -> bool {
    let Some(items) = expected.as_array() else {
        return false;
    };
    let Some(left) = actual else {
        return false;
    };
    match left {
        Value::Array(values) => values.iter().any(|value| {
            items
                .iter()
                .any(|item| loose_eq(Some(value), item, case_sensitive))
        }),
        _ => {
            let left_text = as_text(left);
            items.iter().any(|item| {
                let right_text = as_text(item);
                if case_sensitive {
                    left_text.contains(&right_text)
                } else {
                    left_text
                        .to_lowercase()
                        .contains(&right_text.to_lowercase())
                }
            })
        }
    }
}

/// `contains_all`：期望值是数组，实际值必须包含其中全部元素。
fn contains_all(actual: Option<&Value>, expected: &Value, case_sensitive: bool) -> bool {
    let Some(items) = expected.as_array() else {
        return false;
    };
    let Some(left) = actual else {
        return false;
    };
    match left {
        Value::Array(values) => items.iter().all(|item| {
            values
                .iter()
                .any(|value| loose_eq(Some(value), item, case_sensitive))
        }),
        _ => {
            let left_text = as_text(left);
            items.iter().all(|item| {
                let right_text = as_text(item);
                if case_sensitive {
                    left_text.contains(&right_text)
                } else {
                    left_text
                        .to_lowercase()
                        .contains(&right_text.to_lowercase())
                }
            })
        }
    }
}

/// `starts_with` / `ends_with`。
fn starts_or_ends(
    actual: Option<&Value>,
    expected: &Value,
    case_sensitive: bool,
    prefix: bool,
) -> bool {
    let Some(left) = actual else {
        return false;
    };
    let Value::String(left_text) = left else {
        return false;
    };
    let right_text = as_text(expected);
    let (left_text, right_text) = if case_sensitive {
        (left_text.clone(), right_text)
    } else {
        (left_text.to_lowercase(), right_text.to_lowercase())
    };
    if prefix {
        left_text.starts_with(&right_text)
    } else {
        left_text.ends_with(&right_text)
    }
}

/// `regex`：期望值是正则表达式。编译失败或超长一律判定为不命中。
fn regex_match(actual: Option<&Value>, expected: &Value, case_sensitive: bool) -> bool {
    let Some(left) = actual else {
        return false;
    };
    let Value::String(left_text) = left else {
        return false;
    };
    let pattern = as_text(expected);
    if pattern.is_empty() || pattern.chars().count() > MAX_REGEX_LEN {
        return false;
    }
    let full_pattern = if case_sensitive {
        pattern
    } else {
        format!("(?i){pattern}")
    };
    match regex::Regex::new(&full_pattern) {
        Ok(re) => re.is_match(left_text),
        Err(err) => {
            tracing::warn!(error = %err, "正则表达式编译失败，该条件项判定为不命中");
            false
        }
    }
}

/// `length_gt` / `length_lt`：比较字符串或数组的长度。
fn compare_length(actual: Option<&Value>, expected: &Value, operator: &str) -> bool {
    let Some(left) = actual else {
        return false;
    };
    let length = match left {
        Value::String(text) => text.chars().count() as f64,
        Value::Array(items) => items.len() as f64,
        Value::Object(fields) => fields.len() as f64,
        _ => 0.0,
    };
    let Some(right) = as_number(expected) else {
        return false;
    };
    match operator {
        "length_gt" => length > right,
        "length_lt" => length < right,
        _ => false,
    }
}

/// 取数值：数字直接取，字符串能解析成数字也取。
fn as_number(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.trim().parse::<f64>().ok(),
        _ => None,
    }
}

/// 取文本形式。
fn as_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number.to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// 构造一个只带文本的上下文。
    fn context_with_text(text: &str) -> EvalContext {
        EvalContext {
            media_text: text.to_string(),
            media_text_len: text.chars().count(),
            media_count: 1,
            media_types: vec!["text".to_string()],
            ..EvalContext::default()
        }
    }

    /// 构造一个条件项。
    fn item(field: &str, operator: &str, value: Value) -> RuleItemSpec {
        RuleItemSpec {
            field: field.to_string(),
            operator: operator.to_string(),
            value,
            case_sensitive: false,
            negate: false,
            sort_order: 0,
        }
    }

    /// 求值单个条件项并返回是否命中。
    fn hit(item: &RuleItemSpec, context: &EvalContext) -> bool {
        evaluate_item(item, context).expect("操作符应当合法").hit
    }

    #[test]
    fn eq_and_ne() {
        let context = context_with_text("hello");
        assert!(hit(&item("media.text", "eq", json!("hello")), &context));
        assert!(!hit(&item("media.text", "eq", json!("world")), &context));
        assert!(hit(&item("media.text", "ne", json!("world")), &context));
        // 数字与数字字符串按数值相等处理。
        assert!(hit(&item("media.count", "eq", json!("1")), &context));
    }

    #[test]
    fn gt_gte_lt_lte() {
        let context = EvalContext {
            media_text_len: 18,
            media_count: 3,
            ..EvalContext::default()
        };
        assert!(hit(&item("media.text_len", "gt", json!(10)), &context));
        assert!(hit(&item("media.text_len", "gte", json!(18)), &context));
        assert!(hit(&item("media.text_len", "lt", json!(20)), &context));
        assert!(hit(&item("media.text_len", "lte", json!(18)), &context));
        assert!(!hit(&item("media.text_len", "gt", json!(18)), &context));
    }

    #[test]
    fn between_uses_closed_interval() {
        let context = EvalContext {
            model_score: Some(0.5),
            ..EvalContext::default()
        };
        assert!(hit(
            &item("model.score", "between", json!([0.2, 0.95])),
            &context
        ));
        assert!(!hit(
            &item("model.score", "between", json!([0.6, 0.95])),
            &context
        ));
    }

    #[test]
    fn in_and_not_in() {
        let context = EvalContext {
            model_label: Some("porn".to_string()),
            ..EvalContext::default()
        };
        assert!(hit(
            &item("model.label", "in", json!(["porn", "terror"])),
            &context
        ));
        assert!(hit(&item("model.label", "not_in", json!(["ad"])), &context));
    }

    #[test]
    fn contains_and_not_contains() {
        let context = context_with_text("这是一段包含违禁词A的文本");
        assert!(hit(
            &item("media.text", "contains", json!("违禁词A")),
            &context
        ));
        assert!(!hit(
            &item("media.text", "contains", json!("不存在")),
            &context
        ));
        assert!(hit(
            &item("media.text", "not_contains", json!("不存在")),
            &context
        ));
    }

    #[test]
    fn contains_any_and_contains_all() {
        let context = context_with_text("abc");
        assert!(hit(
            &item("media.text", "contains_any", json!(["x", "b"])),
            &context
        ));
        assert!(!hit(
            &item("media.text", "contains_any", json!(["x", "y"])),
            &context
        ));
        assert!(hit(
            &item("media.text", "contains_all", json!(["a", "c"])),
            &context
        ));
        assert!(!hit(
            &item("media.text", "contains_all", json!(["a", "z"])),
            &context
        ));
    }

    #[test]
    fn starts_with_and_ends_with() {
        let context = context_with_text("hello world");
        assert!(hit(
            &item("media.text", "starts_with", json!("hello")),
            &context
        ));
        assert!(hit(
            &item("media.text", "ends_with", json!("world")),
            &context
        ));
        assert!(!hit(
            &item("media.text", "starts_with", json!("world")),
            &context
        ));
    }

    #[test]
    fn regex_matches_and_invalid_pattern_is_not_hit() {
        let context = context_with_text("abc123");
        assert!(hit(&item("media.text", "regex", json!("[0-9]+")), &context));
        // 非法正则：判定为不命中，且不 panic。
        assert!(!hit(&item("media.text", "regex", json!("([a-z")), &context));
        // 超长正则：判定为不命中。
        let long = "a".repeat(MAX_REGEX_LEN + 1);
        assert!(!hit(&item("media.text", "regex", json!(long)), &context));
    }

    #[test]
    fn length_operators() {
        let context = context_with_text("12345");
        assert!(hit(&item("media.text", "length_gt", json!(3)), &context));
        assert!(hit(&item("media.text", "length_lt", json!(10)), &context));
        assert!(!hit(&item("media.text", "length_gt", json!(5)), &context));
    }

    #[test]
    fn null_and_empty_operators() {
        let context = EvalContext {
            ext: serde_json::Map::new(),
            ..EvalContext::default()
        };
        // ext.user_id 不存在
        assert!(hit(&item("ext.user_id", "is_null", json!(null)), &context));
        assert!(!hit(
            &item("ext.user_id", "is_not_null", json!(null)),
            &context
        ));
        assert!(hit(&item("ext.user_id", "is_empty", json!(null)), &context));

        let mut ext = serde_json::Map::new();
        ext.insert("name".to_string(), json!(""));
        let context = EvalContext {
            ext,
            ..EvalContext::default()
        };
        assert!(!hit(&item("ext.name", "is_null", json!(null)), &context));
        assert!(hit(&item("ext.name", "is_not_null", json!(null)), &context));
        assert!(hit(&item("ext.name", "is_empty", json!(null)), &context));
        assert!(!hit(
            &item("ext.name", "is_not_empty", json!(null)),
            &context
        ));
    }

    #[test]
    fn model_operators() {
        let context = EvalContext {
            model_label: Some("porn".to_string()),
            model_score: Some(0.97),
            model_risk_level: Some("high".to_string()),
            ..EvalContext::default()
        };
        assert!(hit(&item("model.score", "score_gt", json!(0.9)), &context));
        assert!(hit(&item("model.score", "score_lt", json!(0.99)), &context));
        assert!(hit(
            &item("model.label", "label_in", json!(["porn", "ad"])),
            &context
        ));
        assert!(hit(
            &item("model.risk_level", "risk_in", json!(["high", "medium"])),
            &context
        ));
    }

    #[test]
    fn negate_and_case_sensitive() {
        let context = context_with_text("Hello");
        let mut spec = item("media.text", "contains", json!("hello"));
        assert!(hit(&spec, &context));
        spec.case_sensitive = true;
        assert!(!hit(&spec, &context));
        spec.case_sensitive = false;
        spec.negate = true;
        assert!(!hit(&spec, &context));
    }

    #[test]
    fn unknown_operator_returns_none() {
        let context = context_with_text("x");
        assert!(evaluate_item(&item("media.text", "unknown_op", json!(1)), &context).is_none());
    }

    /// 构造一个规则组。
    fn group(
        name: &str,
        priority: i32,
        logic: &str,
        on_hit: &str,
        items: Vec<RuleItemSpec>,
    ) -> RuleGroupSpec {
        RuleGroupSpec {
            id: Some(1),
            name: name.to_string(),
            priority,
            logic: logic.to_string(),
            stop_on_hit: true,
            on_hit_result: on_hit.to_string(),
            status: Some("ACTIVE".to_string()),
            items,
        }
    }

    #[test]
    fn evaluate_returns_default_when_nothing_hits() {
        let context = context_with_text("正常内容");
        let groups = vec![group(
            "高危词",
            10,
            "OR",
            "REJECT",
            vec![item("media.text", "contains", json!("违禁词"))],
        )];
        let (result, traces) = evaluate(&groups, &context, "REVIEW");
        assert_eq!(result, "REVIEW");
        assert_eq!(traces.len(), 1);
        assert!(!traces[0].hit);
    }

    #[test]
    fn evaluate_hits_by_priority_and_stops() {
        let context = context_with_text("含违禁词A");
        let mut low = group(
            "低优先级",
            20,
            "OR",
            "PASS",
            vec![item("media.text", "contains", json!("违禁词A"))],
        );
        low.id = Some(2);
        let high = group(
            "高优先级",
            10,
            "OR",
            "REJECT",
            vec![item("media.text", "contains", json!("违禁词A"))],
        );
        let (result, traces) = evaluate(&[low, high], &context, "REVIEW");
        assert_eq!(result, "REJECT");
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].rule, "高优先级");
        assert!(traces[0].hit);
    }

    #[test]
    fn evaluate_and_logic_requires_all_items() {
        let context = EvalContext {
            model_score: Some(0.1),
            media_count: 2,
            ..EvalContext::default()
        };
        let groups = vec![group(
            "低风险快速通过",
            10,
            "AND",
            "PASS",
            vec![
                item("model.score", "lt", json!(0.2)),
                item("media.count", "lte", json!(9)),
            ],
        )];
        let (result, _) = evaluate(&groups, &context, "REVIEW");
        assert_eq!(result, "PASS");

        let groups = vec![group(
            "低风险快速通过",
            10,
            "AND",
            "PASS",
            vec![
                item("model.score", "lt", json!(0.2)),
                item("media.count", "lte", json!(1)),
            ],
        )];
        let (result, _) = evaluate(&groups, &context, "REVIEW");
        assert_eq!(result, "REVIEW");
    }

    #[test]
    fn evaluate_skips_broken_group_and_continues() {
        let context = context_with_text("命中");
        let broken = group(
            "坏规则",
            10,
            "OR",
            "REJECT",
            vec![item("media.text", "not_an_operator", json!(1))],
        );
        let good = group(
            "好规则",
            20,
            "OR",
            "REJECT",
            vec![item("media.text", "contains", json!("命中"))],
        );
        let (result, traces) = evaluate(&[broken, good], &context, "REVIEW");
        assert_eq!(result, "REJECT");
        assert_eq!(traces.len(), 2);
        assert!(traces[0].skipped);
        assert!(!traces[0].hit);
        assert!(traces[1].hit);
    }

    #[test]
    fn evaluate_skips_inactive_group() {
        let context = context_with_text("命中");
        let mut inactive = group(
            "停用规则",
            10,
            "OR",
            "REJECT",
            vec![item("media.text", "contains", json!("命中"))],
        );
        inactive.status = Some("PAUSED".to_string());
        let (result, traces) = evaluate(&[inactive], &context, "REVIEW");
        assert_eq!(result, "REVIEW");
        assert!(traces[0].skipped);
    }
}
