//! 参数模板渲染引擎：把 `{{变量}}`、过滤器与内置函数渲染成最终文本。
//!
//! 纯函数模块：上下文由调用方构造，渲染过程不碰数据库、不碰网络。
//!
//! 语法见 `doc/API.md` 第五章：
//!
//! - 变量：`{{task.id}}` `{{task.result}}` `{{task.biz_key}}` `{{task.task_no}}`
//!   `{{media.url}}` `{{media.text}}` `{{model.label}}` `{{model.score}}`
//!   `{{ext.user_id}}` `{{now}}` `{{now_ms}}`。
//! - 过滤器：`{{ media.text | truncate:200 }}`、`{{ model.score | round:2 }}`、
//!   `{{ ext.user_id | default:'anonymous' }}`，多个过滤器用 `|` 从左到右串联。
//! - 内置函数：`uuid()`、`sha256(x)`、`json_escape(x)`、`url_encode(x)`。
//! - 允许空格：`{{ task.id }}` 与 `{{task.id}}` 等价。

use serde_json::Value;
use sha2::{Digest, Sha256};

/// 模板上下文：渲染时可取到的全部变量。
#[derive(Debug, Clone, Default)]
pub struct TemplateContext {
    pub task_id: u64,
    pub task_no: String,
    pub task_result: String,
    pub task_biz_key: String,
    pub media_url: String,
    pub media_text: String,
    pub model_label: String,
    pub model_score: f64,
    pub ext: serde_json::Map<String, Value>,
    pub now_ms: i64,
    pub now: String,
}

/// 内置变量清单（`ext.*` 之外的固定变量）。
pub const KNOWN_VARIABLES: &[&str] = &[
    "task.id",
    "task.no",
    "task.task_no",
    "task.result",
    "task.biz_key",
    "media.url",
    "media.text",
    "model.label",
    "model.score",
    "now",
    "now_ms",
];

/// 内置函数清单。
pub const KNOWN_FUNCTIONS: &[&str] = &["uuid", "sha256", "json_escape", "url_encode"];

impl TemplateContext {
    /// 按变量名取值。未知变量返回 `None`。
    pub fn lookup(&self, name: &str) -> Option<Value> {
        let key = name.trim();
        match key {
            "task.id" => return Some(Value::from(self.task_id)),
            "task.no" | "task.task_no" => return Some(Value::String(self.task_no.clone())),
            "task.result" => return Some(Value::String(self.task_result.clone())),
            "task.biz_key" => return Some(Value::String(self.task_biz_key.clone())),
            "media.url" => return Some(Value::String(self.media_url.clone())),
            "media.text" => return Some(Value::String(self.media_text.clone())),
            "model.label" => return Some(Value::String(self.model_label.clone())),
            "model.score" => {
                return Some(
                    serde_json::Number::from_f64(self.model_score)
                        .map(Value::Number)
                        .unwrap_or(Value::Null),
                );
            }
            "now" => return Some(Value::String(self.now.clone())),
            "now_ms" => return Some(Value::from(self.now_ms)),
            _ => {}
        }

        if let Some(rest) = key.strip_prefix("ext.") {
            return self.ext.get(rest).cloned();
        }
        None
    }
}

/// 变量名是否是已知变量。`ext.*` 视为已知（具体键在渲染时才校验）。
pub fn is_known_variable(name: &str) -> bool {
    let key = name.trim();
    if KNOWN_VARIABLES.contains(&key) {
        return true;
    }
    key.strip_prefix("ext.")
        .is_some_and(|rest| !rest.trim().is_empty())
}

/// 渲染 JSON 值：字符串按模板渲染，数组与对象递归处理，其余原样返回。
pub fn render_value(value: &Value, context: &TemplateContext) -> Result<Value, String> {
    match value {
        Value::String(text) => Ok(Value::String(render_string(text, context)?)),
        Value::Array(items) => {
            let mut rendered = Vec::with_capacity(items.len());
            for item in items {
                rendered.push(render_value(item, context)?);
            }
            Ok(Value::Array(rendered))
        }
        Value::Object(fields) => {
            let mut rendered = serde_json::Map::with_capacity(fields.len());
            for (key, item) in fields {
                rendered.insert(key.clone(), render_value(item, context)?);
            }
            Ok(Value::Object(rendered))
        }
        other => Ok(other.clone()),
    }
}

/// 渲染一段文本中的模板表达式。
pub fn render_string(text: &str, context: &TemplateContext) -> Result<String, String> {
    let mut output = String::with_capacity(text.len());
    let mut rest = text;

    while let Some(start) = rest.find("{{") {
        output.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            return Err("模板语法错误：存在未闭合的 {{".to_string());
        };
        let expression = &after[..end];
        let value = eval_expression(expression, context)?;
        output.push_str(&value_to_text(&value));
        rest = &after[end + 2..];
    }
    output.push_str(rest);
    Ok(output)
}

/// 校验一段文本里的模板语法：变量必须存在、过滤器必须合法。
///
/// 用于「保存前校验」——此时还没有真实数据，只检查语法与变量名。
pub fn validate_template(text: &str) -> Result<(), String> {
    let mut rest = text;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            return Err("模板语法错误：存在未闭合的 {{".to_string());
        };
        validate_expression(&after[..end])?;
        rest = &after[end + 2..];
    }
    Ok(())
}

/// 表达式来源：变量或函数调用。
#[derive(Debug, Clone)]
enum Source {
    Variable(String),
    Function { name: String, args: Vec<String> },
}

/// 过滤器。
#[derive(Debug, Clone)]
struct Filter {
    name: String,
    arg: Option<String>,
}

/// 求值一个表达式（首段是来源，其余段是过滤器）。
fn eval_expression(expression: &str, context: &TemplateContext) -> Result<Value, String> {
    let segments = split_segments(expression);
    let Some(first) = segments.first() else {
        return Err("模板表达式为空".to_string());
    };

    let source = parse_source(first)?;
    let mut value = eval_source(&source, context)?;

    for raw in segments.iter().skip(1) {
        if raw.trim().is_empty() {
            continue;
        }
        let filter = parse_filter(raw)?;
        value = apply_filter(&filter, value)?;
    }

    Ok(value)
}

/// 校验一个表达式的语法（不求值）。
fn validate_expression(expression: &str) -> Result<(), String> {
    let segments = split_segments(expression);
    let Some(first) = segments.first() else {
        return Err("模板表达式为空".to_string());
    };

    match parse_source(first)? {
        Source::Variable(name) => {
            if !is_known_variable(&name) {
                return Err(format!("模板变量不存在：{name}"));
            }
        }
        Source::Function { name, args } => {
            if !KNOWN_FUNCTIONS.contains(&name.as_str()) {
                return Err(format!("模板函数不存在：{name}"));
            }
            for arg in &args {
                let arg = arg.trim();
                if is_quoted(arg) {
                    continue;
                }
                if !is_known_variable(arg) {
                    return Err(format!("模板变量不存在：{arg}"));
                }
            }
        }
    }

    for raw in segments.iter().skip(1) {
        if raw.trim().is_empty() {
            continue;
        }
        let filter = parse_filter(raw)?;
        match filter.name.as_str() {
            "truncate" => {
                let arg = filter
                    .arg
                    .as_deref()
                    .ok_or_else(|| "过滤器 truncate 需要长度参数".to_string())?;
                arg.parse::<usize>()
                    .map_err(|_| format!("过滤器 truncate 的参数「{arg}」不是合法长度"))?;
            }
            "round" => {
                let arg = filter
                    .arg
                    .as_deref()
                    .ok_or_else(|| "过滤器 round 需要小数位数参数".to_string())?;
                arg.parse::<usize>()
                    .map_err(|_| format!("过滤器 round 的参数「{arg}」不是合法小数位数"))?;
            }
            "default" => {
                if filter.arg.is_none() {
                    return Err("过滤器 default 需要默认值参数".to_string());
                }
            }
            other => return Err(format!("模板过滤器不存在：{other}")),
        }
    }

    Ok(())
}

/// 求值来源（变量或函数）。
fn eval_source(source: &Source, context: &TemplateContext) -> Result<Value, String> {
    match source {
        Source::Variable(name) => context
            .lookup(name)
            .ok_or_else(|| format!("模板变量不存在：{name}")),
        Source::Function { name, args } => eval_function(name, args, context),
    }
}

/// 求值内置函数。
fn eval_function(name: &str, args: &[String], context: &TemplateContext) -> Result<Value, String> {
    match name {
        "uuid" => {
            if !args.is_empty() {
                return Err("函数 uuid() 不接受参数".to_string());
            }
            Ok(Value::String(uuid::Uuid::new_v4().to_string()))
        }
        "sha256" => {
            let arg = single_arg(args, "sha256")?;
            Ok(Value::String(sha256_hex(&arg_text(&arg, context)?)))
        }
        "json_escape" => {
            let arg = single_arg(args, "json_escape")?;
            Ok(Value::String(json_escape(&arg_text(&arg, context)?)))
        }
        "url_encode" => {
            let arg = single_arg(args, "url_encode")?;
            Ok(Value::String(
                urlencoding::encode(&arg_text(&arg, context)?).into_owned(),
            ))
        }
        other => Err(format!("模板函数不存在：{other}")),
    }
}

/// 取函数的唯一参数。
fn single_arg(args: &[String], name: &str) -> Result<String, String> {
    match args.len() {
        1 => Ok(args[0].trim().to_string()),
        0 => Err(format!("函数 {name}() 缺少参数")),
        _ => Err(format!("函数 {name}() 只接受一个参数")),
    }
}

/// 参数求值：带引号的是字面量，其余按变量名查上下文。
fn arg_text(arg: &str, context: &TemplateContext) -> Result<String, String> {
    let trimmed = arg.trim();
    if is_quoted(trimmed) {
        return Ok(unquote(trimmed));
    }
    let value = context
        .lookup(trimmed)
        .ok_or_else(|| format!("模板变量不存在：{trimmed}"))?;
    Ok(value_to_text(&value))
}

/// 应用过滤器。
fn apply_filter(filter: &Filter, value: Value) -> Result<Value, String> {
    match filter.name.as_str() {
        "truncate" => {
            let arg = filter
                .arg
                .as_deref()
                .ok_or_else(|| "过滤器 truncate 需要长度参数".to_string())?;
            let limit = arg
                .trim()
                .parse::<usize>()
                .map_err(|_| format!("过滤器 truncate 的参数「{arg}」不是合法长度"))?;
            let text = value_to_text(&value);
            Ok(Value::String(text.chars().take(limit).collect()))
        }
        "round" => {
            let arg = filter
                .arg
                .as_deref()
                .ok_or_else(|| "过滤器 round 需要小数位数参数".to_string())?;
            let digits = arg
                .trim()
                .parse::<usize>()
                .map_err(|_| format!("过滤器 round 的参数「{arg}」不是合法小数位数"))?;
            let number = value
                .as_f64()
                .or_else(|| value_to_text(&value).trim().parse::<f64>().ok())
                .ok_or_else(|| "过滤器 round 只能作用于数字".to_string())?;
            let factor = 10f64.powi(digits as i32);
            Ok(Value::from((number * factor).round() / factor))
        }
        "default" => {
            let arg = filter
                .arg
                .as_deref()
                .ok_or_else(|| "过滤器 default 需要默认值参数".to_string())?;
            let empty = match &value {
                Value::Null => true,
                Value::String(text) => text.is_empty(),
                _ => false,
            };
            if empty {
                Ok(literal_value(arg.trim()))
            } else {
                Ok(value)
            }
        }
        other => Err(format!("模板过滤器不存在：{other}")),
    }
}

/// 把字面量参数转成 JSON 值：带引号是字符串，能解析成数字就是数字。
fn literal_value(raw: &str) -> Value {
    if is_quoted(raw) {
        return Value::String(unquote(raw));
    }
    match raw.parse::<f64>() {
        Ok(number) => Value::from(number),
        Err(_) => Value::String(raw.to_string()),
    }
}

/// 按 `|` 切分表达式各段（引号内的 `|` 不切）。
fn split_segments(expression: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;

    for ch in expression.chars() {
        match quote {
            Some(mark) => {
                current.push(ch);
                if ch == mark {
                    quote = None;
                }
            }
            None => {
                if ch == '\'' || ch == '"' {
                    quote = Some(ch);
                    current.push(ch);
                } else if ch == '|' {
                    segments.push(current.trim().to_string());
                    current.clear();
                } else {
                    current.push(ch);
                }
            }
        }
    }
    segments.push(current.trim().to_string());
    segments
}

/// 解析表达式首段：变量名或函数调用。
fn parse_source(raw: &str) -> Result<Source, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("模板表达式为空".to_string());
    }

    if let Some(open) = trimmed.find('(') {
        if !trimmed.ends_with(')') {
            return Err(format!("模板语法错误：表达式「{trimmed}」缺少右括号"));
        }
        let name = trimmed[..open].trim().to_string();
        let inner = &trimmed[open + 1..trimmed.len() - 1];
        return Ok(Source::Function {
            name,
            args: split_args(inner),
        });
    }

    Ok(Source::Variable(trimmed.to_string()))
}

/// 解析过滤器：`name` 或 `name:arg`。
fn parse_filter(raw: &str) -> Result<Filter, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("模板过滤器为空".to_string());
    }
    match trimmed.split_once(':') {
        Some((name, arg)) => Ok(Filter {
            name: name.trim().to_string(),
            arg: Some(arg.trim().to_string()),
        }),
        None => Ok(Filter {
            name: trimmed.to_string(),
            arg: None,
        }),
    }
}

/// 按逗号切分函数参数（引号内的逗号不切）。
fn split_args(raw: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;

    for ch in raw.chars() {
        match quote {
            Some(mark) => {
                current.push(ch);
                if ch == mark {
                    quote = None;
                }
            }
            None => {
                if ch == '\'' || ch == '"' {
                    quote = Some(ch);
                    current.push(ch);
                } else if ch == ',' {
                    args.push(current.trim().to_string());
                    current.clear();
                } else {
                    current.push(ch);
                }
            }
        }
    }
    if !current.trim().is_empty() {
        args.push(current.trim().to_string());
    }
    args
}

/// 是否是带引号的字面量。
fn is_quoted(raw: &str) -> bool {
    let trimmed = raw.trim();
    trimmed.len() >= 2
        && ((trimmed.starts_with('\'') && trimmed.ends_with('\''))
            || (trimmed.starts_with('"') && trimmed.ends_with('"')))
}

/// 去掉字面量外层引号。
fn unquote(raw: &str) -> String {
    let trimmed = raw.trim();
    if is_quoted(trimmed) {
        trimmed[1..trimmed.len() - 1].to_string()
    } else {
        trimmed.to_string()
    }
}

/// 值转文本。
fn value_to_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number.to_string(),
        other => other.to_string(),
    }
}

/// SHA-256 十六进制小写。
fn sha256_hex(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

/// JSON 转义：字符串去掉外层引号后返回转义内容，其他值返回其 JSON 文本。
fn json_escape(text: &str) -> String {
    let encoded = serde_json::to_string(text).unwrap_or_else(|_| "\"\"".to_string());
    if encoded.len() >= 2 {
        encoded[1..encoded.len() - 1].to_string()
    } else {
        encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// 构造一个测试上下文。
    fn context() -> TemplateContext {
        let mut ext = serde_json::Map::new();
        ext.insert("user_id".to_string(), json!("u123"));
        TemplateContext {
            task_id: 180000000000001,
            task_no: "T20261021000001".to_string(),
            task_result: "REJECT".to_string(),
            task_biz_key: "post:9527".to_string(),
            media_url: "https://oss.example.com/a.jpg".to_string(),
            media_text: "待审核文本".to_string(),
            model_label: "porn".to_string(),
            model_score: 0.97234,
            ext,
            now_ms: 1791000000000,
            now: "2026-10-21T10:00:00Z".to_string(),
        }
    }

    #[test]
    fn renders_builtin_variables() {
        let ctx = context();
        assert_eq!(
            render_string("任务 {{task.id}}", &ctx).unwrap(),
            "任务 180000000000001"
        );
        assert_eq!(
            render_string("{{task.result}}/{{task.biz_key}}", &ctx).unwrap(),
            "REJECT/post:9527"
        );
        assert_eq!(
            render_string("{{task.task_no}}", &ctx).unwrap(),
            "T20261021000001"
        );
        assert_eq!(
            render_string("{{media.url}}", &ctx).unwrap(),
            "https://oss.example.com/a.jpg"
        );
        assert_eq!(render_string("{{media.text}}", &ctx).unwrap(), "待审核文本");
        assert_eq!(render_string("{{model.label}}", &ctx).unwrap(), "porn");
        assert_eq!(render_string("{{ext.user_id}}", &ctx).unwrap(), "u123");
        assert_eq!(
            render_string("{{now}}", &ctx).unwrap(),
            "2026-10-21T10:00:00Z"
        );
        assert_eq!(render_string("{{now_ms}}", &ctx).unwrap(), "1791000000000");
    }

    #[test]
    fn allows_spaces_around_expression() {
        let ctx = context();
        assert_eq!(
            render_string("{{ task.id }}", &ctx).unwrap(),
            "180000000000001"
        );
        assert_eq!(
            render_string("{{task.id}}", &ctx).unwrap(),
            "180000000000001"
        );
    }

    #[test]
    fn truncate_filter() {
        let ctx = context();
        assert_eq!(
            render_string("{{ media.text | truncate:2 }}", &ctx).unwrap(),
            "待审"
        );
        // 短于长度时原样返回。
        assert_eq!(
            render_string("{{ media.text | truncate:100 }}", &ctx).unwrap(),
            "待审核文本"
        );
    }

    #[test]
    fn round_filter() {
        let ctx = context();
        assert_eq!(
            render_string("{{ model.score | round:2 }}", &ctx).unwrap(),
            "0.97"
        );
        assert_eq!(
            render_string("{{ model.score | round:4 }}", &ctx).unwrap(),
            "0.9723"
        );
    }

    #[test]
    fn default_filter() {
        let ctx = context();
        assert_eq!(
            render_string("{{ ext.user_id | default:'anonymous' }}", &ctx).unwrap(),
            "u123"
        );
        let mut ext = serde_json::Map::new();
        ext.insert("empty".to_string(), json!(""));
        let ctx = TemplateContext { ext, ..context() };
        assert_eq!(
            render_string("{{ ext.empty | default:'anonymous' }}", &ctx).unwrap(),
            "anonymous"
        );
    }

    #[test]
    fn filters_can_be_chained() {
        let ctx = context();
        assert_eq!(
            render_string("{{ media.text | truncate:2 | default:'x' }}", &ctx).unwrap(),
            "待审"
        );
    }

    #[test]
    fn builtin_functions() {
        let ctx = context();
        let uuid = render_string("{{ uuid() }}", &ctx).unwrap();
        assert_eq!(uuid.len(), 36);

        let sha = render_string("{{ sha256(task.biz_key) }}", &ctx).unwrap();
        assert_eq!(sha.len(), 64);
        assert!(
            sha.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );

        let escaped = render_string("{{ json_escape(task.biz_key) }}", &ctx).unwrap();
        assert_eq!(escaped, "post:9527");

        let encoded = render_string("{{ url_encode(task.biz_key) }}", &ctx).unwrap();
        assert_eq!(encoded, "post%3A9527");
    }

    #[test]
    fn unknown_variable_is_error() {
        let ctx = context();
        let err = render_string("{{ ext.not_exist }}", &ctx).unwrap_err();
        assert!(err.contains("不存在"), "错误信息应为中文说明：{err}");
    }

    #[test]
    fn unknown_filter_is_error() {
        let ctx = context();
        let err = render_string("{{ task.id | nope:1 }}", &ctx).unwrap_err();
        assert!(err.contains("过滤器"), "错误信息应为中文说明：{err}");
    }

    #[test]
    fn unclosed_expression_is_error() {
        let ctx = context();
        assert!(render_string("{{ task.id", &ctx).is_err());
    }

    #[test]
    fn render_value_walks_json() {
        let ctx = context();
        let source = json!({
            "biz_key": "{{task.biz_key}}",
            "nested": { "score": "{{model.score | round:1}}" },
            "list": ["{{task.result}}", 1, true]
        });
        let rendered = render_value(&source, &ctx).unwrap();
        assert_eq!(rendered["biz_key"], json!("post:9527"));
        // 字符串模板渲染后仍是字符串。
        assert_eq!(rendered["nested"]["score"], json!("1.0"));
        assert_eq!(rendered["list"][0], json!("REJECT"));
        assert_eq!(rendered["list"][1], json!(1));
    }

    #[test]
    fn validate_template_checks_variables_and_filters() {
        assert!(validate_template("{{task.id}} {{ ext.user_id }}").is_ok());
        assert!(validate_template("{{ media.text | truncate:200 }}").is_ok());
        assert!(validate_template("{{ ext.user_id | default:'anonymous' }}").is_ok());
        assert!(validate_template("{{unknown.var}}").is_err());
        assert!(validate_template("{{ task.id | bad_filter }}").is_err());
        assert!(validate_template("{{ task.id | truncate:abc }}").is_err());
    }
}
