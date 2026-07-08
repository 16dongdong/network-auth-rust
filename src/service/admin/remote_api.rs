use std::{collections::HashSet, net::IpAddr};

use chrono::NaiveDateTime;
use serde_json::{Value, json};

use crate::{
    error::AppError,
    repository::{
        NewRemoteApiToken, RemoteApiLogFilters, RemoteApiLogRow, RemoteApiTokenDetailRow,
        RemoteApiTokenFilters, RemoteApiTokenRow,
    },
};

const CLEAR_LOGS_CONFIRMATION: &str = "CLEAR_REMOTE_API_LOGS";
const FLAG_ENABLED: i64 = 1;
const FLAG_DISABLED: i64 = 0;

pub fn remote_api_token_filters(payload: &Value) -> Result<RemoteApiTokenFilters, AppError> {
    let (limit, offset) = page(payload, 100)?;
    Ok(RemoteApiTokenFilters {
        keyword: payload_string(payload, "keyword"),
        status: optional_status(payload.get("status")),
        limit,
        offset,
    })
}

pub fn new_remote_api_token(
    payload: &Value,
    access_key: String,
    secret_cipher: String,
    created_by: String,
) -> Result<NewRemoteApiToken, AppError> {
    let name = safe_text(&payload_string(payload, "name"), 80)?;
    if name.is_empty() {
        return Err(AppError::RemoteApiTokenNameRequired);
    }
    Ok(NewRemoteApiToken {
        name,
        access_key,
        secret_cipher,
        status: FLAG_ENABLED,
        expires_at: optional_date_time(&payload_string(payload, "expires_at"))?,
        ip_allowlist_json: json_array(&ip_allowlist(payload.get("ip_allowlist"))?)?,
        created_by: safe_text(&created_by, 64)?,
    })
}

pub fn remote_api_token_id(value: Option<&Value>) -> Result<u64, AppError> {
    positive_id(value)
}

pub fn remote_api_token_status(value: Option<&Value>) -> Result<i64, AppError> {
    Ok(status(value))
}

pub fn remote_api_log_filters(payload: &Value) -> Result<RemoteApiLogFilters, AppError> {
    let (limit, offset) = page(payload, 50)?;
    Ok(RemoteApiLogFilters {
        token_id: optional_cast_positive_id(payload.get("token_id")),
        target_app_id: optional_cast_positive_id(payload.get("target_app_id")),
        route: payload_string(payload, "route"),
        status: payload_string(payload, "status"),
        keyword: payload_string(payload, "keyword"),
        start: optional_date_boundary(&payload_string(payload, "start"), "00:00:00")?,
        end: optional_date_boundary(&payload_string(payload, "end"), "23:59:59")?,
        limit,
        offset,
    })
}

pub fn remote_api_log_ids(payload: &Value) -> Result<Vec<u64>, AppError> {
    let Some(value) = payload.get("log_ids").or_else(|| payload.get("log_id")) else {
        return Err(AppError::InvalidId);
    };
    match value {
        Value::Array(values) => ids(values),
        value => positive_id(Some(value)).map(|id| vec![id]),
    }
}

pub fn assert_remote_api_logs_clear_confirmed(payload: &Value) -> Result<(), AppError> {
    if payload_string(payload, "confirm") == CLEAR_LOGS_CONFIRMATION {
        return Ok(());
    }
    Err(AppError::RemoteApiLogClearConfirmRequired)
}

pub fn remote_api_token_view(row: &RemoteApiTokenRow) -> Value {
    json!({
        "id": row.id,
        "name": row.name,
        "access_key": row.access_key,
        "status": row.status,
        "expires_at": format_datetime(row.expires_at),
        "ip_allowlist": decoded_ip_allowlist(&row.ip_allowlist_json),
        "last_used_at": format_datetime(row.last_used_at),
        "last_ip": row.last_ip,
        "created_by": row.created_by,
        "created_at": format_datetime(row.created_at),
        "updated_at": format_datetime(row.updated_at),
    })
}

pub fn remote_api_created_token_view(token_id: u64, token: &NewRemoteApiToken) -> Value {
    json!({
        "id": token_id,
        "name": token.name,
        "access_key": token.access_key,
        "status": token.status,
        "expires_at": format_datetime(token.expires_at),
        "ip_allowlist": decoded_ip_allowlist(&token.ip_allowlist_json),
        "last_used_at": "",
        "last_ip": "",
        "created_by": token.created_by,
        "created_at": "",
        "updated_at": "",
    })
}

pub fn remote_api_token_detail_view(row: &RemoteApiTokenDetailRow) -> Value {
    json!({
        "id": row.id,
        "name": row.name,
        "access_key": row.access_key,
        "status": row.status,
        "expires_at": format_datetime(row.expires_at),
        "ip_allowlist": decoded_ip_allowlist(&row.ip_allowlist_json),
        "last_used_at": format_datetime(row.last_used_at),
        "last_ip": row.last_ip,
        "created_by": row.created_by,
        "created_at": format_datetime(row.created_at),
        "updated_at": format_datetime(row.updated_at),
    })
}

pub fn remote_api_log_view(row: &RemoteApiLogRow) -> Value {
    json!({
        "id": row.id,
        "token_id": optional_id_text(row.token_id),
        "token_name": row.token_name,
        "access_key": row.access_key,
        "route": row.route,
        "target_app_id": optional_id_text(row.target_app_id),
        "app_code": row.app_code,
        "app_name": row.app_name,
        "status": row.status,
        "error_code": row.error_code,
        "message": row.message,
        "ip": row.ip,
        "created_at": format_datetime(row.created_at),
    })
}

fn optional_date_boundary(value: &str, suffix: &str) -> Result<Option<NaiveDateTime>, AppError> {
    if is_empty(value) {
        return Ok(None);
    }
    let text = if is_date_text(value.trim()) {
        format!("{} {}", value.trim(), suffix)
    } else {
        value.to_string()
    };
    optional_date_time(&text)
}

fn optional_date_time(value: &str) -> Result<Option<NaiveDateTime>, AppError> {
    let text = value.trim();
    if text.is_empty() {
        return Ok(None);
    }
    let normalized = normalize_date_time(text);
    NaiveDateTime::parse_from_str(&normalized, "%Y-%m-%d %H:%M:%S")
        .map(Some)
        .map_err(|_| AppError::RemoteApiExpiresAtInvalid)
}

fn normalize_date_time(value: &str) -> String {
    let normalized = value.replace('T', " ");
    if is_date_text(&normalized) {
        return format!("{normalized} 23:59:59");
    }
    if is_minute_date_time_text(&normalized) {
        return format!("{normalized}:00");
    }
    normalized
}

fn ip_allowlist(value: Option<&Value>) -> Result<Vec<String>, AppError> {
    let items = match value {
        Some(Value::Array(values)) => values.iter().map(value_to_string).collect(),
        Some(value) => split_ip_rules(&value_to_string(value)),
        None => Vec::new(),
    };
    let mut seen = HashSet::new();
    let mut rules = Vec::new();
    for item in items {
        let rule = ip_rule(&item)?;
        if !rule.is_empty() && seen.insert(rule.clone()) {
            rules.push(rule);
        }
    }
    Ok(rules)
}

fn ip_rule(value: &str) -> Result<String, AppError> {
    let rule = value.trim();
    if rule.is_empty() {
        return Ok(String::new());
    }
    if rule.parse::<IpAddr>().is_ok() {
        return Ok(rule.to_string());
    }
    cidr_rule(rule)
}

fn cidr_rule(rule: &str) -> Result<String, AppError> {
    let Some((address, prefix_text)) = rule.split_once('/') else {
        return Err(AppError::RemoteApiIpRuleInvalid);
    };
    let address = address.trim();
    let prefix = prefix_text
        .parse::<u16>()
        .map_err(|_| AppError::RemoteApiIpRuleInvalid)?;
    let ip = address
        .parse::<IpAddr>()
        .map_err(|_| AppError::RemoteApiIpRuleInvalid)?;
    let max_prefix = if ip.is_ipv6() { 128 } else { 32 };
    if prefix > max_prefix {
        return Err(AppError::RemoteApiIpRuleInvalid);
    }
    Ok(format!("{address}/{prefix}"))
}

fn split_ip_rules(value: &str) -> Vec<String> {
    value
        .split(|ch: char| matches!(ch, ',' | ';' | '，' | '；' | '、') || ch.is_whitespace())
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn decoded_ip_allowlist(value: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(value)
        .unwrap_or_default()
        .into_iter()
        .filter(|item| !item.is_empty())
        .collect()
}

fn optional_status(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::String(text)) if text.trim().is_empty() => None,
        Some(value) => Some(status(Some(value))),
        None => None,
    }
}

fn status(value: Option<&Value>) -> i64 {
    match value.map(php_int_from_value) {
        Some(0) => FLAG_DISABLED,
        Some(_) | None => FLAG_ENABLED,
    }
}

fn optional_cast_positive_id(value: Option<&Value>) -> Option<u64> {
    int_from_value(value)
        .filter(|number| *number > 0)
        .map(|number| number as u64)
}

fn positive_id(value: Option<&Value>) -> Result<u64, AppError> {
    filter_int_from_value(value)
        .filter(|number| *number > 0)
        .map(|number| number as u64)
        .ok_or(AppError::InvalidId)
}

fn ids(values: &[Value]) -> Result<Vec<u64>, AppError> {
    let mut seen = HashSet::new();
    let mut ids = Vec::new();
    for value in values {
        let id = positive_id(Some(value))?;
        if seen.insert(id) {
            ids.push(id);
        }
    }
    Ok(ids)
}

fn page(payload: &Value, default_limit: i64) -> Result<(i64, i64), AppError> {
    let page = int_from_value(payload.get("page"))
        .unwrap_or(1)
        .clamp(1, 1_000_000);
    let limit = int_from_value(payload.get("limit"))
        .unwrap_or(default_limit)
        .clamp(1, 100);
    Ok((limit, (page - 1) * limit))
}

fn int_from_value(value: Option<&Value>) -> Option<i64> {
    value.map(php_int_from_value)
}

fn php_int_from_value(value: &Value) -> i64 {
    match value {
        Value::Number(number) => number
            .as_i64()
            .or_else(|| number.as_f64().map(|value| value as i64))
            .unwrap_or(0),
        Value::String(text) => php_int_from_text(text),
        Value::Bool(enabled) => i64::from(*enabled),
        Value::Null | Value::Array(_) | Value::Object(_) => 0,
    }
}

fn php_int_from_text(value: &str) -> i64 {
    let text = value.trim_start();
    let mut digits = String::new();
    for (index, character) in text.chars().enumerate() {
        if index == 0 && matches!(character, '+' | '-') {
            digits.push(character);
            continue;
        }
        if character.is_ascii_digit() {
            digits.push(character);
            continue;
        }
        break;
    }
    if matches!(digits.as_str(), "" | "+" | "-") {
        return 0;
    }
    digits.parse::<i64>().unwrap_or(0)
}

fn filter_int_from_value(value: Option<&Value>) -> Option<i64> {
    value.and_then(|value| match value {
        Value::Number(number) => number.as_i64().or_else(|| {
            number
                .as_u64()
                .and_then(|number| i64::try_from(number).ok())
        }),
        Value::String(text) => filter_int_from_text(text),
        Value::Bool(true) => Some(1),
        Value::Bool(false) | Value::Null | Value::Array(_) | Value::Object(_) => None,
    })
}

fn filter_int_from_text(value: &str) -> Option<i64> {
    let text = value.trim();
    if text.is_empty() {
        return None;
    }
    let (sign, digits) = match text.as_bytes().first() {
        Some(b'+') | Some(b'-') => (&text[..1], &text[1..]),
        _ => ("", text),
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if digits.len() > 1 && digits.starts_with('0') {
        return None;
    }
    format!("{sign}{digits}").parse::<i64>().ok()
}

fn payload_string(payload: &Value, key: &str) -> String {
    payload
        .get(key)
        .map(value_to_string)
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(text) => text.to_string(),
        Value::Number(number) => number.to_string(),
        Value::Bool(true) => "1".to_string(),
        Value::Bool(false) | Value::Null => String::new(),
        Value::Array(_) | Value::Object(_) => "Array".to_string(),
    }
}

fn safe_text(value: &str, max_bytes: usize) -> Result<String, AppError> {
    if value.len() <= max_bytes
        && !value
            .bytes()
            .any(|byte| matches!(byte, b'<' | b'>' | b'"' | 0..=31))
    {
        return Ok(value.to_string());
    }
    Err(AppError::InvalidText)
}

fn json_array(values: &[String]) -> Result<String, AppError> {
    serde_json::to_string(values).map_err(|_| AppError::InvalidInput("JSON 序列化失败"))
}

fn format_datetime(value: Option<NaiveDateTime>) -> String {
    value
        .map(|datetime| datetime.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_default()
}

fn optional_id_text(value: Option<u64>) -> String {
    value.map(|id| id.to_string()).unwrap_or_default()
}

fn is_empty(value: &str) -> bool {
    value.trim().is_empty()
}

fn is_date_text(value: &str) -> bool {
    value.len() == 10
        && digits_at(value, &[0, 1, 2, 3, 5, 6, 8, 9])
        && bytes_at(value, 4) == b'-'
        && bytes_at(value, 7) == b'-'
}

fn is_minute_date_time_text(value: &str) -> bool {
    let bytes = value.as_bytes();
    value.len() == 16
        && is_date_bytes(&bytes[..10])
        && bytes[10] == b' '
        && bytes[13] == b':'
        && [11, 12, 14, 15]
            .iter()
            .all(|index| bytes[*index].is_ascii_digit())
}

fn digits_at(value: &str, indexes: &[usize]) -> bool {
    indexes
        .iter()
        .all(|index| bytes_at(value, *index).is_ascii_digit())
}

fn bytes_at(value: &str, index: usize) -> u8 {
    value.as_bytes()[index]
}

fn is_date_bytes(value: &[u8]) -> bool {
    value.len() == 10
        && [0, 1, 2, 3, 5, 6, 8, 9]
            .iter()
            .all(|index| value[*index].is_ascii_digit())
        && value[4] == b'-'
        && value[7] == b'-'
}

#[cfg(test)]
mod tests {
    use chrono::NaiveDateTime;
    use serde_json::json;

    use crate::repository::{RemoteApiLogRow, RemoteApiTokenRow};

    use super::{
        assert_remote_api_logs_clear_confirmed, new_remote_api_token, remote_api_log_ids,
        remote_api_log_view, remote_api_token_filters, remote_api_token_view,
    };

    #[test]
    fn builds_token_payload_like_php_service() {
        let token = new_remote_api_token(
            &json!({
                "name": "CI",
                "expires_at": "2026-06-11T12:30",
                "ip_allowlist": "127.0.0.1, 10.0.0.0/24、::1"
            }),
            "access".to_string(),
            "secret-cipher".to_string(),
            "admin".to_string(),
        )
        .expect("token payload");

        assert_eq!("CI", token.name);
        assert_eq!("2026-06-11 12:30:00", format_time(token.expires_at));
        assert_eq!(
            "[\"127.0.0.1\",\"10.0.0.0/24\",\"::1\"]",
            token.ip_allowlist_json
        );
    }

    #[test]
    fn parses_token_filters_and_log_ids() {
        let filters = remote_api_token_filters(&json!({
            "keyword": "deploy",
            "status": "0",
            "page": 2,
            "limit": 20
        }))
        .expect("filters");

        assert_eq!("deploy", filters.keyword);
        assert_eq!(Some(0), filters.status);
        assert_eq!(20, filters.limit);
        assert_eq!(20, filters.offset);
        assert_eq!(
            vec![3, 4],
            remote_api_log_ids(&json!({"log_ids": [3, "4", 4]})).expect("ids")
        );
    }

    #[test]
    fn validates_clear_confirmation() {
        assert!(
            assert_remote_api_logs_clear_confirmed(&json!({
                "confirm": "CLEAR_REMOTE_API_LOGS"
            }))
            .is_ok()
        );
        assert!(assert_remote_api_logs_clear_confirmed(&json!({})).is_err());
    }

    #[test]
    fn renders_token_and_log_rows_for_frontend() {
        let token_view = remote_api_token_view(&RemoteApiTokenRow {
            id: 9,
            name: "CI".to_string(),
            access_key: "access".to_string(),
            status: 1,
            expires_at: None,
            ip_allowlist_json: "[\"127.0.0.1\"]".to_string(),
            last_used_at: None,
            last_ip: String::new(),
            created_by: "admin".to_string(),
            created_at: Some(parse_time("2026-06-11 12:00:00")),
            updated_at: Some(parse_time("2026-06-11 12:00:00")),
        });
        let log_view = remote_api_log_view(&RemoteApiLogRow {
            id: 5,
            token_id: Some(9),
            access_key: "access".to_string(),
            route: "/remote/config/get".to_string(),
            target_app_id: None,
            request_hash: "hash".to_string(),
            status: "success".to_string(),
            error_code: String::new(),
            message: "ok".to_string(),
            ip: "127.0.0.1".to_string(),
            created_at: Some(parse_time("2026-06-11 12:01:00")),
            token_name: "CI".to_string(),
            app_code: String::new(),
            app_name: String::new(),
        });

        assert_eq!(json!(["127.0.0.1"]), token_view["ip_allowlist"]);
        assert_eq!("2026-06-11 12:01:00", log_view["created_at"]);
    }

    fn parse_time(value: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S").expect("time")
    }

    fn format_time(value: Option<NaiveDateTime>) -> String {
        value
            .map(|time| time.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_default()
    }
}
