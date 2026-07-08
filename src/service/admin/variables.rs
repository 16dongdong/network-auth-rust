use std::collections::HashSet;

use serde_json::{Value, json};

use crate::{
    error::AppError,
    repository::{
        RemoteVariableDetailRow, RemoteVariableFilters, RemoteVariableInput, RemoteVariableRow,
    },
    service::remote_lua,
};

const SCOPE_PUBLIC: &str = "public";
const SCOPE_PRIVATE: &str = "private";
const FLAG_ENABLED: i64 = 1;
const FLAG_DISABLED: i64 = 0;

pub struct RemoteVariablePayload {
    pub variable: RemoteVariableInput,
    pub app_ids: Vec<u64>,
}

pub fn remote_variable_filters(payload: &Value) -> Result<RemoteVariableFilters, AppError> {
    let scope = optional_scope(&payload_string(payload, "scope"))?;
    let status = optional_status(payload.get("status"))?;
    let app_id = optional_positive_id(payload.get("app_id"))?;
    Ok(RemoteVariableFilters {
        keyword: payload_string(payload, "keyword").trim().to_string(),
        scope,
        status,
        app_id,
    })
}

pub fn remote_variable_payload(
    payload: &Value,
    system_key: &str,
) -> Result<RemoteVariablePayload, AppError> {
    let scope = variable_scope(&payload_string_or(payload, "scope", SCOPE_PUBLIC))?;
    let app_ids = if scope == SCOPE_PRIVATE {
        remote_variable_app_ids(payload.get("app_ids"))?
    } else {
        Vec::new()
    };
    let name = variable_name(&payload_string(payload, "name"))?;
    let value = remote_lua::storage_value(&name, payload, system_key)?;
    Ok(RemoteVariablePayload {
        variable: RemoteVariableInput {
            name,
            value,
            scope,
            status: variable_status(payload.get("status")),
        },
        app_ids,
    })
}

pub fn remote_variable_name(value: &str) -> Result<String, AppError> {
    variable_name(value)
}

pub fn remote_variable_names(payload: &Value) -> Result<Vec<String>, AppError> {
    let raw_names = match payload.get("names") {
        Some(Value::Array(values)) => values.iter().map(value_text).collect::<Vec<_>>(),
        _ => vec![payload.get("name").map(value_text).unwrap_or_default()],
    };
    let mut seen = HashSet::new();
    let mut names = Vec::new();
    for raw_name in raw_names {
        let name = variable_name(&raw_name)?;
        if seen.insert(name.clone()) {
            names.push(name);
        }
    }
    if names.is_empty() {
        return Err(AppError::InvalidVariable);
    }
    Ok(names)
}

pub fn remote_variable_id(value: Option<&Value>) -> Result<u64, AppError> {
    positive_id(value).map_err(|_| AppError::InvalidVariable)
}

pub fn remote_variable_ids(value: Option<&Value>) -> Result<Vec<u64>, AppError> {
    ids(value).map_err(|_| AppError::InvalidVariableIds)
}

pub fn remote_variable_app_ids(value: Option<&Value>) -> Result<Vec<u64>, AppError> {
    ids(value).map_err(|_| AppError::InvalidVariableApps)
}

pub fn remote_variable_scope(value: &str) -> Result<String, AppError> {
    variable_scope(value)
}

pub fn remote_variable_status(value: Option<&Value>) -> i64 {
    variable_status(value)
}

pub fn remote_variable_view(row: RemoteVariableRow) -> Value {
    json!({
        "id": row.id,
        "name": row.name,
        "value": row.value,
        "scope": row.scope,
        "status": row.status,
        "app_ids": csv_ints(&row.app_ids_csv),
        "app_names": csv_lines(&row.app_names_csv),
        "app_count": row.app_count,
        "created_at": row.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
        "updated_at": row.updated_at.format("%Y-%m-%d %H:%M:%S").to_string(),
    })
}

pub fn converted_remote_variable_input(
    variable: &RemoteVariableDetailRow,
    scope: String,
) -> RemoteVariableInput {
    RemoteVariableInput {
        name: variable.name.clone(),
        value: variable.value.clone(),
        scope,
        status: variable.status,
    }
}

fn variable_name(value: &str) -> Result<String, AppError> {
    let name = value.trim();
    if (1..=80).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
    {
        return Ok(name.to_string());
    }
    Err(AppError::InvalidVariable)
}

fn value_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        Value::Bool(enabled) => {
            if *enabled {
                "1".to_string()
            } else {
                String::new()
            }
        }
        Value::Null | Value::Array(_) | Value::Object(_) => String::new(),
    }
}

fn variable_scope(value: &str) -> Result<String, AppError> {
    let scope = value.trim();
    if matches!(scope, SCOPE_PUBLIC | SCOPE_PRIVATE) {
        return Ok(scope.to_string());
    }
    Err(AppError::InvalidVariableScope)
}

fn optional_scope(value: &str) -> Result<String, AppError> {
    let scope = value.trim();
    if scope.is_empty() {
        return Ok(String::new());
    }
    variable_scope(scope)
}

fn variable_status(value: Option<&Value>) -> i64 {
    match value {
        Some(value) if int_from_value(value) == 0 => FLAG_DISABLED,
        _ => FLAG_ENABLED,
    }
}

fn optional_status(value: Option<&Value>) -> Result<Option<i64>, AppError> {
    match value {
        Some(Value::String(text)) if text.trim().is_empty() => Ok(None),
        Some(value) => Ok(Some(variable_status(Some(value)))),
        None => Ok(None),
    }
}

fn optional_positive_id(value: Option<&Value>) -> Result<Option<u64>, AppError> {
    match value {
        Some(Value::String(text)) if text.trim().is_empty() => Ok(None),
        Some(value) => {
            let id = int_from_value(value);
            Ok((id > 0).then_some(id as u64))
        }
        None => Ok(None),
    }
}

fn positive_id(value: Option<&Value>) -> Result<u64, AppError> {
    let Some(value) = value else {
        return Err(AppError::InvalidVariableIds);
    };
    let id = int_from_value(value);
    if id > 0 {
        return Ok(id as u64);
    }
    Err(AppError::InvalidVariableIds)
}

fn ids(value: Option<&Value>) -> Result<Vec<u64>, AppError> {
    let Some(Value::Array(values)) = value else {
        return Err(AppError::InvalidVariableIds);
    };
    let mut seen = HashSet::new();
    let mut ids = Vec::new();
    for value in values {
        let id = int_from_value(value);
        if id > 0 && seen.insert(id) {
            ids.push(id as u64);
        }
    }
    if ids.is_empty() {
        return Err(AppError::InvalidVariableIds);
    }
    Ok(ids)
}

fn int_from_value(value: &Value) -> i64 {
    match value {
        Value::Number(number) => number.as_i64().unwrap_or(0),
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

fn payload_string(payload: &Value, key: &str) -> String {
    payload.get(key).map(value_text).unwrap_or_default()
}

fn payload_string_or(payload: &Value, key: &str, default: &str) -> String {
    payload
        .get(key)
        .map(value_text)
        .unwrap_or_else(|| default.to_string())
}

fn csv_ints(value: &str) -> Vec<u64> {
    value
        .split(',')
        .filter_map(|text| text.trim().parse::<u64>().ok())
        .filter(|id| *id > 0)
        .collect()
}

fn csv_lines(value: &str) -> Vec<String> {
    value
        .split('\n')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use chrono::NaiveDateTime;
    use serde_json::json;

    use crate::{crypto, error::AppError};

    use super::{
        RemoteVariableRow, remote_variable_app_ids, remote_variable_filters, remote_variable_id,
        remote_variable_ids, remote_variable_names, remote_variable_payload,
        remote_variable_status, remote_variable_view,
    };

    #[test]
    fn normalizes_private_variable_payload_like_frontend() {
        let payload = remote_variable_payload(
            &json!({
                "name": "feature.flag-1",
                "value": "enabled\ntrue",
                "scope": "private",
                "status": 0,
                "app_ids": [1, "2", 2]
            }),
            "system-key",
        )
        .expect("variable payload");

        assert_eq!("feature.flag-1", payload.variable.name);
        assert_eq!("private", payload.variable.scope);
        assert_eq!(0, payload.variable.status);
        assert_eq!(vec![1, 2], payload.app_ids);
    }

    #[test]
    fn accepts_remote_lua_storage_value_like_php_admin_service() {
        let source = "return function() return true end";
        let protected_value = json!({
            "format": "ace.remoteLua.source.v1",
            "ciphertext": crypto::encrypt_protected_text_with_iv(
                source,
                "system-key",
                &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
            )
            .expect("source should encrypt"),
            "sourceSha256": crypto::sha256_hex(source),
        })
        .to_string();

        let payload = remote_variable_payload(
            &json!({
                "name": "ace.lua.gameProbe",
                "value": protected_value,
                "scope": "public",
                "status": 1
            }),
            "system-key",
        )
        .expect("remote lua payload");

        assert_eq!("ace.lua.gameProbe", payload.variable.name);
        assert_eq!(protected_value, payload.variable.value);
    }

    #[test]
    fn rejects_plain_value_invalid_text_like_php_validator() {
        assert!(matches!(
            remote_variable_payload(
                &json!({
                    "name": "feature.flag",
                    "value": "<bad>",
                    "scope": "public"
                }),
                "system-key"
            ),
            Err(AppError::InvalidText)
        ));
    }

    #[test]
    fn parses_remote_variable_names_like_php_strval() {
        assert_eq!(
            vec!["ace.flag".to_string(), "123".to_string()],
            remote_variable_names(&json!({"names": ["ace.flag", "ace.flag", 123]})).expect("names")
        );
        assert!(remote_variable_names(&json!({"names": [null]})).is_err());
    }

    #[test]
    fn parses_variable_ids_like_php_int_filter() {
        assert_eq!(
            vec![12, 1],
            remote_variable_ids(Some(&json!([0, "12abc", "bad", true, false, 12]))).expect("ids")
        );
        assert_eq!(12, remote_variable_id(Some(&json!("12abc"))).expect("id"));
        assert!(remote_variable_id(Some(&json!("abc"))).is_err());
        assert_eq!(
            vec![1],
            remote_variable_app_ids(Some(&json!(["bad", 1, 0]))).expect("app ids")
        );
    }

    #[test]
    fn parses_variable_status_like_php_int_cast() {
        assert_eq!(0, remote_variable_status(Some(&json!("abc"))));
        assert_eq!(0, remote_variable_status(Some(&json!(false))));
        assert_eq!(1, remote_variable_status(Some(&json!("1abc"))));
        assert_eq!(1, remote_variable_status(Some(&json!(true))));
    }

    #[test]
    fn parses_variable_filters() {
        let filters = remote_variable_filters(&json!({
            "keyword": "feature",
            "scope": "public",
            "status": "0",
            "app_id": "9"
        }))
        .expect("filters");

        assert_eq!("feature", filters.keyword);
        assert_eq!("public", filters.scope);
        assert_eq!(Some(0), filters.status);
        assert_eq!(Some(9), filters.app_id);

        let php_cast_filters = remote_variable_filters(&json!({
            "status": "abc",
            "app_id": "abc"
        }))
        .expect("php cast filters");
        assert_eq!(Some(0), php_cast_filters.status);
        assert_eq!(None, php_cast_filters.app_id);
    }

    #[test]
    fn renders_variable_row_csv_fields() {
        let view = remote_variable_view(RemoteVariableRow {
            id: 7,
            name: "theme".to_string(),
            value: "dark".to_string(),
            scope: "private".to_string(),
            status: 1,
            app_ids_csv: "2,5".to_string(),
            app_names_csv: "App A\nApp B".to_string(),
            app_count: 2,
            created_at: NaiveDateTime::parse_from_str("2026-01-01 00:00:00", "%Y-%m-%d %H:%M:%S")
                .expect("created_at"),
            updated_at: NaiveDateTime::parse_from_str("2026-01-02 00:00:00", "%Y-%m-%d %H:%M:%S")
                .expect("updated_at"),
        });

        assert_eq!(json!([2, 5]), view["app_ids"]);
        assert_eq!(json!(["App A", "App B"]), view["app_names"]);
    }
}
