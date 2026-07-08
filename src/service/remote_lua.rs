use serde_json::{Value, json};

use crate::{crypto, error::AppError};

const VARIABLE_PREFIX: &str = "ace.lua.";
const SOURCE_FORMAT: &str = "ace.remoteLua.source.v1";
const ENVELOPE_FORMAT: &str = "ace.remoteLua.v1";
const KEY_MODE: &str = "session.hkdf.sha256.v1";
const HKDF_INFO: &str = "ACE Remote Lua Script V1";
const MAX_SOURCE_BYTES: usize = 20_000;
const MAX_STORED_BYTES: usize = 60_000;

pub struct RemoteLuaSession<'a> {
    pub session_token: &'a str,
    pub session_ticket: &'a str,
    pub install_id: &'a str,
    pub app_code: &'a str,
    pub app_version: &'a str,
}

pub fn client_value(
    name: &str,
    stored_value: Option<String>,
    session: &RemoteLuaSession<'_>,
    system_key: &str,
) -> Result<Option<String>, AppError> {
    let Some(stored_value) = stored_value else {
        return Ok(None);
    };
    if !is_script_variable_name(name) {
        return Ok(Some(stored_value));
    }

    let source = source_from_storage(&stored_value, system_key)?;
    let envelope = runtime_envelope(function_name(name)?, &source, session)?;
    serde_json::to_string(&envelope)
        .map(Some)
        .map_err(|_| AppError::RemoteLuaSourceInvalid("RemoteLua 运行信封序列化失败"))
}

pub(crate) fn storage_value(
    name: &str,
    payload: &Value,
    system_key: &str,
) -> Result<String, AppError> {
    if !is_script_variable_name(name) {
        let value = payload
            .get("value")
            .map(payload_value_string)
            .unwrap_or_default();
        return safe_text_block(&value, 4000);
    }
    if let Some(lua_source) = payload.get("lua_source") {
        return protect_source(
            source_text(payload_value_string(lua_source))?.as_str(),
            system_key,
        );
    }
    let stored_value = payload
        .get("value")
        .map(payload_value_string)
        .unwrap_or_default();
    source_from_storage(&stored_value, system_key)?;
    Ok(stored_value)
}

fn is_script_variable_name(name: &str) -> bool {
    name.starts_with(VARIABLE_PREFIX) && name.len() > VARIABLE_PREFIX.len()
}

fn protect_source(source: &str, system_key: &str) -> Result<String, AppError> {
    serde_json::to_string(&json!({
        "format": SOURCE_FORMAT,
        "ciphertext": crypto::encrypt_protected_text(source, system_key)?,
        "sourceSha256": crypto::sha256_hex(source),
    }))
    .map_err(|_| AppError::RemoteLuaSourceInvalid("RemoteLua 源码保护失败"))
}

fn source_from_storage(stored_value: &str, system_key: &str) -> Result<String, AppError> {
    if stored_value.is_empty() || stored_value.len() > MAX_STORED_BYTES {
        return Err(AppError::RemoteLuaSourceInvalid(
            "RemoteLua 源码密文格式错误",
        ));
    }
    let payload = serde_json::from_str::<Value>(stored_value)
        .map_err(|_| AppError::RemoteLuaSourceInvalid("RemoteLua 源码密文不是合法 JSON"))?;
    if payload.get("format").and_then(Value::as_str) != Some(SOURCE_FORMAT) {
        return Err(AppError::RemoteLuaSourceInvalid(
            "RemoteLua 源码密文格式错误",
        ));
    }
    let source_sha256 = hex_sha256(payload.get("sourceSha256").and_then(Value::as_str))?;
    let ciphertext = payload
        .get("ciphertext")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let source = crypto::decrypt_protected_text(ciphertext, system_key)?;
    if source_sha256 != crypto::sha256_hex(&source) {
        return Err(AppError::RemoteLuaSourceInvalid("RemoteLua 源码哈希不匹配"));
    }
    source_text(source)
}

fn runtime_envelope(
    function_name: &str,
    source: &str,
    session: &RemoteLuaSession<'_>,
) -> Result<Value, AppError> {
    let source_sha256 = crypto::sha256_hex(source);
    let key = script_key(
        session.session_token,
        session.session_ticket,
        session.install_id,
        session.app_code,
        function_name,
        &source_sha256,
    )?;
    let aad = format!(
        "{}\n{}\n{}\n{}",
        session.app_code, session.app_version, function_name, source_sha256
    );
    let encrypted = crypto::encrypt_gcm(source, &key, &aad)?;
    Ok(json!({
        "format": ENVELOPE_FORMAT,
        "key": KEY_MODE,
        "iv": encrypted.iv,
        "ciphertext": encrypted.ciphertext,
        "tag": encrypted.tag,
        "sourceSha256": source_sha256,
    }))
}

fn script_key(
    session_token: &str,
    session_ticket: &str,
    install_id: &str,
    app_code: &str,
    function_name: &str,
    source_sha256: &str,
) -> Result<Vec<u8>, AppError> {
    let input_text = format!("{session_token}\n{session_ticket}\n{install_id}");
    let salt_text = format!("{app_code}\n{function_name}\n{source_sha256}");
    let pseudo_random_key =
        crypto::hmac_sha256_bytes(salt_text.as_bytes(), &[input_text.as_bytes()])?;
    crypto::hmac_sha256_bytes(&pseudo_random_key, &[HKDF_INFO.as_bytes(), &[1_u8]])
}

fn function_name(variable_name: &str) -> Result<&str, AppError> {
    let function_name = &variable_name[VARIABLE_PREFIX.len()..];
    if (1..=96).contains(&function_name.len())
        && function_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        return Ok(function_name);
    }
    Err(AppError::RemoteLuaFunctionInvalid)
}

fn source_text(source: String) -> Result<String, AppError> {
    let has_invalid_control = source
        .bytes()
        .any(|byte| matches!(byte, 0x00..=0x08 | 0x0B | 0x0C | 0x0E..=0x1F));
    if source.is_empty() || source.len() > MAX_SOURCE_BYTES || has_invalid_control {
        return Err(AppError::RemoteLuaSourceInvalid(
            "RemoteLua 源码包含非法字符或超过长度限制",
        ));
    }
    Ok(source)
}

fn hex_sha256(value: Option<&str>) -> Result<String, AppError> {
    let value = value.unwrap_or_default();
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(value.to_ascii_lowercase());
    }
    Err(AppError::RemoteLuaSourceInvalid(
        "RemoteLua 源码哈希格式错误",
    ))
}

fn payload_value_string(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        Value::Bool(enabled) => {
            if *enabled {
                "1".to_string()
            } else {
                String::new()
            }
        }
        Value::Number(number) => number.to_string(),
        Value::Array(_) | Value::Object(_) => "Array".to_string(),
    }
}

fn safe_text_block(value: &str, max_bytes: usize) -> Result<String, AppError> {
    if value.len() <= max_bytes
        && !value.bytes().any(|byte| {
            matches!(
                byte,
                b'<' | b'>' | b'"' | 0..=8 | 11 | 12 | 14..=31
            )
        })
    {
        return Ok(value.to_string());
    }
    Err(AppError::InvalidText)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn returns_plain_variable_without_envelope() {
        let session = session();
        let value = client_value(
            "feature.flag",
            Some("enabled".to_string()),
            &session,
            "system-key",
        )
        .expect("plain variable should render");

        assert_eq!(Some("enabled".to_string()), value);
    }

    #[test]
    fn builds_remote_lua_envelope_from_protected_source() {
        let source = "return function(ctx) return ctx.appCode end";
        let protected = protected_source(source);
        let session = session();
        let value = client_value(
            "ace.lua.healthCheck",
            Some(protected),
            &session,
            "system-key",
        )
        .expect("lua variable should render")
        .expect("lua variable should not be null");
        let envelope = serde_json::from_str::<Value>(&value).expect("envelope json");

        assert_eq!(ENVELOPE_FORMAT, envelope["format"]);
        assert_eq!(KEY_MODE, envelope["key"]);
        assert_eq!(crypto::sha256_hex(source), envelope["sourceSha256"]);
        assert!(envelope["iv"].as_str().expect("iv").len() >= 16);
        assert!(envelope["ciphertext"].as_str().expect("ciphertext").len() >= 16);
        assert!(envelope["tag"].as_str().expect("tag").len() >= 16);
    }

    #[test]
    fn protects_lua_source_for_admin_storage_like_php() {
        let source = "return function(ctx)\n    return ctx.appCode\nend";
        let stored = storage_value(
            "ace.lua.healthCheck",
            &json!({"lua_source": source, "value": "ignored"}),
            "system-key",
        )
        .expect("source should be protected");
        let stored_json = serde_json::from_str::<Value>(&stored).expect("storage json");

        assert_eq!(SOURCE_FORMAT, stored_json["format"]);
        assert_eq!(crypto::sha256_hex(source), stored_json["sourceSha256"]);
        assert!(
            stored_json["ciphertext"]
                .as_str()
                .expect("ciphertext")
                .len()
                > 32
        );
        assert_eq!(
            source,
            source_from_storage(&stored, "system-key").expect("source should decrypt")
        );
    }

    #[test]
    fn accepts_existing_lua_storage_when_source_is_not_submitted() {
        let protected = protected_source("return function() return true end");

        assert_eq!(
            protected,
            storage_value(
                "ace.lua.healthCheck",
                &json!({"value": protected}),
                "system-key"
            )
            .expect("existing protected value should remain unchanged")
        );
    }

    #[test]
    fn rejects_plain_lua_value_like_php_storage_validator() {
        let error = storage_value(
            "ace.lua.healthCheck",
            &json!({"value": "return function() return true end"}),
            "system-key",
        )
        .expect_err("plain lua source is not a stored protected envelope");

        assert!(matches!(error, AppError::RemoteLuaSourceInvalid(_)));
    }

    #[test]
    fn validates_plain_variable_storage_text_like_php() {
        assert_eq!(
            "enabled\ntrue",
            storage_value(
                "feature.flag",
                &json!({"value": "enabled\ntrue", "lua_source": "ignored"}),
                "system-key"
            )
            .expect("plain variable")
        );
        assert!(matches!(
            storage_value("feature.flag", &json!({"value": "<bad>"}), "system-key"),
            Err(AppError::InvalidText)
        ));
    }

    #[test]
    fn casts_json_compound_values_like_php_for_plain_storage() {
        assert_eq!(
            "Array",
            storage_value("feature.flag", &json!({"value": ["enabled"]}), "system-key")
                .expect("array value follows PHP string cast")
        );
        assert_eq!(
            "Array",
            storage_value(
                "feature.flag",
                &json!({"value": {"enabled": true}}),
                "system-key"
            )
            .expect("object value follows PHP string cast")
        );
    }

    #[test]
    fn validates_existing_lua_value_after_php_string_cast() {
        let error = storage_value(
            "ace.lua.healthCheck",
            &json!({"value": {"format": SOURCE_FORMAT}}),
            "system-key",
        )
        .expect_err("compound lua value casts to Array and then fails JSON parsing");

        assert!(matches!(
            error,
            AppError::RemoteLuaSourceInvalid("RemoteLua 源码密文不是合法 JSON")
        ));
    }

    #[test]
    fn rejects_bad_remote_lua_function_name_like_php() {
        let session = session();
        let error = client_value(
            "ace.lua.bad:name",
            Some(protected_source("return function() return true end")),
            &session,
            "system-key",
        )
        .expect_err("bad function should fail");

        assert!(matches!(error, AppError::RemoteLuaFunctionInvalid));
    }

    fn protected_source(source: &str) -> String {
        json!({
            "format": SOURCE_FORMAT,
            "ciphertext": crypto::encrypt_protected_text_with_iv(
                source,
                "system-key",
                &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
            )
            .expect("source should encrypt"),
            "sourceSha256": crypto::sha256_hex(source),
        })
        .to_string()
    }

    fn session() -> RemoteLuaSession<'static> {
        RemoteLuaSession {
            session_token: "session_token_12345678901234567890",
            session_ticket: "session_ticket_1234567890123456789",
            install_id: "install-1234567890",
            app_code: "APP001",
            app_version: "1.2.3",
        }
    }
}
