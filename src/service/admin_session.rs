use chrono::{Duration, Local, NaiveDateTime, TimeZone};
use md5::{Digest as Md5Digest, Md5};
use serde::Serialize;
use serde_json::Value;
use subtle::ConstantTimeEq;

use crate::{
    crypto::{self, GcmPayload, SignatureInput},
    error::AppError,
    repository::{AdminSessionRow, AuthRepository, NewAdminSession},
};

const SESSION_TTL_SECONDS: i64 = 3600;
const SIGNATURE_WINDOW_SECONDS: i64 = 300;

#[derive(Clone)]
pub struct AdminSessionService {
    repository: AuthRepository,
    system_key: String,
    admin_token_hash: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CreatedAdminSession {
    pub session_token: String,
    pub session_key: String,
    pub expires_at: String,
    pub admin_username: String,
    pub demo_mode: bool,
}

pub struct AdminSignedRequest<'a> {
    pub method: &'a str,
    pub route: &'a str,
    pub session_token: &'a str,
    pub timestamp: &'a str,
    pub nonce: &'a str,
    pub signature: &'a str,
    pub body: &'a [u8],
    pub ip: &'a str,
}

pub struct AdminSessionContext {
    pub session_id: u64,
    pub key: Vec<u8>,
    pub route: String,
    pub nonce: String,
    pub ip: String,
    pub admin_username: String,
    pub session_expires_at: String,
    pub payload: Value,
}

pub struct AdminUploadSessionContext {
    pub session_id: u64,
}

impl AdminSessionService {
    pub fn new(repository: AuthRepository, system_key: String, admin_token_hash: String) -> Self {
        Self {
            repository,
            system_key,
            admin_token_hash,
        }
    }

    pub async fn create_trusted_from_cookie(
        &self,
        cookie_value: &str,
        ip: &str,
    ) -> Result<CreatedAdminSession, AppError> {
        let admin_username = self.admin_username_from_cookie(cookie_value).await?;
        self.create_session(ip, &admin_username).await
    }

    pub async fn admin_username_from_cookie(&self, cookie_value: &str) -> Result<String, AppError> {
        self.validate_admin_cookie(cookie_value).await
    }

    pub async fn create(
        &self,
        admin_token: &str,
        ip: &str,
    ) -> Result<CreatedAdminSession, AppError> {
        self.assert_admin_token(admin_token)?;
        self.create_session(ip, "").await
    }

    pub async fn open(
        &self,
        request: &AdminSignedRequest<'_>,
    ) -> Result<AdminSessionContext, AppError> {
        let timestamp = self.fresh_timestamp(request.timestamp)?;
        let nonce = valid_nonce(request.nonce)?;
        let signature = valid_signature(request.signature)?;
        let session = self.load_session(request.session_token, request.ip).await?;
        let raw_key = self.session_key(&session)?;
        self.assert_signature(request, signature, &raw_key)?;
        self.reserve_nonce(session.id, nonce, timestamp).await?;
        let payload = self.decrypt_payload(request, &raw_key)?;
        self.repository
            .touch_admin_session(session.id, Local::now().naive_local())
            .await?;
        Ok(AdminSessionContext {
            session_id: session.id,
            key: raw_key,
            route: request.route.to_string(),
            nonce: nonce.to_string(),
            ip: request.ip.to_string(),
            admin_username: session.admin_username,
            session_expires_at: format_datetime(session.expires_at),
            payload,
        })
    }

    pub async fn open_upload(
        &self,
        session_token: &str,
        ip: &str,
    ) -> Result<AdminUploadSessionContext, AppError> {
        let session = self.load_session(session_token, ip).await?;
        self.repository
            .touch_admin_session(session.id, Local::now().naive_local())
            .await?;
        Ok(AdminUploadSessionContext {
            session_id: session.id,
        })
    }

    pub fn encrypt_response(
        &self,
        context: &AdminSessionContext,
        data: Value,
    ) -> Result<Value, AppError> {
        let body = serde_json::to_string(&normalize_response_ids(data))
            .map_err(|_| AppError::CryptoError("响应序列化失败"))?;
        let encrypted = crypto::encrypt_gcm(&body, &context.key, &response_aad(context));
        Ok(serde_json::json!({
            "encrypted": true,
            "payload": encrypted?,
        }))
    }

    fn assert_admin_token(&self, token: &str) -> Result<(), AppError> {
        if self.admin_token_hash.is_empty()
            || !constant_time_str_eq(&self.admin_token_hash, &crypto::sha256_hex(token))
        {
            return Err(AppError::AdminUnauthorized);
        }
        Ok(())
    }

    async fn validate_admin_cookie(&self, cookie_value: &str) -> Result<String, AppError> {
        let decoded = crypto::decrypt_protected_text(cookie_value, &self.system_key)
            .map_err(|_| AppError::AdminLoginRequired)?;
        let (username, session) = parse_admin_cookie_payload(&decoded)?;
        let admin = self
            .repository
            .find_admin_by_username(username)
            .await?
            .ok_or(AppError::AdminLoginRequired)?;
        let expected = admin_cookie_session(&admin.username, &admin.password, &self.system_key);
        if !constant_time_str_eq(&expected, session) {
            return Err(AppError::AdminLoginRequired);
        }
        Ok(admin.username)
    }

    async fn create_session(
        &self,
        ip: &str,
        admin_username: &str,
    ) -> Result<CreatedAdminSession, AppError> {
        let session_token = crypto::token(32);
        let session_key = crypto::token(32);
        let expires_at = Local::now().naive_local() + Duration::seconds(SESSION_TTL_SECONDS);
        let key_cipher = crypto::encrypt_protected_text(&session_key, &self.system_key)?;
        let token_hash = crypto::sha256_hex(&session_token);
        self.repository
            .create_admin_session(&NewAdminSession {
                token_hash: &token_hash,
                key_cipher: &key_cipher,
                ip,
                admin_username,
                expires_at,
                status: 1,
            })
            .await?;
        Ok(CreatedAdminSession {
            session_token,
            session_key,
            expires_at: format_datetime(expires_at),
            admin_username: admin_username.to_string(),
            demo_mode: false,
        })
    }

    async fn load_session(
        &self,
        session_token: &str,
        ip: &str,
    ) -> Result<AdminSessionRow, AppError> {
        let token_hash = crypto::sha256_hex(session_token);
        let session = self
            .repository
            .find_admin_session_by_token_hash(&token_hash)
            .await?
            .ok_or(AppError::AdminSessionInvalid)?;
        if session.status != 1 || session.expires_at < Local::now().naive_local() {
            return Err(AppError::AdminSessionInvalid);
        }
        if session.ip != ip {
            return Err(AppError::AdminSessionIpChanged);
        }
        Ok(session)
    }

    fn session_key(&self, session: &AdminSessionRow) -> Result<Vec<u8>, AppError> {
        let key_text = crypto::decrypt_protected_text(&session.key_cipher, &self.system_key)?;
        let raw_key = crypto::decode_base64_url(&key_text)?;
        if raw_key.len() != 32 {
            return Err(AppError::AdminSessionInvalid);
        }
        Ok(raw_key)
    }

    fn assert_signature(
        &self,
        request: &AdminSignedRequest<'_>,
        signature: &str,
        raw_key: &[u8],
    ) -> Result<(), AppError> {
        let expected = crypto::request_signature(
            raw_key,
            &SignatureInput {
                method: request.method,
                route: request.route,
                timestamp: request.timestamp,
                nonce: request.nonce,
                body: request.body,
            },
        )?;
        if !constant_time_str_eq(&expected, signature) {
            return Err(AppError::BadSignature);
        }
        Ok(())
    }

    async fn reserve_nonce(
        &self,
        session_id: u64,
        nonce: &str,
        timestamp: i64,
    ) -> Result<(), AppError> {
        let expires_at = Local
            .timestamp_opt(timestamp + SIGNATURE_WINDOW_SECONDS, 0)
            .single()
            .ok_or(AppError::StaleRequest)?
            .naive_local();
        let nonce_hash = crypto::sha256_hex(nonce);
        if !self
            .repository
            .reserve_admin_nonce(session_id, &nonce_hash, expires_at)
            .await?
        {
            return Err(AppError::ReplayRequest);
        }
        Ok(())
    }

    fn decrypt_payload(
        &self,
        request: &AdminSignedRequest<'_>,
        raw_key: &[u8],
    ) -> Result<Value, AppError> {
        let payload: GcmPayload =
            serde_json::from_slice(request.body).map_err(|_| AppError::RequestJsonInvalid)?;
        let plaintext = crypto::decrypt_gcm(&payload, raw_key, &request_aad(request))?;
        let decoded: Value = serde_json::from_str(&plaintext).map_err(|_| AppError::InvalidJson)?;
        match decoded {
            Value::Object(_) => Ok(decoded),
            _ => Err(AppError::InvalidJson),
        }
    }

    fn fresh_timestamp(&self, timestamp: &str) -> Result<i64, AppError> {
        let timestamp = timestamp
            .parse::<i64>()
            .map_err(|_| AppError::StaleRequest)?;
        if (Local::now().timestamp() - timestamp).abs() > SIGNATURE_WINDOW_SECONDS {
            return Err(AppError::StaleRequest);
        }
        Ok(timestamp)
    }
}

fn parse_admin_cookie_payload(decoded: &str) -> Result<(&str, &str), AppError> {
    let (username, session) = decoded
        .split_once('\t')
        .ok_or(AppError::AdminLoginRequired)?;
    let username = username.trim();
    if username.is_empty() || session.is_empty() {
        return Err(AppError::AdminLoginRequired);
    }
    Ok((username, session))
}

pub fn admin_cookie_session(username: &str, password_hash: &str, system_key: &str) -> String {
    md5_hex(&format!(
        "{}{}{}",
        username,
        password_hash,
        crypto::sha256_hex(system_key)
    ))
}

fn md5_hex(value: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

fn valid_nonce(nonce: &str) -> Result<&str, AppError> {
    if nonce.len() < 16 || nonce.len() > 64 || !nonce.bytes().all(is_nonce_byte) {
        return Err(AppError::InvalidNonce);
    }
    Ok(nonce)
}

fn valid_signature(signature: &str) -> Result<&str, AppError> {
    if signature.len() != 64 || !signature.bytes().all(is_lower_hex_byte) {
        return Err(AppError::BadSignature);
    }
    Ok(signature)
}

fn is_lower_hex_byte(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

fn is_nonce_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn constant_time_str_eq(left: &str, right: &str) -> bool {
    left.as_bytes().ct_eq(right.as_bytes()).unwrap_u8() == 1
}

fn request_aad(request: &AdminSignedRequest<'_>) -> String {
    format!(
        "{}\n{}\n{}\n{}",
        request.method.to_uppercase(),
        request.route,
        request.timestamp,
        request.nonce
    )
}

fn response_aad(context: &AdminSessionContext) -> String {
    format!("RESPONSE\n{}\n{}", context.route, context.nonce)
}

fn format_datetime(value: NaiveDateTime) -> String {
    value.format("%Y-%m-%d %H:%M:%S").to_string()
}

fn normalize_response_ids(value: Value) -> Value {
    normalize_response_ids_for_key(value, "")
}

fn normalize_response_ids_for_key(value: Value, key: &str) -> Value {
    match value {
        Value::Array(items) if is_response_id_list_key(key) => {
            Value::Array(items.into_iter().map(normalize_response_id_value).collect())
        }
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| normalize_response_ids_for_key(item, ""))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(child_key, child_value)| {
                    let normalized = normalize_response_ids_for_key(child_value, &child_key);
                    (child_key, normalized)
                })
                .collect(),
        ),
        scalar if is_response_id_key(key) => normalize_response_id_value(scalar),
        scalar => scalar,
    }
}

fn normalize_response_id_value(value: Value) -> Value {
    match value {
        Value::Number(number) if number.is_u64() || number.is_i64() => {
            Value::String(number.to_string())
        }
        Value::String(text) if text.bytes().all(|byte| byte.is_ascii_digit()) => {
            Value::String(text)
        }
        other => other,
    }
}

fn is_response_id_key(key: &str) -> bool {
    key == "id" || key.ends_with("_id")
}

fn is_response_id_list_key(key: &str) -> bool {
    key.ends_with("_ids")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_php_admin_cookie_session_shape() {
        let session = admin_cookie_session("admin", "$2y$10$examplePasswordHash", "system-key");

        assert_eq!(32, session.len());
        assert!(session.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn rejects_invalid_nonce_values() {
        assert!(valid_nonce("abcdefghijklmnop").is_ok());
        assert!(valid_nonce("short").is_err());
        assert!(valid_nonce("invalid+invalid+invalid").is_err());
    }

    #[test]
    fn normalizes_response_ids_as_strings() {
        let normalized = normalize_response_ids(serde_json::json!({
            "id": 7,
            "app_id": "8",
            "card_ids": [9, "10", "bad"],
            "nested": {"device_id": 11}
        }));

        assert_eq!(
            serde_json::json!({
                "id": "7",
                "app_id": "8",
                "card_ids": ["9", "10", "bad"],
                "nested": {"device_id": "11"}
            }),
            normalized
        );
    }

    #[test]
    fn serializes_demo_mode_like_php_session_endpoint() {
        let session = CreatedAdminSession {
            session_token: "session-token".to_string(),
            session_key: "session-key".to_string(),
            expires_at: "2026-06-11 22:00:00".to_string(),
            admin_username: "admin".to_string(),
            demo_mode: true,
        };

        assert_eq!(
            serde_json::json!({
                "session_token": "session-token",
                "session_key": "session-key",
                "expires_at": "2026-06-11 22:00:00",
                "admin_username": "admin",
                "demo_mode": true
            }),
            serde_json::to_value(session).expect("session should serialize")
        );
    }
}
