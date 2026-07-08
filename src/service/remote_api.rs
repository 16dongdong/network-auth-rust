use std::net::IpAddr;

use axum::http::HeaderMap;
use chrono::{Local, TimeZone};
use subtle::ConstantTimeEq;

use crate::{
    crypto::{self, SignatureInput},
    error::AppError,
    repository::{AuthRepository, RemoteApiLogInput, RemoteApiTokenDetailRow},
};

const SIGNATURE_WINDOW_SECONDS: i64 = 300;
const FLAG_ENABLED: i64 = 1;
const HIGH_RISK_ACTIONS: &[(&str, &str)] = &[
    ("/remote/apps/delete", "remote_apps_delete"),
    ("/remote/apps/generate-keypair", "remote_keypair_rotate"),
    ("/remote/apps/status", "remote_apps_status"),
    ("/remote/variables/delete", "remote_vars_delete"),
    ("/remote/variables/status", "remote_vars_status"),
    ("/remote/cards/delete", "remote_cards_delete"),
    ("/remote/cards/status", "remote_cards_status"),
    ("/remote/cards/revoke", "remote_cards_revoke"),
    ("/remote/config/set", "remote_config_set"),
    ("/remote/apps/api/update", "remote_api_update"),
    (
        "/remote/cloud-storage/files/upload",
        "remote_cloud_file_upload",
    ),
    (
        "/remote/cloud-storage/files/delete",
        "remote_cloud_file_delete",
    ),
    (
        "/remote/cloud-storage/config/save",
        "remote_cloud_config_save",
    ),
    (
        "/remote/cloud-storage/download-token/refresh",
        "remote_cloud_token_refresh",
    ),
    (
        "/remote/cloud-storage/download-token/status",
        "remote_cloud_token_status",
    ),
];

#[derive(Clone)]
pub struct RemoteApiService {
    repository: AuthRepository,
    system_key: String,
}

pub struct RemoteApiRequest<'a> {
    pub method: &'a str,
    pub route: &'a str,
    pub headers: &'a HeaderMap,
    pub body: &'a [u8],
    pub ip: &'a str,
}

pub struct RemoteApiContext {
    pub token_id: u64,
    pub access_key: String,
    pub actor_name: String,
}

struct SignedHeaders {
    access_key: String,
    timestamp: String,
    nonce: String,
    signature: String,
}

impl RemoteApiService {
    pub fn new(repository: AuthRepository, system_key: String) -> Self {
        Self {
            repository,
            system_key,
        }
    }

    pub async fn authenticate(
        &self,
        request: &RemoteApiRequest<'_>,
    ) -> Result<RemoteApiContext, AppError> {
        let access_key = header_text(request.headers, "x-remote-access-key").unwrap_or_default();
        match self.authenticate_inner(request).await {
            Ok(context) => Ok(context),
            Err(error) => {
                self.record_failure(None, &access_key, request, &error)
                    .await;
                Err(error)
            }
        }
    }

    pub async fn record_route_not_found(
        &self,
        context: &RemoteApiContext,
        request: &RemoteApiRequest<'_>,
    ) {
        self.record_log(
            Some(context.token_id),
            &context.access_key,
            request,
            None,
            "failed",
            AppError::RemoteApiRouteNotFound.error_code(),
            &AppError::RemoteApiRouteNotFound.to_string(),
        )
        .await;
    }

    pub async fn record_success(
        &self,
        context: &RemoteApiContext,
        request: &RemoteApiRequest<'_>,
        target_app_id: Option<u64>,
    ) {
        self.record_log(
            Some(context.token_id),
            &context.access_key,
            request,
            target_app_id,
            "success",
            "",
            "OK",
        )
        .await;
    }

    pub async fn record_context_failure(
        &self,
        context: &RemoteApiContext,
        request: &RemoteApiRequest<'_>,
        target_app_id: Option<u64>,
        error: &AppError,
    ) {
        self.record_log(
            Some(context.token_id),
            &context.access_key,
            request,
            target_app_id,
            "failed",
            error.error_code(),
            &error.to_string(),
        )
        .await;
    }

    pub async fn target_app_id(
        &self,
        payload: &serde_json::Value,
    ) -> Result<Option<u64>, AppError> {
        if let Some(app_id) = payload_app_id(payload) {
            return Ok(Some(app_id));
        }
        let app_code = payload_string(payload, "app_code");
        if app_code.is_empty() {
            return Ok(None);
        }
        self.repository.find_app_id_by_code(&app_code).await
    }

    pub async fn require_app_id(&self, payload: &serde_json::Value) -> Result<u64, AppError> {
        if let Some(app_id) = payload_app_id(payload) {
            return Ok(app_id);
        }
        let app_code = payload_string(payload, "app_code");
        if app_code.is_empty() {
            return Err(AppError::AppNotFound);
        }
        self.repository
            .find_app_id_by_code(&app_code)
            .await?
            .ok_or(AppError::AppNotFound)
    }

    pub async fn require_app_code(&self, payload: &serde_json::Value) -> Result<String, AppError> {
        let app_code = payload_string(payload, "app_code");
        if !app_code.is_empty() {
            return Ok(app_code);
        }
        let Some(app_id) = payload_app_id(payload) else {
            return Err(AppError::AppNotFound);
        };
        self.repository
            .find_app_by_id(app_id)
            .await?
            .map(|app| app.app_code)
            .ok_or(AppError::AppNotFound)
    }

    pub async fn app_ids_from_codes(
        &self,
        app_codes: &serde_json::Value,
    ) -> Result<Vec<u64>, AppError> {
        let serde_json::Value::Array(values) = app_codes else {
            return Err(AppError::InvalidAppCodes);
        };
        let mut app_ids = Vec::new();
        let mut seen_codes = std::collections::HashSet::new();
        for value in values {
            let app_code = php_app_code_string(value);
            if !seen_codes.insert(app_code.clone()) {
                continue;
            }
            let app_code = app_code.trim().to_string();
            let app_id = self
                .repository
                .find_app_id_by_code(&app_code)
                .await?
                .ok_or(AppError::AppNotFound)?;
            app_ids.push(app_id);
        }
        if app_ids.is_empty() {
            return Err(AppError::InvalidAppCodes);
        }
        Ok(app_ids)
    }

    pub async fn record_high_risk_audit(
        &self,
        route: &str,
        context: &RemoteApiContext,
        target_app_id: Option<u64>,
        ip: &str,
    ) {
        let Some(action) = remote_high_risk_action(route) else {
            return;
        };
        let message = format!(
            "远程 API 执行高危操作：{route}，Token：{}",
            context.actor_name
        );
        let _ = self
            .repository
            .write_audit(target_app_id, None, action, &message, ip)
            .await;
    }

    async fn authenticate_inner(
        &self,
        request: &RemoteApiRequest<'_>,
    ) -> Result<RemoteApiContext, AppError> {
        let headers = signed_headers(request.headers)?;
        let token = self
            .load_usable_token(&headers.access_key, request.ip)
            .await?;
        let secret = crypto::decrypt_protected_text(&token.secret_cipher, &self.system_key)?;
        assert_signature(request, &headers, &secret)?;
        self.reserve_nonce(token.id, &headers.nonce, &headers.timestamp)
            .await?;
        self.repository
            .touch_remote_api_token(token.id, request.ip, Local::now().naive_local())
            .await?;
        let actor_name = if token.name.trim().is_empty() {
            token.access_key.clone()
        } else {
            token.name.trim().to_string()
        };
        Ok(RemoteApiContext {
            token_id: token.id,
            access_key: token.access_key,
            actor_name,
        })
    }

    async fn load_usable_token(
        &self,
        access_key: &str,
        ip: &str,
    ) -> Result<RemoteApiTokenDetailRow, AppError> {
        let token = self
            .repository
            .find_remote_api_token_by_access_key(access_key)
            .await?
            .ok_or(AppError::RemoteApiAccessTokenInvalid)?;
        if token.status != FLAG_ENABLED {
            return Err(AppError::RemoteApiTokenDisabled);
        }
        if token
            .expires_at
            .is_some_and(|expires_at| expires_at <= Local::now().naive_local())
        {
            return Err(AppError::RemoteApiTokenExpired);
        }
        assert_ip_allowed(ip, &token.ip_allowlist_json)?;
        Ok(token)
    }

    async fn reserve_nonce(
        &self,
        token_id: u64,
        nonce: &str,
        timestamp: &str,
    ) -> Result<(), AppError> {
        let timestamp = timestamp
            .parse::<i64>()
            .map_err(|_| AppError::RemoteApiStaleRequest)?;
        let expires_at = Local
            .timestamp_opt(timestamp + SIGNATURE_WINDOW_SECONDS, 0)
            .single()
            .ok_or(AppError::RemoteApiStaleRequest)?
            .naive_local();
        let reserved = self
            .repository
            .reserve_remote_api_nonce(token_id, &crypto::sha256_hex(nonce), expires_at)
            .await?;
        if reserved {
            return Ok(());
        }
        Err(AppError::RemoteApiReplayRequest)
    }

    async fn record_failure(
        &self,
        token_id: Option<u64>,
        access_key: &str,
        request: &RemoteApiRequest<'_>,
        error: &AppError,
    ) {
        self.record_log(
            token_id,
            access_key,
            request,
            None,
            "failed",
            error.error_code(),
            &error.to_string(),
        )
        .await;
    }

    async fn record_log(
        &self,
        token_id: Option<u64>,
        access_key: &str,
        request: &RemoteApiRequest<'_>,
        target_app_id: Option<u64>,
        status: &str,
        error_code: &str,
        message: &str,
    ) {
        let _ = self
            .repository
            .write_remote_api_log(&RemoteApiLogInput {
                token_id,
                access_key: access_key.to_string(),
                route: request.route.to_string(),
                target_app_id,
                request_hash: crypto::sha256_hex_bytes(request.body),
                status: status.to_string(),
                error_code: error_code.to_string(),
                message: message.to_string(),
                ip: request.ip.to_string(),
            })
            .await;
    }
}

fn php_app_code_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => String::new(),
        serde_json::Value::Bool(true) => "1".to_string(),
        serde_json::Value::Bool(false) => String::new(),
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::String(text) => text.to_string(),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => "Array".to_string(),
    }
}

fn payload_app_id(payload: &serde_json::Value) -> Option<u64> {
    payload
        .get("app_id")
        .and_then(|value| match value {
            serde_json::Value::Number(number) => number.as_u64(),
            serde_json::Value::String(text) => text.trim().parse::<u64>().ok(),
            _ => None,
        })
        .filter(|app_id| *app_id > 0)
}

fn payload_string(payload: &serde_json::Value, key: &str) -> String {
    payload
        .get(key)
        .and_then(|value| match value {
            serde_json::Value::String(text) => Some(text.trim().to_string()),
            serde_json::Value::Number(number) => Some(number.to_string()),
            _ => None,
        })
        .unwrap_or_default()
}

fn remote_high_risk_action(route: &str) -> Option<&'static str> {
    HIGH_RISK_ACTIONS
        .iter()
        .find_map(|(remote_route, action)| (*remote_route == route).then_some(*action))
}

fn signed_headers(headers: &HeaderMap) -> Result<SignedHeaders, AppError> {
    Ok(SignedHeaders {
        access_key: access_key(&required_header(headers, "x-remote-access-key")?)?,
        timestamp: fresh_timestamp(&required_header(headers, "x-timestamp")?)?,
        nonce: nonce(&required_header(headers, "x-nonce")?)?,
        signature: signature(&required_header(headers, "x-signature")?)?,
    })
}

fn required_header(headers: &HeaderMap, name: &str) -> Result<String, AppError> {
    header_text(headers, name).ok_or(AppError::RemoteApiHeaderMissing)
}

fn header_text(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn access_key(value: &str) -> Result<String, AppError> {
    if (32..=64).contains(&value.len()) && is_token_text(value) {
        return Ok(value.to_string());
    }
    Err(AppError::RemoteApiAccessTokenInvalid)
}

fn fresh_timestamp(value: &str) -> Result<String, AppError> {
    let timestamp = value
        .parse::<i64>()
        .map_err(|_| AppError::RemoteApiStaleRequest)?;
    if (Local::now().timestamp() - timestamp).abs() <= SIGNATURE_WINDOW_SECONDS {
        return Ok(value.to_string());
    }
    Err(AppError::RemoteApiStaleRequest)
}

fn nonce(value: &str) -> Result<String, AppError> {
    if (16..=64).contains(&value.len()) && is_token_text(value) {
        return Ok(value.to_string());
    }
    Err(AppError::RemoteApiInvalidNonce)
}

fn signature(value: &str) -> Result<String, AppError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Ok(value.to_string());
    }
    Err(AppError::RemoteApiBadSignature)
}

fn is_token_text(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn assert_signature(
    request: &RemoteApiRequest<'_>,
    headers: &SignedHeaders,
    secret: &str,
) -> Result<(), AppError> {
    let expected = remote_signature(
        secret,
        request.method,
        request.route,
        &headers.timestamp,
        &headers.nonce,
        request.body,
    )?;
    if bool::from(expected.as_bytes().ct_eq(headers.signature.as_bytes())) {
        return Ok(());
    }
    Err(AppError::RemoteApiBadSignature)
}

fn remote_signature(
    secret: &str,
    method: &str,
    route: &str,
    timestamp: &str,
    nonce: &str,
    body: &[u8],
) -> Result<String, AppError> {
    crypto::request_signature(
        secret.as_bytes(),
        &SignatureInput {
            method,
            route,
            timestamp,
            nonce,
            body,
        },
    )
}

fn assert_ip_allowed(ip: &str, allowlist_json: &str) -> Result<(), AppError> {
    let allowlist = serde_json::from_str::<Vec<String>>(allowlist_json)
        .map_err(|_| AppError::RemoteApiIpDenied)?;
    if allowlist.is_empty() {
        return Ok(());
    }
    let ip_addr = ip
        .parse::<IpAddr>()
        .map_err(|_| AppError::RemoteApiIpDenied)?;
    if allowlist.iter().any(|rule| ip_matches_rule(ip_addr, rule)) {
        return Ok(());
    }
    Err(AppError::RemoteApiIpDenied)
}

fn ip_matches_rule(ip: IpAddr, rule: &str) -> bool {
    let rule = rule.trim();
    if let Some((network, prefix)) = rule.split_once('/') {
        return prefix
            .parse::<u8>()
            .ok()
            .zip(network.parse::<IpAddr>().ok())
            .is_some_and(|(prefix, network)| ip_in_cidr(ip, network, prefix));
    }
    rule.parse::<IpAddr>()
        .is_ok_and(|allowed_ip| allowed_ip == ip)
}

fn ip_in_cidr(ip: IpAddr, network: IpAddr, prefix: u8) -> bool {
    let ip_octets = ip_bytes(ip);
    let network_octets = ip_bytes(network);
    if ip_octets.len() != network_octets.len() || prefix as usize > ip_octets.len() * 8 {
        return false;
    }
    let full_bytes = usize::from(prefix / 8);
    let remaining_bits = prefix % 8;
    if ip_octets[..full_bytes] != network_octets[..full_bytes] {
        return false;
    }
    if remaining_bits == 0 {
        return true;
    }
    let mask = 0xff_u8 << (8 - remaining_bits);
    (ip_octets[full_bytes] & mask) == (network_octets[full_bytes] & mask)
}

fn ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(value) => value.octets().to_vec(),
        IpAddr::V6(value) => value.octets().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn remote_signature_matches_documented_canonical_format() {
        let body = br#"{"name":"noticeText","value":"hello","scope":"public","status":1}"#;
        let signature = remote_signature(
            "remote-secret",
            "POST",
            "/remote/variables/upsert",
            "1781180000",
            "nonce_1234567890",
            body,
        )
        .expect("signature");
        let canonical = "POST\n/remote/variables/upsert\n1781180000\nnonce_1234567890\na5244e40bbd569f552e3182aa1847c40cde3654d6dbbb20df7eb4dc3e7b7789e";

        assert_eq!(
            crypto::hmac_sha256_hex_string("remote-secret".as_bytes(), canonical)
                .expect("expected"),
            signature
        );
    }

    #[test]
    fn validates_remote_signature_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-remote-access-key",
            HeaderValue::from_static("abcdefghijklmnopqrstuvwxyzABCDEF"),
        );
        headers.insert("x-timestamp", HeaderValue::from_static("1"));
        headers.insert("x-nonce", HeaderValue::from_static("nonce_1234567890"));
        headers.insert(
            "x-signature",
            HeaderValue::from_static(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
        );

        assert!(matches!(
            signed_headers(&headers),
            Err(AppError::RemoteApiStaleRequest)
        ));
    }

    #[test]
    fn matches_ip_allowlist_rules() {
        assert!(ip_matches_rule(
            "203.0.113.10".parse().expect("ip"),
            "203.0.113.10"
        ));
        assert!(ip_matches_rule(
            "203.0.113.20".parse().expect("ip"),
            "203.0.113.0/24"
        ));
        assert!(ip_matches_rule(
            "2001:db8::1".parse().expect("ip"),
            "2001:db8::/32"
        ));
        assert!(!ip_matches_rule(
            "203.0.114.20".parse().expect("ip"),
            "203.0.113.0/24"
        ));
    }

    #[test]
    fn rejects_invalid_ip_allowlist_json() {
        assert!(matches!(
            assert_ip_allowed("203.0.113.10", "bad-json"),
            Err(AppError::RemoteApiIpDenied)
        ));
    }

    #[test]
    fn casts_remote_app_codes_like_php_strval_before_unique() {
        let values = [
            serde_json::Value::Null,
            serde_json::Value::Bool(false),
            serde_json::Value::Bool(true),
            serde_json::json!(" app "),
            serde_json::json!("app"),
            serde_json::json!("app"),
            serde_json::json!([]),
            serde_json::json!({ "app_code": "demo" }),
        ];
        let mut seen_codes = std::collections::HashSet::new();
        let app_codes = values
            .iter()
            .map(php_app_code_string)
            .filter(|app_code| seen_codes.insert(app_code.clone()))
            .collect::<Vec<_>>();

        assert_eq!(vec!["", "1", " app ", "app", "Array"], app_codes);
    }
}
