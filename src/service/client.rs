use std::collections::HashSet;

use chrono::{Duration, Local, NaiveDateTime, TimeZone};
use hmac::{Hmac, Mac};
use serde_json::{Map, Value, json};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::remote_lua::{self, RemoteLuaSession};
use crate::{
    crypto,
    error::AppError,
    repository::{
        AppDetailRow, AuthRepository, CardRow, ClientLoginCard, ClientLoginCommand,
        ClientSecurityActionRecord, ClientSecurityMessageRecord, ClientSecurityReportCommand,
        ClientSecurityReportRecord, ClientSecurityReportResult, ClientSecurityReportRow,
        ClientSessionRotation, ClientSessionRow, ClientUnbindCommand, RemoteConfigRow,
        SecurityPolicyRow, SecurityReportCountFilters,
    },
};

type HmacSha256 = Hmac<Sha256>;

const FLAG_ENABLED: i64 = 1;
const FLAG_DISABLED: i64 = 0;
const DISABLED_VERIFICATION_DURATION_SECONDS: i64 = 315_360_000;
const LOGIN_CHALLENGE_TTL_SECONDS: i64 = 300;
const SIGNATURE_WINDOW_SECONDS: i64 = 300;
const EPHEMERAL_TICKET_TTL_SECONDS: i64 = 120;
const CLIENT_CRYPTO_MAX_PLAINTEXT_BYTES: usize = 65_536;
const CLIENT_DOWNLOAD_TICKET_TTL_SECONDS: i64 = 300;
const DEVICE_TOUCH_INTERVAL_SECONDS: i64 = 60;
const LOGIN_CHALLENGE_VERSION: i64 = 1;
const DIRECT_EPHEMERAL_CHALLENGE_PREFIX: &str = "ephemeral.";
const DIRECT_EPHEMERAL_RANDOM_MIN_LENGTH: usize = 20;
const PERMANENT_CARD_EXPIRES_AT: &str = "9999-12-31 23:59:59";
const PROOF_MODE_LOCAL_KEY: &str = "local_key_v1";
const PROOF_MODE_EPHEMERAL_TICKET: &str = "ephemeral_ticket_v1";
const DEVICE_KEY_ALGORITHM: &str = "ecdsa_p256_sha256_v1";
const SECURITY_EVENT_TYPES: &[&str] = &[
    "debugger_detected",
    "tracer_detected",
    "hook_detected",
    "instrumentation_detected",
    "module_tampered",
    "signature_mismatch",
    "emulator_detected",
    "root_detected",
    "attestation_failed",
    "policy_violation",
];
const SECURITY_RISK_LEVELS: &[&str] = &["low", "medium", "high", "critical"];
const SECURITY_ACTIONS: &[&str] = &[
    "record_only",
    "manual_review",
    "kick_session",
    "disable_device",
    "disable_card",
];
const SECURITY_POLICY_MODES: &[&str] = &["honor_client", "bounded_client", "server_score"];
const SECURITY_TARGET_FIELDS: &[&str] = &[
    "card_id",
    "device_id",
    "session_id",
    "card_hash",
    "device_hash",
];
const SECURITY_EVIDENCE_FIELDS: &[&str] = &[
    "detector",
    "matched_rule",
    "module_hash",
    "symbol_hash",
    "process_hashes",
    "debug_port_open",
    "hook_count",
    "attestation_verdict",
];
const SECURITY_ATTESTATION_FIELDS: &[&str] = &[
    "provider",
    "nonce_hash",
    "challenge_hash",
    "verdict",
    "key_id",
    "certificate_hash",
    "error_code",
];
const SECURITY_SESSION_RATE_LIMIT: i64 = 10;
const SECURITY_CARD_RATE_LIMIT: i64 = 20;
const SECURITY_DEVICE_RATE_LIMIT: i64 = 20;
const SECURITY_IP_RATE_LIMIT: i64 = 60;
const SECURITY_CRITICAL_FALLBACK_SECONDS: i64 = 300;
const CLIENT_ROUTES: &[ClientRouteDefinition] = &[
    ClientRouteDefinition::new("/login/challenge", "login_challenge"),
    ClientRouteDefinition::new("/login", "login"),
    ClientRouteDefinition::new("/heartbeat", "heartbeat"),
    ClientRouteDefinition::new("/config", "config"),
    ClientRouteDefinition::new("/variable", "variable"),
    ClientRouteDefinition::new("/cloud/download-ticket", "cloud_download_ticket"),
    ClientRouteDefinition::new("/security/report", "security_report"),
    ClientRouteDefinition::new("/notice", "notice"),
    ClientRouteDefinition::new("/unbind", "unbind"),
    ClientRouteDefinition::new("/logout", "logout"),
];

#[derive(Clone)]
pub struct ClientService {
    repository: AuthRepository,
    system_key: String,
}

#[derive(Clone, Copy)]
struct ClientRouteDefinition {
    route: &'static str,
    call_id: &'static str,
}

struct ClientRouteConfig {
    call_id: String,
    enabled: i64,
}

struct ChallengeInput {
    install_id: String,
    device_name: String,
    device_public_key: String,
    device_key_mode: String,
}

struct LoginInput {
    card_key: String,
    challenge_id: String,
    install_id: String,
    device_name: String,
    machine_profile_hash: String,
    timestamp: i64,
    signature: String,
    device_key_mode: String,
    client_version: String,
}

struct UnbindInput {
    card_key: String,
    install_id: String,
    timestamp: i64,
    signature: String,
}

#[derive(Debug, Clone)]
pub struct ClientCryptoContext {
    algorithm: crypto::ClientCryptoAlgorithm,
    session_key: Vec<u8>,
}

struct SecurityReportInput {
    event_id: String,
    event_type: String,
    risk_level: String,
    confidence: i64,
    requested_action: String,
    action_reason: String,
    title: String,
    message: String,
    evidence: Value,
    attestation: Value,
    occurred_at: i64,
    sdk_version: String,
    detector_version: String,
    platform: String,
}

struct LoginChallengeForLogin {
    install_id: String,
    device_name: String,
    device_public_key: String,
    device_key_mode: String,
    challenge_id: String,
    server_nonce: String,
    expires_at: NaiveDateTime,
    stateless: bool,
    direct_ephemeral: bool,
}

struct ClientLoginProof {
    proof_mode: String,
    device_public_key: String,
}

struct ClientSessionInput {
    install_id: String,
    counter: i64,
    timestamp: i64,
    request_nonce: String,
    session_ticket: String,
    signature: String,
}

struct PreparedClientSession {
    current_token_hash: String,
    session: ClientSessionRow,
    card: ClientLoginCard,
    install_id: String,
    request_counter: i64,
    now: NaiveDateTime,
}

struct RotatedClientSession {
    card: ClientLoginCard,
    token: String,
    session_expires_at: NaiveDateTime,
    proof_mode: String,
    session_ticket: Option<String>,
    ticket_expires_at: Option<NaiveDateTime>,
}

struct ClientSecurityPolicy {
    enabled: bool,
    mode: String,
    min_confidence_for_client_action: i64,
    max_client_action: String,
    allowed_client_actions: Vec<String>,
    kick_score: i64,
    disable_device_score: i64,
    disable_card_score: i64,
    client_disable_device_min_score: i64,
    client_disable_card_min_score: i64,
    report_rate_limit_per_minute: i64,
    server_critical_action: String,
    server_high_action: String,
    server_medium_action: String,
    server_low_action: String,
}

struct SecurityDecision {
    action: String,
    action_source: String,
    risk_score: i64,
}

impl ClientRouteDefinition {
    const fn new(route: &'static str, call_id: &'static str) -> Self {
        Self { route, call_id }
    }
}

impl ClientService {
    pub fn new(repository: AuthRepository, system_key: String) -> Self {
        Self {
            repository,
            system_key,
        }
    }

    pub async fn load_app(&self, app_code: &str) -> Result<AppDetailRow, AppError> {
        let normalized_app_code = validate_app_code(app_code)?;
        let app = self
            .repository
            .find_app_by_code(&normalized_app_code)
            .await?
            .ok_or(AppError::AppDisabled)?;
        if app.status != FLAG_ENABLED {
            return Err(AppError::AppDisabled);
        }
        Ok(app)
    }

    pub fn assert_api_access(
        &self,
        app: &AppDetailRow,
        route: &str,
        api_token: &str,
        api_call_id: &str,
    ) -> Result<(), AppError> {
        let config = route_config(app, route)?;
        if config.enabled != FLAG_ENABLED {
            return Err(AppError::ApiDisabled);
        }
        if !constant_eq(
            &resolved_api_token(app, &self.system_key)?,
            api_token.trim(),
        ) {
            return Err(AppError::ApiTokenInvalid);
        }
        if !constant_eq(&config.call_id, api_call_id.trim()) {
            return Err(AppError::ApiCallIdInvalid);
        }
        Ok(())
    }

    pub fn client_success_code(&self, app: &AppDetailRow) -> i64 {
        client_success_code(app.api_success_code)
    }

    pub fn open_encrypted_request(
        &self,
        app: &AppDetailRow,
        route: &str,
        timestamp: &str,
        nonce: &str,
        envelope: &Value,
    ) -> Result<(Value, ClientCryptoContext), AppError> {
        let algorithm = client_crypto_algorithm(envelope, app)?;
        let session_key = client_crypto_session_key(envelope, app, algorithm, &self.system_key)?;
        let plaintext = crypto::decrypt_gcm(
            &client_crypto_gcm_payload(envelope)?,
            &session_key,
            &client_request_aad(route, timestamp, nonce, algorithm),
        )?;
        if plaintext.len() > CLIENT_CRYPTO_MAX_PLAINTEXT_BYTES {
            return Err(AppError::PayloadTooLarge);
        }
        let payload = client_plaintext_payload(&plaintext)?;
        Ok((
            payload,
            ClientCryptoContext {
                algorithm,
                session_key,
            },
        ))
    }

    pub fn encrypt_client_response(
        &self,
        route: &str,
        timestamp: &str,
        nonce: &str,
        context: &ClientCryptoContext,
        payload: &Value,
    ) -> Result<Value, AppError> {
        let plaintext = serde_json::to_string(payload).map_err(|_| AppError::InvalidJson)?;
        let encrypted = crypto::encrypt_gcm(
            &plaintext,
            &context.session_key,
            &client_response_aad(route, timestamp, nonce, context.algorithm),
        )?;
        Ok(client_encrypted_response(context.algorithm, encrypted))
    }

    pub async fn notice(&self, app: &AppDetailRow) -> Result<Value, AppError> {
        let notice = self
            .repository
            .find_remote_config(app.id)
            .await?
            .map(|config| config.notice)
            .unwrap_or_default();
        Ok(json!({ "notice": notice }))
    }

    pub fn login_challenge(&self, app: &AppDetailRow, payload: &Value) -> Result<Value, AppError> {
        let input = challenge_input(payload)?;
        let server_nonce = crypto::token(24);
        let expires_at = Local::now() + Duration::seconds(LOGIN_CHALLENGE_TTL_SECONDS);
        let challenge_id = stateless_login_challenge(
            &self.system_key,
            app,
            &input,
            &server_nonce,
            expires_at.timestamp(),
        )?;
        Ok(json!({
            "challenge_id": challenge_id,
            "server_nonce": server_nonce,
            "expires_at": expires_at.timestamp(),
        }))
    }

    pub async fn card_query(&self, app: &AppDetailRow, payload: &Value) -> Result<Value, AppError> {
        if app.web_card_query_enabled != FLAG_ENABLED {
            return Err(AppError::CardQueryDisabled);
        }
        let card_key = client_card_key(app, &payload_scalar_text(payload, "card_key"))?;
        let card = self.read_card_for_client(app, &card_key).await?;
        Ok(card_query_response(card))
    }

    pub async fn login(
        &self,
        app: &AppDetailRow,
        payload: &Value,
        ip: &str,
    ) -> Result<Value, AppError> {
        let input = login_input(app, payload)?;
        let challenge = login_challenge_for_login(app, &input, &self.system_key)?;
        if challenge.install_id != input.install_id {
            return Err(AppError::LoginChallengeInvalid("登录挑战与设备不匹配"));
        }
        assert_client_timestamp(input.timestamp)?;
        assert_login_client_version(&self.repository, app, &input.client_version).await?;
        let card_hash = card_hash(app, &input.card_key);
        let card = self.read_card_for_client(app, &input.card_key).await?;
        let login_proof = login_proof_for_card(&card, &card_hash, &input, &challenge)?;
        let proof_mode = login_proof.proof_mode;
        let device_public_key = login_proof.device_public_key;
        let now = Local::now().naive_local();
        let token = crypto::token(32);
        let session_ticket = login_session_ticket(&proof_mode);
        let ticket_hash = session_ticket
            .as_ref()
            .map(|ticket| session_ticket_hash(ticket, &self.system_key))
            .transpose()?;
        let ticket_expires_at = session_ticket
            .as_ref()
            .map(|_| now + Duration::seconds(EPHEMERAL_TICKET_TTL_SECONDS));
        let challenge_nonce_hash = login_challenge_nonce_hash(&challenge);
        let challenge_expires_at = login_challenge_expires_at(&challenge);
        let bind_region = if app.login_ip_binding_enabled == FLAG_ENABLED {
            login_ip_binding_key(ip)?
        } else {
            String::new()
        };
        let command = ClientLoginCommand {
            app_id: app.id,
            verification_enabled: app.verification_enabled == FLAG_ENABLED,
            device_binding_enabled: app.device_binding_enabled == FLAG_ENABLED,
            shared_cards_enabled: app.shared_cards_enabled == FLAG_ENABLED,
            login_ip_binding_enabled: app.login_ip_binding_enabled == FLAG_ENABLED,
            app_max_devices: app.max_devices,
            heartbeat_interval: app.heartbeat_interval,
            card_key: input.card_key.clone(),
            card_hash,
            install_id: input.install_id.clone(),
            device_hash: device_hash(app, &input.install_id),
            device_name: challenge.device_name,
            machine_profile_hash: input.machine_profile_hash,
            ip: ip.to_string(),
            bind_ip: if app.login_ip_binding_enabled == FLAG_ENABLED {
                ip.to_string()
            } else {
                String::new()
            },
            bind_region: bind_region.clone(),
            proof_mode: proof_mode.clone(),
            device_public_key,
            token_hash: session_token_hash(&token, &self.system_key)?,
            ticket_hash,
            ticket_expires_at,
            challenge_nonce_hash,
            challenge_expires_at,
            now,
        };
        let result = self
            .repository
            .create_plain_ephemeral_login(command)
            .await?;
        Ok(login_response(
            app,
            &result.card,
            &token,
            result.session_expires_at,
            &proof_mode,
            session_ticket.as_deref(),
            ticket_expires_at,
            &bind_region,
        ))
    }

    pub async fn unbind(
        &self,
        app: &AppDetailRow,
        payload: &Value,
        ip: &str,
    ) -> Result<Value, AppError> {
        let input = unbind_input(app, payload)?;
        let card_hash = card_hash(app, &input.card_key);
        self.read_card_for_client(app, &input.card_key).await?;
        let Some(device) = self
            .repository
            .find_client_unbind_device(app.id, &input.install_id)
            .await?
        else {
            return Ok(unbind_response(false));
        };
        assert_client_timestamp(input.timestamp)?;
        crypto::verify_p256_signature(
            &device.device_public_key,
            &unbind_canonical(&input.install_id, input.timestamp, &card_hash),
            &input.signature,
        )?;
        let unbound = self
            .repository
            .unbind_client_device(&ClientUnbindCommand {
                app_id: app.id,
                verification_enabled: app.verification_enabled == FLAG_ENABLED,
                card_hash,
                install_id: input.install_id,
                verified_device_public_key: device.device_public_key,
                unbind_interval_seconds: app.unbind_interval_seconds,
                unbind_deduct_seconds: app.unbind_deduct_seconds,
                unbind_deduct_uses: app.unbind_deduct_uses,
                now: Local::now().naive_local(),
                ip: ip.to_string(),
            })
            .await?;
        Ok(unbind_response(unbound))
    }

    pub async fn heartbeat(&self, app: &AppDetailRow, payload: &Value) -> Result<Value, AppError> {
        let prepared_session = self
            .prepare_client_session(app, "/heartbeat", payload)
            .await?;
        let rotated_session = self.rotate_prepared_session(app, prepared_session).await?;
        Ok(heartbeat_response(app, &rotated_session))
    }

    pub async fn config(&self, app: &AppDetailRow, payload: &Value) -> Result<Value, AppError> {
        let prepared_session = self.prepare_client_session(app, "/config", payload).await?;
        let config = self.repository.find_remote_config(app.id).await?;
        let rotated_session = self.rotate_prepared_session(app, prepared_session).await?;
        Ok(config_response(app, &rotated_session, config.as_ref()))
    }

    pub async fn variable(&self, app: &AppDetailRow, payload: &Value) -> Result<Value, AppError> {
        let prepared_session = self
            .prepare_client_session(app, "/variable", payload)
            .await?;
        let name = variable_name(&payload_scalar_text(payload, "name"))?;
        let stored_value = self
            .repository
            .find_readable_remote_variable_value(app.id, &name)
            .await?;
        let install_id = prepared_session.install_id.clone();
        let rotated_session = self.rotate_prepared_session(app, prepared_session).await?;
        let app_version = self.client_app_version(app, payload).await?;
        let value = remote_lua::client_value(
            &name,
            stored_value,
            &RemoteLuaSession {
                session_token: &rotated_session.token,
                session_ticket: rotated_session.session_ticket.as_deref().unwrap_or(""),
                install_id: &install_id,
                app_code: &app.app_code,
                app_version: &app_version,
            },
            &self.system_key,
        )?;
        Ok(variable_response(app, &rotated_session, value))
    }

    pub async fn cloud_download_ticket(
        &self,
        app: &AppDetailRow,
        payload: &Value,
    ) -> Result<Value, AppError> {
        let prepared_session = self
            .prepare_client_session(app, "/cloud/download-ticket", payload)
            .await?;
        let file_key = cloud_file_key(&payload_scalar_text(payload, "file_key"))?;
        let file = self
            .repository
            .find_cloud_file_by_key(&file_key)
            .await?
            .filter(|file| file.status == "active")
            .ok_or(AppError::CloudFileUnavailable)?;
        let ticket = cloud_download_ticket(&file.file_key, &self.system_key)?;
        let rotated_session = self.rotate_prepared_session(app, prepared_session).await?;
        Ok(cloud_download_ticket_response(
            app,
            &rotated_session,
            &ticket,
        ))
    }

    pub async fn security_report(
        &self,
        app: &AppDetailRow,
        payload: &Value,
        ip: &str,
    ) -> Result<Value, AppError> {
        let input = security_report_input(payload)?;
        let prepared_session = self
            .prepare_client_session(app, "/security/report", payload)
            .await?;
        if let Some(report) = self
            .repository
            .find_security_report_by_event(app.id, prepared_session.session.id, &input.event_id)
            .await?
        {
            return self
                .duplicate_security_report_response(app, prepared_session, report)
                .await;
        }
        let policy = self.security_policy(app).await?;
        self.assert_security_report_rate_limit(app, &input, &prepared_session, &policy, ip)
            .await?;
        let decision = self
            .security_decision(app, &input, &prepared_session, &policy, ip)
            .await?;
        let should_rotate = !security_action_revokes_session(&decision.action);
        let rotated_session = if should_rotate {
            Some(self.next_rotated_session(app, &prepared_session)?)
        } else {
            None
        };
        let command = client_security_report_command(
            app,
            &prepared_session,
            &input,
            &decision,
            ip,
            rotated_session
                .as_ref()
                .map(|(_, rotation)| rotation.clone()),
        )?;
        let result = self
            .repository
            .create_client_security_report(&command)
            .await?;
        let mut response = security_report_response(&input, &decision, &result);
        if let Some((rotated_session, _)) = rotated_session {
            insert_rotated_session_response_fields(&mut response, app, &rotated_session);
        }
        Ok(Value::Object(response))
    }

    pub async fn logout(&self, app: &AppDetailRow, payload: &Value) -> Result<Value, AppError> {
        let prepared_session = self.prepare_client_session(app, "/logout", payload).await?;
        self.repository
            .revoke_client_session(prepared_session.session.id)
            .await?;
        Ok(logout_response())
    }

    async fn prepare_client_session(
        &self,
        app: &AppDetailRow,
        route: &str,
        payload: &Value,
    ) -> Result<PreparedClientSession, AppError> {
        let token = validate_session_token(&payload_scalar_text(payload, "token"))?;
        let current_token_hash = session_token_hash(&token, &self.system_key)?;
        let session = self
            .repository
            .find_client_session_by_token_hash(app.id, &current_token_hash)
            .await?
            .ok_or(AppError::SessionInvalid("会话无效或已过期"))?;
        let input = client_session_input(payload)?;
        let now = Local::now().naive_local();
        assert_client_session(
            &session,
            &input,
            route,
            &token,
            payload,
            now,
            &self.system_key,
        )?;
        let card = card_from_session(app, &session, now)?;
        Ok(PreparedClientSession {
            current_token_hash,
            session,
            card,
            install_id: input.install_id,
            request_counter: input.counter,
            now,
        })
    }

    async fn rotate_prepared_session(
        &self,
        app: &AppDetailRow,
        prepared_session: PreparedClientSession,
    ) -> Result<RotatedClientSession, AppError> {
        let (rotated_session, rotation) = self.next_rotated_session(app, &prepared_session)?;
        let rotated = self.repository.rotate_client_session(&rotation).await?;
        if !rotated {
            return Err(AppError::SessionInvalid("会话已被更新，请使用最新令牌"));
        }
        touch_session_device_if_needed(
            &self.repository,
            &prepared_session.session,
            prepared_session.now,
        )
        .await?;
        Ok(rotated_session)
    }

    fn next_rotated_session(
        &self,
        app: &AppDetailRow,
        prepared_session: &PreparedClientSession,
    ) -> Result<(RotatedClientSession, ClientSessionRotation), AppError> {
        let token = crypto::token(32);
        let proof_mode = session_proof_mode(&prepared_session.session)?;
        let session_ticket = login_session_ticket(&proof_mode);
        let ticket_hash = session_ticket
            .as_ref()
            .map(|ticket| session_ticket_hash(ticket, &self.system_key))
            .transpose()?;
        let ticket_expires_at = session_ticket
            .as_ref()
            .map(|_| prepared_session.now + Duration::seconds(EPHEMERAL_TICKET_TTL_SECONDS));
        let session_expires_at =
            session_expires_at(app, &prepared_session.card, prepared_session.now);
        Ok((
            RotatedClientSession {
                card: prepared_session.card.clone(),
                token: token.clone(),
                session_expires_at,
                proof_mode: proof_mode.clone(),
                session_ticket,
                ticket_expires_at,
            },
            ClientSessionRotation {
                session_id: prepared_session.session.id,
                current_token_hash: prepared_session.current_token_hash.clone(),
                next_token_hash: session_token_hash(&token, &self.system_key)?,
                request_counter: prepared_session.request_counter,
                heartbeat_at: prepared_session.now,
                expires_at: session_expires_at,
                ticket_hash,
                ticket_expires_at,
            },
        ))
    }

    async fn duplicate_security_report_response(
        &self,
        app: &AppDetailRow,
        prepared_session: PreparedClientSession,
        report: ClientSecurityReportRow,
    ) -> Result<Value, AppError> {
        let message = self
            .repository
            .find_message_by_report(app.id, report.id)
            .await?;
        let action = security_action_or_record(&report.action);
        let session_revoked = security_action_revokes_session(&action);
        let mut response = duplicate_security_report_response(&report, message.as_ref(), &action);
        if !session_revoked {
            let rotated_session = self.rotate_prepared_session(app, prepared_session).await?;
            insert_rotated_session_response_fields(&mut response, app, &rotated_session);
        }
        Ok(Value::Object(response))
    }

    async fn security_policy(&self, app: &AppDetailRow) -> Result<ClientSecurityPolicy, AppError> {
        let policy = self.repository.find_security_policy(app.id).await?;
        Ok(security_policy_from_row(policy.as_ref()))
    }

    async fn assert_security_report_rate_limit(
        &self,
        app: &AppDetailRow,
        input: &SecurityReportInput,
        prepared_session: &PreparedClientSession,
        policy: &ClientSecurityPolicy,
        ip: &str,
    ) -> Result<(), AppError> {
        let since = Local::now().naive_local() - Duration::seconds(60);
        let limits = [
            (
                SECURITY_SESSION_RATE_LIMIT,
                SecurityReportCountFilters {
                    session_id: Some(prepared_session.session.id),
                    since: Some(since),
                    ..Default::default()
                },
            ),
            (
                SECURITY_CARD_RATE_LIMIT.min(policy.report_rate_limit_per_minute),
                card_security_rate_filters(&prepared_session.card, since),
            ),
            (
                SECURITY_DEVICE_RATE_LIMIT,
                match prepared_session.session.device_id {
                    Some(device_id) => SecurityReportCountFilters {
                        device_id: Some(device_id),
                        since: Some(since),
                        ..Default::default()
                    },
                    None => SecurityReportCountFilters::default(),
                },
            ),
            (
                SECURITY_IP_RATE_LIMIT,
                SecurityReportCountFilters {
                    ip: ip.to_string(),
                    since: Some(since),
                    ..Default::default()
                },
            ),
        ];
        for (limit, filters) in limits {
            if security_report_filters_empty(&filters) {
                continue;
            }
            if self
                .repository
                .count_security_reports(app.id, &filters)
                .await?
                < limit
            {
                continue;
            }
            if self
                .critical_report_fallback_available(app, input, prepared_session)
                .await?
            {
                return Ok(());
            }
            return Err(AppError::RateLimited("安全上报过于频繁"));
        }
        Ok(())
    }

    async fn critical_report_fallback_available(
        &self,
        app: &AppDetailRow,
        input: &SecurityReportInput,
        prepared_session: &PreparedClientSession,
    ) -> Result<bool, AppError> {
        if input.risk_level != "critical" {
            return Ok(false);
        }
        let since =
            Local::now().naive_local() - Duration::seconds(SECURITY_CRITICAL_FALLBACK_SECONDS);
        let count = self
            .repository
            .count_security_reports(
                app.id,
                &SecurityReportCountFilters {
                    session_id: Some(prepared_session.session.id),
                    since: Some(since),
                    risk_levels: vec!["critical".to_string()],
                    ..Default::default()
                },
            )
            .await?;
        Ok(count < 1)
    }

    async fn security_decision(
        &self,
        app: &AppDetailRow,
        input: &SecurityReportInput,
        prepared_session: &PreparedClientSession,
        policy: &ClientSecurityPolicy,
        ip: &str,
    ) -> Result<SecurityDecision, AppError> {
        let risk_score = self
            .security_risk_score(app, input, &prepared_session.card, ip)
            .await?;
        let action = if !policy.enabled {
            "record_only".to_string()
        } else {
            match policy.mode.as_str() {
                "bounded_client" => bounded_client_security_action(input, policy, risk_score),
                "server_score" => server_score_security_action(risk_score, policy),
                _ => input.requested_action.clone(),
            }
        };
        let source = if action == input.requested_action
            && policy.mode == "honor_client"
            && policy.enabled
        {
            "client"
        } else {
            "server_policy"
        };
        let (action, action_source) = security_target_action(
            &action,
            &prepared_session.session,
            &prepared_session.card,
            source,
        );
        Ok(SecurityDecision {
            action,
            action_source,
            risk_score,
        })
    }

    async fn security_risk_score(
        &self,
        app: &AppDetailRow,
        input: &SecurityReportInput,
        card: &ClientLoginCard,
        ip: &str,
    ) -> Result<i64, AppError> {
        let mut score = security_event_base_score(&input.event_type)
            .max(security_risk_level_score(&input.risk_level));
        if input.confidence >= 90 {
            score += 10;
        }
        if attestation_failed(input) {
            score += 30;
        }
        if self.recent_card_event_count(app.id, input, card).await? >= 2 {
            score += 15;
        }
        if self.recent_ip_high_risk_card_count(app.id, ip).await? >= 4 {
            score += 20;
        }
        if card.card_type == "count" && self.recent_card_report_count(app.id, card).await? >= 2 {
            score += 15;
        }
        Ok(score.clamp(0, 255))
    }

    async fn recent_card_event_count(
        &self,
        app_id: u64,
        input: &SecurityReportInput,
        card: &ClientLoginCard,
    ) -> Result<i64, AppError> {
        let mut filters =
            card_security_rate_filters(card, Local::now().naive_local() - Duration::seconds(600));
        if security_report_filters_empty(&filters) {
            return Ok(0);
        }
        filters.event_type = input.event_type.clone();
        self.repository
            .count_security_reports(app_id, &filters)
            .await
    }

    async fn recent_card_report_count(
        &self,
        app_id: u64,
        card: &ClientLoginCard,
    ) -> Result<i64, AppError> {
        let filters =
            card_security_rate_filters(card, Local::now().naive_local() - Duration::seconds(600));
        if security_report_filters_empty(&filters) {
            return Ok(0);
        }
        self.repository
            .count_security_reports(app_id, &filters)
            .await
    }

    async fn recent_ip_high_risk_card_count(&self, app_id: u64, ip: &str) -> Result<i64, AppError> {
        let risk_levels = vec!["high".to_string(), "critical".to_string()];
        self.repository
            .count_distinct_security_report_cards(
                app_id,
                ip,
                Local::now().naive_local() - Duration::seconds(600),
                &risk_levels,
            )
            .await
    }

    async fn client_app_version(
        &self,
        app: &AppDetailRow,
        payload: &Value,
    ) -> Result<String, AppError> {
        let client_version = safe_text(payload_scalar_text(payload, "client_version").trim(), 40)?;
        if !client_version.is_empty() {
            return Ok(client_version);
        }
        let config = self.repository.find_remote_config(app.id).await?;
        let version = config
            .as_ref()
            .map(|config| config.version.as_str())
            .unwrap_or(&app.latest_version);
        safe_text(version.trim(), 40)
    }

    async fn read_card_for_client(
        &self,
        app: &AppDetailRow,
        card_key: &str,
    ) -> Result<ClientCard, AppError> {
        let card_hash = card_hash(app, card_key);
        if app.verification_enabled != FLAG_ENABLED {
            return Ok(ClientCard::virtual_card(card_key, &card_hash));
        }
        let card = self
            .repository
            .find_card_by_hash(app.id, &card_hash)
            .await?;
        assert_client_card_usable(card, &card_hash)
    }
}

struct ClientCard {
    card_fingerprint: String,
    card_type: String,
    status: i64,
    used_at: String,
    expires_at: NaiveDateTime,
    remaining_uses: i64,
    max_devices: i64,
    unbind_limit: i64,
    unbind_count: i64,
}

impl ClientCard {
    fn virtual_card(card_key: &str, card_hash: &str) -> Self {
        let now = Local::now().naive_local();
        Self {
            card_fingerprint: card_key_fingerprint(card_key),
            card_type: "time".to_string(),
            status: 0,
            used_at: format_naive_datetime(now),
            expires_at: now + Duration::seconds(DISABLED_VERIFICATION_DURATION_SECONDS),
            remaining_uses: 0,
            max_devices: i64::MAX,
            unbind_limit: 0,
            unbind_count: 0,
        }
        .with_hash_fingerprint(card_hash)
    }

    fn with_hash_fingerprint(mut self, card_hash: &str) -> Self {
        if self.card_fingerprint.is_empty() {
            self.card_fingerprint = hash_fingerprint(card_hash);
        }
        self
    }
}

fn assert_client_card_usable(
    card: Option<CardRow>,
    card_hash: &str,
) -> Result<ClientCard, AppError> {
    let card = card.ok_or(AppError::CardInvalid)?;
    if card.status == 2 {
        return Err(AppError::CardInvalid);
    }
    let card_type = normalized_card_type(&card.card_type);
    let expires_at = card_expiry(&card_type, &card);
    if local_timestamp(expires_at) < Local::now().timestamp() {
        return Err(AppError::CardExpired);
    }
    Ok(ClientCard {
        card_fingerprint: if card.card_fingerprint.is_empty() {
            hash_fingerprint(card_hash)
        } else {
            card.card_fingerprint
        },
        card_type,
        status: card.status,
        used_at: format_datetime(card.used_at),
        expires_at,
        remaining_uses: card.remaining_uses,
        max_devices: card.max_devices,
        unbind_limit: card.unbind_limit,
        unbind_count: card.unbind_count,
    })
}

fn stateless_login_challenge(
    system_key: &str,
    app: &AppDetailRow,
    input: &ChallengeInput,
    server_nonce: &str,
    expires_at: i64,
) -> Result<String, AppError> {
    let payload = json!({
        "v": LOGIN_CHALLENGE_VERSION,
        "a": app.id,
        "i": input.install_id,
        "d": input.device_name,
        "p": input.device_public_key,
        "m": input.device_key_mode,
        "n": server_nonce,
        "e": expires_at,
        "r": crypto::token(12),
    });
    let encoded_payload = crypto::encode_base64_url(
        serde_json::to_string(&payload)
            .map_err(|_| AppError::LoginChallengeFailed)?
            .as_bytes(),
    );
    let signature = hmac_sha256_base64_url(system_key.as_bytes(), &encoded_payload)?;
    Ok(format!("{encoded_payload}.{signature}"))
}

fn card_query_response(card: ClientCard) -> Value {
    json!({
        "card_fingerprint": card.card_fingerprint,
        "card_type": card.card_type,
        "status": card.status,
        "used_at": card.used_at,
        "expires_at": local_timestamp(card.expires_at),
        "remaining_uses": card.remaining_uses,
        "max_devices": card.max_devices,
        "unbind_limit": card.unbind_limit,
        "unbind_count": card.unbind_count,
    })
}

fn login_response(
    app: &AppDetailRow,
    card: &ClientLoginCard,
    token: &str,
    session_expires_at: NaiveDateTime,
    proof_mode: &str,
    session_ticket: Option<&str>,
    ticket_expires_at: Option<NaiveDateTime>,
    bind_region: &str,
) -> Value {
    let mut response = serde_json::Map::new();
    insert_session_response_fields(
        &mut response,
        app,
        card,
        token,
        session_expires_at,
        proof_mode,
        session_ticket,
        ticket_expires_at,
    );
    response.insert(
        "ip_check".to_string(),
        json!({
            "enabled": app.login_ip_binding_enabled == FLAG_ENABLED && card.card_type != "count",
            "passed": true,
            "scope": if app.login_ip_binding_enabled == FLAG_ENABLED && card.card_type != "count" {
                bind_region
            } else {
                ""
            },
        }),
    );
    Value::Object(response)
}

fn heartbeat_response(app: &AppDetailRow, rotated_session: &RotatedClientSession) -> Value {
    let mut response = serde_json::Map::new();
    response.insert("ok".to_string(), json!(true));
    insert_rotated_session_response_fields(&mut response, app, rotated_session);
    Value::Object(response)
}

fn config_response(
    app: &AppDetailRow,
    rotated_session: &RotatedClientSession,
    config: Option<&RemoteConfigRow>,
) -> Value {
    let mut response = serde_json::Map::new();
    insert_rotated_session_response_fields(&mut response, app, rotated_session);
    response.insert(
        "version".to_string(),
        json!(config.map(|config| config.version.as_str()).unwrap_or("")),
    );
    response.insert(
        "download_url".to_string(),
        json!(
            config
                .map(|config| config.download_url.as_str())
                .unwrap_or("")
        ),
    );
    response.insert(
        "force_update".to_string(),
        json!(config.map(|config| config.force_update).unwrap_or(0)),
    );
    response.insert(
        "notice".to_string(),
        json!(config.map(|config| config.notice.as_str()).unwrap_or("")),
    );
    Value::Object(response)
}

fn variable_response(
    app: &AppDetailRow,
    rotated_session: &RotatedClientSession,
    value: Option<String>,
) -> Value {
    let mut response = serde_json::Map::new();
    insert_rotated_session_response_fields(&mut response, app, rotated_session);
    response.insert(
        "value".to_string(),
        value.map(Value::String).unwrap_or(Value::Null),
    );
    Value::Object(response)
}

fn cloud_download_ticket_response(
    app: &AppDetailRow,
    rotated_session: &RotatedClientSession,
    ticket: &ClientDownloadTicket,
) -> Value {
    let mut response = serde_json::Map::new();
    insert_rotated_session_response_fields(&mut response, app, rotated_session);
    response.insert(
        "download_url".to_string(),
        json!(format!(
            "/api/v1/index.php?route=%2Fcloud%2Fdownload&ticket={}",
            ticket.ticket
        )),
    );
    response.insert("download_ticket".to_string(), json!(ticket.ticket));
    response.insert("expires_at".to_string(), json!(ticket.expires_at));
    Value::Object(response)
}

fn logout_response() -> Value {
    json!({ "logged_out": true })
}

fn unbind_response(unbound: bool) -> Value {
    json!({ "unbound": unbound })
}

fn client_crypto_algorithm(
    envelope: &Value,
    app: &AppDetailRow,
) -> Result<crypto::ClientCryptoAlgorithm, AppError> {
    let request_algorithm =
        crypto::ClientCryptoAlgorithm::normalize(&payload_scalar_text(envelope, "alg"))?;
    let app_algorithm = crypto::ClientCryptoAlgorithm::normalize(&app.client_crypto_alg)?;
    if request_algorithm != app_algorithm {
        return Err(AppError::CryptoAlgorithmMismatch);
    }
    Ok(request_algorithm)
}

fn client_crypto_session_key(
    envelope: &Value,
    app: &AppDetailRow,
    algorithm: crypto::ClientCryptoAlgorithm,
    system_key: &str,
) -> Result<Vec<u8>, AppError> {
    let wrapped_key = crypto::decode_base64_url(&payload_scalar_text(envelope, "key"))
        .map_err(|_| AppError::BadEncryptedPayloadFormat)?;
    if wrapped_key.is_empty() {
        return Err(AppError::BadEncryptedPayloadFormat);
    }
    if app.client_private_key_cipher.trim().is_empty() {
        return Err(AppError::AppKeyPairMissing);
    }
    let private_key = crypto::decrypt_protected_text(&app.client_private_key_cipher, system_key)?;
    crypto::decrypt_client_session_key(&wrapped_key, &private_key, algorithm)
}

fn client_crypto_gcm_payload(envelope: &Value) -> Result<crypto::GcmPayload, AppError> {
    Ok(crypto::GcmPayload {
        iv: payload_scalar_text(envelope, "iv"),
        ciphertext: payload_scalar_text(envelope, "ciphertext"),
        tag: payload_scalar_text(envelope, "tag"),
    })
}

fn client_plaintext_payload(plaintext: &str) -> Result<Value, AppError> {
    if plaintext.is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    match serde_json::from_str::<Value>(plaintext).map_err(|_| AppError::RequestJsonInvalid)? {
        Value::Object(values) => Ok(Value::Object(values)),
        Value::Array(values) => Ok(Value::Array(values)),
        _ => Err(AppError::RequestJsonInvalid),
    }
}

fn client_encrypted_response(
    algorithm: crypto::ClientCryptoAlgorithm,
    encrypted: crypto::GcmPayload,
) -> Value {
    let mut response = Map::new();
    response.insert("alg".to_string(), json!(algorithm.name()));
    response.insert("iv".to_string(), json!(encrypted.iv));
    response.insert("ciphertext".to_string(), json!(encrypted.ciphertext));
    response.insert("tag".to_string(), json!(encrypted.tag));
    Value::Object(response)
}

fn client_request_aad(
    route: &str,
    timestamp: &str,
    nonce: &str,
    algorithm: crypto::ClientCryptoAlgorithm,
) -> String {
    format!(
        "client-request\n{}\n{}\n{}\n{}",
        route,
        timestamp,
        nonce,
        algorithm.name()
    )
}

fn client_response_aad(
    route: &str,
    timestamp: &str,
    nonce: &str,
    algorithm: crypto::ClientCryptoAlgorithm,
) -> String {
    format!(
        "client-response\n{}\n{}\n{}\n{}",
        route,
        timestamp,
        nonce,
        algorithm.name()
    )
}

fn security_report_input(payload: &Value) -> Result<SecurityReportInput, AppError> {
    assert_no_client_security_target(payload)?;
    let event_type = security_event_type(&payload_scalar_text(payload, "event_type"))?;
    let risk_level = security_risk_level(&payload_scalar_text(payload, "risk_level"))?;
    let requested_action = security_requested_action(&payload_scalar_text_or(
        payload,
        "requested_action",
        "record_only",
    ))?;
    let evidence = security_evidence_payload(payload.get("evidence").unwrap_or(&Value::Null))?;
    let empty_attestation = Value::Object(Default::default());
    let attestation =
        security_attestation_payload(payload.get("attestation").unwrap_or(&empty_attestation))?;
    Ok(SecurityReportInput {
        event_id: validate_security_event_id(&payload_scalar_text(payload, "event_id"))?,
        event_type,
        risk_level,
        confidence: validate_security_confidence(
            payload.get("confidence").unwrap_or(&Value::Null),
        )?,
        requested_action,
        action_reason: safe_text(&payload_scalar_text(payload, "action_reason"), 200)?,
        title: required_security_text(
            &payload_scalar_text(payload, "title"),
            80,
            "安全上报标题不能为空",
        )?,
        message: required_security_text_block(
            &payload_scalar_text(payload, "message"),
            500,
            "安全上报消息不能为空",
        )?,
        evidence,
        attestation,
        occurred_at: security_occurred_at(payload.get("occurred_at"))?,
        sdk_version: required_security_text(
            &payload_scalar_text(payload, "sdk_version"),
            32,
            "SDK 版本不能为空",
        )?,
        detector_version: required_security_text(
            &payload_scalar_text(payload, "detector_version"),
            32,
            "检测器版本不能为空",
        )?,
        platform: security_platform(&payload_scalar_text(payload, "platform"))?,
    })
}

fn client_security_report_command(
    app: &AppDetailRow,
    prepared_session: &PreparedClientSession,
    input: &SecurityReportInput,
    decision: &SecurityDecision,
    ip: &str,
    rotation: Option<ClientSessionRotation>,
) -> Result<ClientSecurityReportCommand, AppError> {
    let occurred_at = Local
        .timestamp_opt(input.occurred_at, 0)
        .single()
        .ok_or(AppError::InvalidInput("时间戳格式错误"))?
        .naive_local();
    let touch_device_id = if rotation.is_some() {
        session_device_touch_id(&prepared_session.session, prepared_session.now)
    } else {
        None
    };
    Ok(ClientSecurityReportCommand {
        report: ClientSecurityReportRecord {
            app_id: app.id,
            session_id: prepared_session.session.id,
            device_id: prepared_session.session.device_id,
            card_id: prepared_session.card.id,
            card_hash: prepared_session.card.card_hash.clone(),
            card_fingerprint: prepared_session.card.card_fingerprint.clone(),
            install_id: prepared_session.session.install_id.clone(),
            event_id: input.event_id.clone(),
            event_type: input.event_type.clone(),
            risk_level: input.risk_level.clone(),
            confidence: input.confidence,
            requested_action: input.requested_action.clone(),
            action: decision.action.clone(),
            action_source: decision.action_source.clone(),
            risk_score: decision.risk_score,
            action_reason: input.action_reason.clone(),
            title: input.title.clone(),
            message: input.message.clone(),
            evidence_json: json_payload(&input.evidence, 4096)?,
            attestation_json: json_payload(&input.attestation, 8192)?,
            sdk_version: input.sdk_version.clone(),
            detector_version: input.detector_version.clone(),
            platform: input.platform.clone(),
            ip: ip.to_string(),
            occurred_at,
        },
        message: ClientSecurityMessageRecord {
            app_id: app.id,
            session_id: prepared_session.session.id,
            device_id: prepared_session.session.device_id,
            card_id: prepared_session.card.id,
            severity: input.risk_level.clone(),
            title: input.title.clone(),
            summary: security_message_summary(input),
            action: decision.action.clone(),
            action_source: decision.action_source.clone(),
            risk_score: decision.risk_score,
        },
        action: ClientSecurityActionRecord {
            app_id: app.id,
            session_id: prepared_session.session.id,
            device_id: prepared_session.session.device_id,
            card_id: prepared_session.card.id,
            card_hash: prepared_session.card.card_hash.clone(),
            action: decision.action.clone(),
            action_source: decision.action_source.clone(),
            ip: ip.to_string(),
        },
        rotation,
        touch_device_id,
    })
}

fn security_report_response(
    input: &SecurityReportInput,
    decision: &SecurityDecision,
    result: &ClientSecurityReportResult,
) -> serde_json::Map<String, Value> {
    let mut response = serde_json::Map::new();
    response.insert("message_id".to_string(), json!(result.message_id));
    response.insert("report_id".to_string(), json!(result.report_id));
    response.insert("risk_score".to_string(), json!(decision.risk_score));
    response.insert(
        "requested_action".to_string(),
        json!(input.requested_action),
    );
    response.insert("action".to_string(), json!(decision.action));
    response.insert("action_source".to_string(), json!(decision.action_source));
    response.insert("session_revoked".to_string(), json!(result.session_revoked));
    response.insert("device_disabled".to_string(), json!(result.device_disabled));
    response.insert("card_disabled".to_string(), json!(result.card_disabled));
    response.insert(
        "revoked_sessions".to_string(),
        json!(result.revoked_sessions),
    );
    response
}

fn duplicate_security_report_response(
    report: &ClientSecurityReportRow,
    message: Option<&crate::repository::ClientSecurityMessageRow>,
    action: &str,
) -> serde_json::Map<String, Value> {
    let mut response = serde_json::Map::new();
    response.insert(
        "message_id".to_string(),
        json!(message.map(|message| message.id).unwrap_or(0)),
    );
    response.insert("report_id".to_string(), json!(report.id));
    response.insert("risk_score".to_string(), json!(report.risk_score));
    response.insert(
        "requested_action".to_string(),
        json!(security_action_or_record(&report.requested_action)),
    );
    response.insert("action".to_string(), json!(action));
    response.insert("action_source".to_string(), json!(report.action_source));
    response.insert(
        "session_revoked".to_string(),
        json!(security_action_revokes_session(action)),
    );
    response.insert(
        "device_disabled".to_string(),
        json!(action == "disable_device"),
    );
    response.insert("card_disabled".to_string(), json!(action == "disable_card"));
    response.insert("revoked_sessions".to_string(), json!(0));
    response.insert("duplicate".to_string(), json!(true));
    response
}

fn insert_rotated_session_response_fields(
    response: &mut serde_json::Map<String, Value>,
    app: &AppDetailRow,
    rotated_session: &RotatedClientSession,
) {
    insert_session_response_fields(
        response,
        app,
        &rotated_session.card,
        &rotated_session.token,
        rotated_session.session_expires_at,
        &rotated_session.proof_mode,
        rotated_session.session_ticket.as_deref(),
        rotated_session.ticket_expires_at,
    );
}

fn insert_session_response_fields(
    response: &mut serde_json::Map<String, Value>,
    app: &AppDetailRow,
    card: &ClientLoginCard,
    token: &str,
    session_expires_at: NaiveDateTime,
    proof_mode: &str,
    session_ticket: Option<&str>,
    ticket_expires_at: Option<NaiveDateTime>,
) {
    response.insert("token".to_string(), json!(token));
    response.insert(
        "token_expires_at".to_string(),
        json!(local_timestamp(session_expires_at)),
    );
    response.insert(
        "card_expires_at".to_string(),
        json!(local_timestamp(card.expires_at)),
    );
    response.insert(
        "heartbeat_interval".to_string(),
        json!(session_ttl_seconds(app)),
    );
    response.insert("proof_mode".to_string(), json!(proof_mode));
    if card.card_type == "count" {
        response.insert("remaining_uses".to_string(), json!(card.remaining_uses));
    }
    if let (Some(session_ticket), Some(ticket_expires_at)) = (
        session_ticket.filter(|ticket| !ticket.is_empty()),
        ticket_expires_at,
    ) {
        response.insert("session_ticket".to_string(), json!(session_ticket));
        response.insert(
            "ticket_expires_at".to_string(),
            json!(local_timestamp(ticket_expires_at)),
        );
    }
}

fn assert_no_client_security_target(payload: &Value) -> Result<(), AppError> {
    let Some(object) = payload.as_object() else {
        return Ok(());
    };
    if SECURITY_TARGET_FIELDS
        .iter()
        .any(|field_name| object.contains_key(*field_name))
    {
        return Err(AppError::SecurityReportInvalid("安全上报不能指定处置目标"));
    }
    Ok(())
}

fn validate_security_event_id(value: &str) -> Result<String, AppError> {
    if (8..=96).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
    {
        return Ok(value.to_string());
    }
    Err(AppError::InvalidInput("安全事件标识格式错误"))
}

fn security_event_type(value: &str) -> Result<String, AppError> {
    if !(3..=40).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(AppError::InvalidInput("安全事件类型格式错误"));
    }
    if SECURITY_EVENT_TYPES.contains(&value) {
        return Ok(value.to_string());
    }
    Err(AppError::SecurityReportInvalid("安全事件类型不支持"))
}

fn security_risk_level(value: &str) -> Result<String, AppError> {
    if !(3..=16).contains(&value.len()) || !value.bytes().all(|byte| byte.is_ascii_lowercase()) {
        return Err(AppError::InvalidInput("安全风险等级格式错误"));
    }
    if SECURITY_RISK_LEVELS.contains(&value) {
        return Ok(value.to_string());
    }
    Err(AppError::SecurityReportInvalid("安全风险等级不支持"))
}

fn security_action(value: &str) -> Result<String, AppError> {
    if !(6..=32).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        return Err(AppError::InvalidInput("安全处置动作格式错误"));
    }
    if SECURITY_ACTIONS.contains(&value) {
        return Ok(value.to_string());
    }
    Err(AppError::InvalidSecurityAction)
}

fn security_action_or_record(value: &str) -> String {
    security_action(value).unwrap_or_else(|_| "record_only".to_string())
}

fn security_requested_action(value: &str) -> Result<String, AppError> {
    let action = security_action(value)?;
    if action == "manual_review" {
        return Err(AppError::InvalidSecurityAction);
    }
    Ok(action)
}

fn validate_security_confidence(value: &Value) -> Result<i64, AppError> {
    let confidence = match value {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.trim().parse::<f64>().ok(),
        _ => None,
    }
    .filter(|number| number.is_finite())
    .map(|number| number as i64)
    .ok_or(AppError::InvalidInput("安全置信度格式错误"))?;
    if (0..=100).contains(&confidence) {
        return Ok(confidence);
    }
    Err(AppError::InvalidInput("安全置信度必须在 0 到 100 之间"))
}

fn required_security_text(
    value: &str,
    max_bytes: usize,
    message: &'static str,
) -> Result<String, AppError> {
    let text = safe_text(value.trim(), max_bytes)?;
    if text.is_empty() {
        return Err(AppError::SecurityReportInvalid(message));
    }
    Ok(text)
}

fn required_security_text_block(
    value: &str,
    max_bytes: usize,
    message: &'static str,
) -> Result<String, AppError> {
    let text = safe_text_block(value.trim(), max_bytes)?;
    if text.is_empty() {
        return Err(AppError::SecurityReportInvalid(message));
    }
    Ok(text)
}

fn security_evidence_payload(value: &Value) -> Result<Value, AppError> {
    let payload = security_object_payload(value)?;
    let Some(object) = payload.as_object() else {
        return Err(AppError::SecurityReportInvalid(
            "安全上报扩展字段必须是对象",
        ));
    };
    if object.is_empty() {
        return Err(AppError::SecurityReportInvalid(
            "安全上报 evidence 不能为空",
        ));
    }
    assert_security_object_fields(object, SECURITY_EVIDENCE_FIELDS, "evidence")?;
    assert_security_evidence_types(object)?;
    json_payload(&payload, 4096)?;
    Ok(payload)
}

fn security_attestation_payload(value: &Value) -> Result<Value, AppError> {
    let payload = security_object_payload(value)?;
    let Some(object) = payload.as_object() else {
        return Err(AppError::SecurityReportInvalid(
            "安全上报扩展字段必须是对象",
        ));
    };
    assert_security_object_fields(object, SECURITY_ATTESTATION_FIELDS, "attestation")?;
    assert_security_attestation_types(object)?;
    json_payload(&payload, 4096)?;
    Ok(payload)
}

fn security_object_payload(value: &Value) -> Result<Value, AppError> {
    match value {
        Value::Object(_) => Ok(value.clone()),
        Value::Array(values) if values.is_empty() => Ok(Value::Object(Default::default())),
        _ => Err(AppError::SecurityReportInvalid(
            "安全上报扩展字段必须是对象",
        )),
    }
}

fn assert_security_object_fields(
    object: &serde_json::Map<String, Value>,
    allowed_fields: &[&str],
    field_name: &'static str,
) -> Result<(), AppError> {
    if object
        .keys()
        .any(|key| !allowed_fields.contains(&key.as_str()))
    {
        return Err(AppError::SecurityReportInvalid(match field_name {
            "evidence" => "安全上报 evidence 字段不在白名单",
            _ => "安全上报 attestation 字段不在白名单",
        }));
    }
    Ok(())
}

fn assert_security_evidence_types(object: &serde_json::Map<String, Value>) -> Result<(), AppError> {
    for field_name in [
        "detector",
        "matched_rule",
        "module_hash",
        "symbol_hash",
        "attestation_verdict",
    ] {
        if let Some(value) = object.get(field_name) {
            if !value.as_str().is_some_and(|text| text.len() <= 160) {
                return Err(AppError::SecurityReportInvalid(
                    "安全上报 evidence 字段类型错误",
                ));
            }
        }
    }
    if let Some(value) = object.get("process_hashes") {
        let Some(values) = value.as_array() else {
            return Err(AppError::SecurityReportInvalid("安全上报进程摘要格式错误"));
        };
        if values.len() > 32
            || values
                .iter()
                .any(|value| !value.as_str().is_some_and(|text| text.len() <= 160))
        {
            return Err(AppError::SecurityReportInvalid("安全上报进程摘要格式错误"));
        }
    }
    if let Some(value) = object.get("debug_port_open") {
        if !value.is_boolean() {
            return Err(AppError::SecurityReportInvalid(
                "安全上报调试端口字段格式错误",
            ));
        }
    }
    if let Some(value) = object.get("hook_count") {
        if !value
            .as_i64()
            .is_some_and(|count| (0..=100_000).contains(&count))
        {
            return Err(AppError::SecurityReportInvalid(
                "安全上报 Hook 数量格式错误",
            ));
        }
    }
    Ok(())
}

fn assert_security_attestation_types(
    object: &serde_json::Map<String, Value>,
) -> Result<(), AppError> {
    if object
        .values()
        .any(|value| !value.as_str().is_some_and(|text| text.len() <= 256))
    {
        return Err(AppError::SecurityReportInvalid(
            "安全上报 attestation 字段类型错误",
        ));
    }
    Ok(())
}

fn security_occurred_at(value: Option<&Value>) -> Result<i64, AppError> {
    match value {
        None | Some(Value::Null) => {
            return Err(AppError::SecurityReportInvalid("安全事件发生时间不能为空"));
        }
        Some(Value::String(text)) if text.is_empty() => {
            return Err(AppError::SecurityReportInvalid("安全事件发生时间不能为空"));
        }
        Some(value) => validate_unix_timestamp(value),
    }
}

fn security_platform(value: &str) -> Result<String, AppError> {
    if value.is_empty()
        || value.len() > 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
    {
        return Err(AppError::InvalidInput("平台标识格式错误"));
    }
    let platform = value.to_ascii_lowercase();
    if ["android", "ios", "windows", "macos", "linux"].contains(&platform.as_str()) {
        return Ok(platform);
    }
    Err(AppError::SecurityReportInvalid("安全上报平台不支持"))
}

fn json_payload(value: &Value, max_bytes: usize) -> Result<String, AppError> {
    let json = if value.as_object().is_some_and(|object| object.is_empty()) {
        "{}".to_string()
    } else {
        serde_json::to_string(value)
            .map_err(|_| AppError::SecurityReportInvalid("安全上报 JSON 编码失败"))?
    };
    if json.len() > max_bytes {
        return Err(AppError::SecurityReportTooLarge("安全上报扩展字段过大"));
    }
    Ok(json)
}

fn client_session_input(payload: &Value) -> Result<ClientSessionInput, AppError> {
    Ok(ClientSessionInput {
        install_id: validate_install_id(&payload_scalar_text(payload, "install_id"))?,
        counter: validate_request_counter(payload.get("counter").unwrap_or(&Value::Null))?,
        timestamp: validate_unix_timestamp(payload.get("timestamp").unwrap_or(&Value::Null))?,
        request_nonce: validate_request_nonce(&payload_scalar_text(payload, "request_nonce"))?,
        session_ticket: payload_scalar_text(payload, "session_ticket")
            .trim()
            .to_string(),
        signature: payload_scalar_text(payload, "signature").trim().to_string(),
    })
}

fn assert_client_session(
    session: &ClientSessionRow,
    input: &ClientSessionInput,
    route: &str,
    token: &str,
    payload: &Value,
    now: NaiveDateTime,
    system_key: &str,
) -> Result<(), AppError> {
    if session.status != FLAG_ENABLED || session.expires_at < now {
        return Err(AppError::SessionInvalid("会话无效或已过期"));
    }
    if session.device_id.is_some() && session.device_status != Some(FLAG_ENABLED) {
        return Err(AppError::SessionInvalid("会话无效或已过期"));
    }
    if input.counter <= session.request_counter {
        return Err(AppError::SessionInvalid("会话请求计数器无效"));
    }
    if session.device_id.is_some() && !constant_eq(&session.install_id, &input.install_id) {
        return Err(AppError::SessionInvalid("会话设备不匹配"));
    }
    assert_client_timestamp(input.timestamp)?;
    let proof_mode = session_proof_mode(session)?;
    if proof_mode == PROOF_MODE_EPHEMERAL_TICKET {
        return assert_session_ticket(session, &input.session_ticket, system_key);
    }
    assert_local_key_session(session, input, route, token, payload)?;
    Ok(())
}

fn assert_session_ticket(
    session: &ClientSessionRow,
    ticket: &str,
    system_key: &str,
) -> Result<(), AppError> {
    if ticket.trim().is_empty() {
        return Err(AppError::SessionTicketMissing);
    }
    let ticket = validate_session_ticket(ticket)?;
    if session.ticket_hash.as_deref().unwrap_or_default()
        != session_ticket_hash(&ticket, system_key)?
    {
        return Err(AppError::SessionTicketInvalid);
    }
    let Some(ticket_expires_at) = session.ticket_expires_at else {
        return Err(AppError::SessionTicketExpired);
    };
    if ticket_expires_at < Local::now().naive_local() {
        return Err(AppError::SessionTicketExpired);
    }
    Ok(())
}

fn assert_local_key_session(
    session: &ClientSessionRow,
    input: &ClientSessionInput,
    route: &str,
    token: &str,
    payload: &Value,
) -> Result<(), AppError> {
    if session.device_id.is_none() {
        return Err(AppError::SessionInvalid("无设备会话必须使用临时票据"));
    }
    let signature = validate_base64_url_signature(&input.signature)?;
    crypto::verify_p256_signature(
        &session.device_public_key,
        &session_canonical(
            route,
            token,
            &input.install_id,
            input.counter,
            &input.request_nonce,
            input.timestamp,
            &session_extra(route, payload)?,
        ),
        &signature,
    )
}

fn session_canonical(
    route: &str,
    token: &str,
    install_id: &str,
    counter: i64,
    request_nonce: &str,
    timestamp: i64,
    extra: &str,
) -> String {
    format!(
        "POST\n{route}\n{token}\n{install_id}\n{counter}\n{request_nonce}\n{timestamp}\n{}",
        crypto::sha256_hex(extra)
    )
}

fn session_extra(route: &str, payload: &Value) -> Result<String, AppError> {
    match route {
        "/variable" => variable_name(&payload_scalar_text(payload, "name")),
        "/security/report" => validate_security_event_id(&payload_scalar_text(payload, "event_id")),
        "/cloud/download-ticket" => Ok(payload_scalar_text(payload, "file_key")),
        _ => Ok(String::new()),
    }
}

fn session_proof_mode(session: &ClientSessionRow) -> Result<String, AppError> {
    if !session.proof_mode.is_empty() {
        return normalize_proof_mode(&session.proof_mode);
    }
    normalize_proof_mode(if session.device_key_alg.is_empty() {
        PROOF_MODE_LOCAL_KEY
    } else {
        &session.device_key_alg
    })
}

fn card_from_session(
    app: &AppDetailRow,
    session: &ClientSessionRow,
    now: NaiveDateTime,
) -> Result<ClientLoginCard, AppError> {
    if session.card_id.is_none() {
        if app.verification_enabled == FLAG_ENABLED {
            return Err(AppError::CardInvalid);
        }
        return Ok(ClientLoginCard {
            id: None,
            card_hash: session.card_hash.clone(),
            card_fingerprint: session.card_fingerprint.clone(),
            card_type: "time".to_string(),
            expires_at: now + Duration::seconds(DISABLED_VERIFICATION_DURATION_SECONDS),
            remaining_uses: 0,
            max_devices: i64::MAX,
            first_use: false,
        });
    }
    if session.card_status.is_none() || session.card_status == Some(2) {
        return Err(AppError::CardInvalid);
    }
    let card_type = normalized_card_type(&session.stored_card_type);
    let expires_at = card_expiry_from_parts(
        &card_type,
        session.stored_card_used_at,
        session.stored_card_duration_seconds,
    );
    if expires_at < now {
        return Err(AppError::CardExpired);
    }
    Ok(ClientLoginCard {
        id: session.card_id,
        card_hash: if session.stored_card_hash.is_empty() {
            session.card_hash.clone()
        } else {
            session.stored_card_hash.clone()
        },
        card_fingerprint: if session.stored_card_fingerprint.is_empty() {
            session.card_fingerprint.clone()
        } else {
            session.stored_card_fingerprint.clone()
        },
        card_type,
        expires_at,
        remaining_uses: session.stored_card_remaining_uses,
        max_devices: session.stored_card_max_devices,
        first_use: false,
    })
}

fn session_expires_at(
    app: &AppDetailRow,
    card: &ClientLoginCard,
    now: NaiveDateTime,
) -> NaiveDateTime {
    let ttl_expires_at = now + Duration::seconds(session_ttl_seconds(app));
    if ttl_expires_at < card.expires_at {
        ttl_expires_at
    } else {
        card.expires_at
    }
}

async fn touch_session_device_if_needed(
    repository: &AuthRepository,
    session: &ClientSessionRow,
    now: NaiveDateTime,
) -> Result<(), AppError> {
    if let Some(device_id) = session_device_touch_id(session, now) {
        repository.touch_client_device(device_id, now).await?;
    }
    Ok(())
}

fn login_input(app: &AppDetailRow, payload: &Value) -> Result<LoginInput, AppError> {
    validate_optional_base64_url_signature(&payload_scalar_text(payload, "signature"))?;
    Ok(LoginInput {
        card_key: client_card_key(app, &payload_scalar_text(payload, "card_key"))?,
        challenge_id: validate_challenge_id(&payload_scalar_text(payload, "challenge_id"))?,
        install_id: validate_install_id(&payload_scalar_text(payload, "install_id"))?,
        device_name: safe_text(&payload_scalar_text(payload, "device_name"), 80)?,
        machine_profile_hash: validate_machine_profile_hash(&payload_scalar_text(
            payload,
            "machine_profile_hash",
        ))?,
        timestamp: validate_unix_timestamp(payload.get("timestamp").unwrap_or(&Value::Null))?,
        signature: payload_scalar_text(payload, "signature").trim().to_string(),
        device_key_mode: normalize_proof_mode(&validate_device_key_mode(&payload_scalar_text(
            payload,
            "device_key_mode",
        ))?)?,
        client_version: safe_text(payload_scalar_text(payload, "client_version").trim(), 40)?,
    })
}

fn unbind_input(app: &AppDetailRow, payload: &Value) -> Result<UnbindInput, AppError> {
    Ok(UnbindInput {
        card_key: client_card_key(app, &payload_scalar_text(payload, "card_key"))?,
        install_id: validate_install_id(&payload_scalar_text(payload, "install_id"))?,
        timestamp: validate_unix_timestamp(payload.get("timestamp").unwrap_or(&Value::Null))?,
        signature: validate_base64_url_signature(&payload_scalar_text(payload, "signature"))?,
    })
}

fn unbind_canonical(install_id: &str, timestamp: i64, card_hash: &str) -> String {
    format!("POST\n/unbind\n{install_id}\n{timestamp}\n{card_hash}")
}

fn login_challenge_for_login(
    app: &AppDetailRow,
    input: &LoginInput,
    system_key: &str,
) -> Result<LoginChallengeForLogin, AppError> {
    if is_direct_ephemeral_challenge(input) {
        let expires_at = Local
            .timestamp_opt(input.timestamp + SIGNATURE_WINDOW_SECONDS, 0)
            .single()
            .ok_or(AppError::LoginChallengeInvalid("登录挑战不存在或已过期"))?
            .naive_local();
        return Ok(LoginChallengeForLogin {
            install_id: input.install_id.clone(),
            device_name: input.device_name.clone(),
            device_public_key: String::new(),
            device_key_mode: PROOF_MODE_EPHEMERAL_TICKET.to_string(),
            challenge_id: input.challenge_id.clone(),
            server_nonce: String::new(),
            expires_at,
            stateless: false,
            direct_ephemeral: true,
        });
    }
    load_stateless_login_challenge(app, &input.challenge_id, system_key)
}

fn is_direct_ephemeral_challenge(input: &LoginInput) -> bool {
    input.device_key_mode == PROOF_MODE_EPHEMERAL_TICKET
        && input
            .challenge_id
            .starts_with(DIRECT_EPHEMERAL_CHALLENGE_PREFIX)
}

fn load_stateless_login_challenge(
    app: &AppDetailRow,
    challenge_id: &str,
    system_key: &str,
) -> Result<LoginChallengeForLogin, AppError> {
    let Some((encoded_payload, signature)) = challenge_id.split_once('.') else {
        return Err(AppError::LoginChallengeInvalid("登录挑战不存在或已过期"));
    };
    let expected_signature = hmac_sha256_base64_url(system_key.as_bytes(), encoded_payload)?;
    if encoded_payload.is_empty()
        || signature.is_empty()
        || !constant_eq(&expected_signature, signature)
    {
        return Err(AppError::LoginChallengeInvalid("登录挑战签名无效"));
    }
    let payload = crypto::decode_base64_url(encoded_payload)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .ok_or(AppError::LoginChallengeInvalid("登录挑战格式无效"))?;
    let expires_at = challenge_payload_i64(&payload, "e");
    if challenge_payload_i64(&payload, "v") != LOGIN_CHALLENGE_VERSION
        || challenge_payload_i64(&payload, "a") != app.id as i64
        || expires_at < Local::now().timestamp()
    {
        return Err(AppError::LoginChallengeInvalid("登录挑战不存在或已过期"));
    }
    let expires_at = Local
        .timestamp_opt(expires_at, 0)
        .single()
        .ok_or(AppError::LoginChallengeInvalid("登录挑战不存在或已过期"))?
        .naive_local();
    Ok(LoginChallengeForLogin {
        install_id: validate_install_id(&challenge_payload_text(&payload, "i"))?,
        device_name: safe_text(&challenge_payload_text(&payload, "d"), 80)?,
        device_public_key: challenge_payload_text(&payload, "p"),
        device_key_mode: normalize_proof_mode(&validate_device_key_mode(
            &challenge_payload_text(&payload, "m"),
        )?)?,
        challenge_id: challenge_id.to_string(),
        server_nonce: validate_request_nonce(&challenge_payload_text(&payload, "n"))?,
        expires_at,
        stateless: true,
        direct_ephemeral: false,
    })
}

fn challenge_payload_text(payload: &Value, key: &str) -> String {
    payload.get(key).map(php_scalar_string).unwrap_or_default()
}

fn challenge_payload_i64(payload: &Value, key: &str) -> i64 {
    payload.get(key).and_then(value_to_i64).unwrap_or(0)
}

fn assert_direct_ephemeral_challenge_randomness(challenge_id: &str) -> Result<(), AppError> {
    let random_part = challenge_id
        .strip_prefix(DIRECT_EPHEMERAL_CHALLENGE_PREFIX)
        .unwrap_or_default();
    if random_part.len() >= DIRECT_EPHEMERAL_RANDOM_MIN_LENGTH {
        return Ok(());
    }
    Err(AppError::LoginChallengeInvalid("登录挑战随机量不足"))
}

fn login_proof_for_card(
    card: &ClientCard,
    card_hash: &str,
    input: &LoginInput,
    challenge: &LoginChallengeForLogin,
) -> Result<ClientLoginProof, AppError> {
    if challenge.device_key_mode != input.device_key_mode {
        return Err(AppError::DeviceKeyModeMismatch(
            "登录挑战与设备密钥模式不匹配",
        ));
    }
    if card.card_type == "count" && card.remaining_uses <= 0 {
        return Err(AppError::CardExhausted);
    }
    if challenge.device_key_mode == PROOF_MODE_EPHEMERAL_TICKET {
        if challenge.direct_ephemeral {
            assert_direct_ephemeral_challenge_randomness(&input.challenge_id)?;
        }
        return Ok(ClientLoginProof {
            proof_mode: PROOF_MODE_EPHEMERAL_TICKET.to_string(),
            device_public_key: String::new(),
        });
    }
    let device_public_key = normalize_p256_public_key(&challenge.device_public_key)?;
    assert_login_signature(card_hash, input, challenge, &device_public_key)?;
    Ok(ClientLoginProof {
        proof_mode: if card.card_type == "count" {
            PROOF_MODE_EPHEMERAL_TICKET.to_string()
        } else {
            PROOF_MODE_LOCAL_KEY.to_string()
        },
        device_public_key: if card.card_type == "count" {
            String::new()
        } else {
            device_public_key
        },
    })
}

fn assert_login_signature(
    card_hash: &str,
    input: &LoginInput,
    challenge: &LoginChallengeForLogin,
    device_public_key: &str,
) -> Result<(), AppError> {
    if input.signature.trim().is_empty() {
        return Err(AppError::BadDeviceSignature("设备签名格式错误"));
    }
    let signature = validate_base64_url_signature(&input.signature)
        .map_err(|_| AppError::BadDeviceSignature("设备签名格式错误"))?;
    crypto::verify_p256_signature(
        device_public_key,
        &login_canonical(
            &input.challenge_id,
            &input.install_id,
            input.timestamp,
            &input.machine_profile_hash,
            card_hash,
            &challenge.server_nonce,
        ),
        &signature,
    )
}

fn login_canonical(
    challenge_id: &str,
    install_id: &str,
    timestamp: i64,
    machine_profile_hash: &str,
    card_hash: &str,
    server_nonce: &str,
) -> String {
    format!(
        "POST\n/login\n{challenge_id}\n{install_id}\n{timestamp}\n{machine_profile_hash}\n{card_hash}\n{server_nonce}"
    )
}

fn login_session_ticket(proof_mode: &str) -> Option<String> {
    (proof_mode == PROOF_MODE_EPHEMERAL_TICKET).then(|| crypto::token(32))
}

fn login_challenge_nonce_hash(challenge: &LoginChallengeForLogin) -> Option<String> {
    challenge
        .stateless
        .then(|| crypto::sha256_hex(&format!("login_challenge:{}", challenge.challenge_id)))
}

fn login_challenge_expires_at(challenge: &LoginChallengeForLogin) -> Option<NaiveDateTime> {
    challenge.stateless.then_some(challenge.expires_at)
}

fn assert_client_timestamp(timestamp: i64) -> Result<(), AppError> {
    if timestamp > 0 && (Local::now().timestamp() - timestamp).abs() <= SIGNATURE_WINDOW_SECONDS {
        return Ok(());
    }
    Err(AppError::ClientStaleRequest)
}

async fn assert_login_client_version(
    repository: &AuthRepository,
    app: &AppDetailRow,
    client_version: &str,
) -> Result<(), AppError> {
    let Some(config) = repository.find_remote_config(app.id).await? else {
        return Ok(());
    };
    let latest_version = config.version.trim();
    if config.force_update != FLAG_ENABLED || latest_version.is_empty() {
        return Ok(());
    }
    if constant_eq(latest_version, client_version.trim()) {
        return Ok(());
    }
    Err(AppError::ClientVersionOutdated)
}

fn validate_challenge_id(value: &str) -> Result<String, AppError> {
    if (24..=2048).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        return Ok(value.to_string());
    }
    Err(AppError::InvalidInput("挑战标识格式错误"))
}

fn validate_machine_profile_hash(value: &str) -> Result<String, AppError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Ok(value.to_string());
    }
    Err(AppError::InvalidInput("设备摘要格式错误"))
}

fn validate_unix_timestamp(value: &Value) -> Result<i64, AppError> {
    let timestamp = php_scalar_string(value);
    if timestamp.len() == 10 && timestamp.bytes().all(|byte| byte.is_ascii_digit()) {
        return timestamp
            .parse::<i64>()
            .map_err(|_| AppError::InvalidInput("时间戳格式错误"));
    }
    Err(AppError::InvalidInput("时间戳格式错误"))
}

fn validate_session_token(value: &str) -> Result<String, AppError> {
    if (32..=256).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Ok(value.to_string());
    }
    Err(AppError::InvalidInput("会话令牌格式错误"))
}

fn validate_session_ticket(value: &str) -> Result<String, AppError> {
    if (32..=256).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Ok(value.to_string());
    }
    Err(AppError::InvalidInput("临时票据格式错误"))
}

fn validate_request_nonce(value: &str) -> Result<String, AppError> {
    if (16..=96).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Ok(value.to_string());
    }
    Err(AppError::InvalidInput("请求随机串格式错误"))
}

fn validate_request_counter(value: &Value) -> Result<i64, AppError> {
    let counter = match value {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.trim().parse::<f64>().ok(),
        _ => None,
    }
    .filter(|number| number.is_finite())
    .map(|number| number.trunc() as i64)
    .ok_or(AppError::InvalidInput("请求计数器格式错误"))?;
    if counter > 0 {
        return Ok(counter);
    }
    Err(AppError::InvalidInput("请求计数器格式错误"))
}

fn validate_optional_base64_url_signature(value: &str) -> Result<(), AppError> {
    let signature = value.trim();
    if signature.is_empty() || validate_base64_url_signature(signature).is_ok() {
        return Ok(());
    }
    Err(AppError::InvalidInput("签名格式错误"))
}

fn validate_base64_url_signature(value: &str) -> Result<String, AppError> {
    let signature = value.trim();
    if (40..=2048).contains(&signature.len())
        && signature
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Ok(signature.to_string());
    }
    Err(AppError::InvalidInput("签名格式错误"))
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
    Err(AppError::InvalidInput("远程变量名格式错误"))
}

pub fn cloud_file_key(value: &str) -> Result<String, AppError> {
    let file_key = value.trim();
    if (16..=64).contains(&file_key.len())
        && file_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Ok(file_key.to_string());
    }
    Err(AppError::CloudFileKeyInvalid)
}

struct ClientDownloadTicket {
    ticket: String,
    expires_at: i64,
}

fn cloud_download_ticket(
    file_key: &str,
    system_key: &str,
) -> Result<ClientDownloadTicket, AppError> {
    let expires_at = Local::now().timestamp() + CLIENT_DOWNLOAD_TICKET_TTL_SECONDS;
    let mut payload = serde_json::Map::new();
    payload.insert("v".to_string(), json!(1));
    payload.insert("file_key".to_string(), json!(file_key));
    payload.insert("exp".to_string(), json!(expires_at));
    payload.insert("nonce".to_string(), json!(crypto::token(12)));
    let json = serde_json::to_string(&Value::Object(payload))
        .map_err(|_| AppError::CloudDownloadTicketFailed)?;
    Ok(ClientDownloadTicket {
        ticket: crypto::encrypt_protected_text(&json, system_key)?,
        expires_at,
    })
}

fn session_token_hash(token: &str, system_key: &str) -> Result<String, AppError> {
    crypto::hmac_sha256_hex_string(system_key.as_bytes(), token)
}

fn session_ticket_hash(ticket: &str, system_key: &str) -> Result<String, AppError> {
    crypto::hmac_sha256_hex_string(system_key.as_bytes(), &format!("ticket:{ticket}"))
}

fn device_hash(app: &AppDetailRow, install_id: &str) -> String {
    crypto::sha256_hex(&format!("{}:install:{}", app.app_code, install_id))
}

fn session_ttl_seconds(app: &AppDetailRow) -> i64 {
    app.heartbeat_interval.max(300)
}

fn login_ip_binding_key(ip: &str) -> Result<String, AppError> {
    let address = ip
        .trim()
        .parse::<std::net::IpAddr>()
        .map_err(|_| AppError::IpRegionUnavailable)?;
    if is_public_ip_for_binding(address) {
        return Err(AppError::IpRegionUnavailable);
    }
    Ok(match address {
        std::net::IpAddr::V4(address) if address.is_loopback() => "local:loopback".to_string(),
        std::net::IpAddr::V4(address) => {
            let octets = address.octets();
            format!("local4:{}.{}.{}.0/24", octets[0], octets[1], octets[2])
        }
        std::net::IpAddr::V6(address) if address.is_loopback() => "local:loopback".to_string(),
        std::net::IpAddr::V6(address) => {
            let octets = address.octets();
            format!("local6:{}/64", hex::encode(&octets[..8]))
        }
    })
}

fn is_public_ip_for_binding(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(address) => {
            !(address.is_unspecified()
                || address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_multicast()
                || address.is_documentation())
        }
        std::net::IpAddr::V6(address) => {
            let segments = address.segments();
            !(address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || ((segments[0] & 0xfe00) == 0xfc00)
                || ((segments[0] & 0xffc0) == 0xfe80)
                || (segments[0] == 0x2001 && segments[1] == 0x0db8))
        }
    }
}

fn validate_app_code(value: &str) -> Result<String, AppError> {
    if (3..=32).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Ok(value.to_string());
    }
    Err(AppError::InvalidInput("应用编号格式错误"))
}

fn challenge_input(payload: &Value) -> Result<ChallengeInput, AppError> {
    let mode = normalize_proof_mode(&validate_device_key_mode(
        &payload
            .get("device_key_mode")
            .map(php_scalar_string)
            .unwrap_or_else(|| PROOF_MODE_LOCAL_KEY.to_string()),
    )?)?;
    Ok(ChallengeInput {
        install_id: validate_install_id(&payload_scalar_text(payload, "install_id"))?,
        device_name: safe_text(&payload_scalar_text(payload, "device_name"), 80)?,
        device_public_key: if mode == PROOF_MODE_LOCAL_KEY {
            normalize_p256_public_key(&payload_scalar_text(payload, "device_public_key"))?
        } else {
            String::new()
        },
        device_key_mode: mode,
    })
}

fn validate_install_id(value: &str) -> Result<String, AppError> {
    if (16..=80).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Ok(value.to_string());
    }
    Err(AppError::InvalidInput("安装标识格式错误"))
}

fn client_card_key(app: &AppDetailRow, value: &str) -> Result<String, AppError> {
    if app.verification_enabled == FLAG_ENABLED {
        return validate_card_key(value);
    }
    let card_key = value.trim();
    if card_key.is_empty()
        || card_key.len() > 128
        || card_key.bytes().any(|byte| matches!(byte, 0..=31 | 127))
    {
        return Err(AppError::InvalidInput("卡密格式错误"));
    }
    Ok(card_key.to_string())
}

fn validate_card_key(value: &str) -> Result<String, AppError> {
    if (8..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Ok(value.to_string());
    }
    Err(AppError::InvalidInput("卡密格式错误"))
}

fn validate_device_key_mode(value: &str) -> Result<String, AppError> {
    if (8..=40).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Ok(value.to_string());
    }
    Err(AppError::InvalidInput("设备密钥模式格式错误"))
}

fn normalize_proof_mode(value: &str) -> Result<String, AppError> {
    let mode = value.trim();
    if mode.is_empty() || mode == "platform_key_v1" || mode == DEVICE_KEY_ALGORITHM {
        return Ok(PROOF_MODE_LOCAL_KEY.to_string());
    }
    if mode == PROOF_MODE_LOCAL_KEY || mode == PROOF_MODE_EPHEMERAL_TICKET {
        return Ok(mode.to_string());
    }
    Err(AppError::DeviceKeyModeInvalid("设备密钥模式不支持"))
}

fn normalize_p256_public_key(value: &str) -> Result<String, AppError> {
    crypto::normalize_p256_public_key(value)
}

fn safe_text(value: &str, max_bytes: usize) -> Result<String, AppError> {
    if value.len() <= max_bytes
        && !value
            .bytes()
            .any(|byte| matches!(byte, b'<' | b'>' | b'"' | 0..=31))
    {
        return Ok(value.to_string());
    }
    Err(AppError::InvalidInput("文本包含非法字符"))
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
    Err(AppError::InvalidInput("文本包含非法字符"))
}

fn security_policy_from_row(row: Option<&SecurityPolicyRow>) -> ClientSecurityPolicy {
    let mode = row
        .map(|row| row.mode.as_str())
        .filter(|mode| SECURITY_POLICY_MODES.contains(mode))
        .unwrap_or("honor_client");
    ClientSecurityPolicy {
        enabled: row.map(|row| row.enabled).unwrap_or(FLAG_ENABLED) == FLAG_ENABLED,
        mode: mode.to_string(),
        min_confidence_for_client_action: row
            .map(|row| row.min_confidence_for_client_action)
            .unwrap_or(0)
            .clamp(0, 100),
        max_client_action: security_policy_action(
            row.map(|row| row.max_client_action.as_str())
                .unwrap_or("disable_card"),
        ),
        allowed_client_actions: allowed_security_actions(
            row.map(|row| row.allowed_client_actions.as_str())
                .unwrap_or("record_only,kick_session,disable_device,disable_card"),
        ),
        kick_score: row.map(|row| row.kick_score).unwrap_or(80).clamp(0, 255),
        disable_device_score: row
            .map(|row| row.disable_device_score)
            .unwrap_or(95)
            .clamp(0, 255),
        disable_card_score: row
            .map(|row| row.disable_card_score)
            .unwrap_or(120)
            .clamp(0, 255),
        client_disable_device_min_score: row
            .map(|row| row.client_disable_device_min_score)
            .unwrap_or(80)
            .clamp(0, 255),
        client_disable_card_min_score: row
            .map(|row| row.client_disable_card_min_score)
            .unwrap_or(95)
            .clamp(0, 255),
        report_rate_limit_per_minute: row
            .map(|row| row.report_rate_limit_per_minute)
            .unwrap_or(20)
            .clamp(1, 1000),
        server_critical_action: security_policy_action(
            row.map(|row| row.server_critical_action.as_str())
                .unwrap_or("disable_card"),
        ),
        server_high_action: security_policy_action(
            row.map(|row| row.server_high_action.as_str())
                .unwrap_or("disable_device"),
        ),
        server_medium_action: security_policy_action(
            row.map(|row| row.server_medium_action.as_str())
                .unwrap_or("manual_review"),
        ),
        server_low_action: security_policy_action(
            row.map(|row| row.server_low_action.as_str())
                .unwrap_or("record_only"),
        ),
    }
}

fn security_policy_action(value: &str) -> String {
    if SECURITY_ACTIONS.contains(&value) {
        return value.to_string();
    }
    "record_only".to_string()
}

fn allowed_security_actions(value: &str) -> Vec<String> {
    let mut actions = vec!["record_only".to_string()];
    for raw_action in value.split(',') {
        let action = raw_action.trim();
        if SECURITY_ACTIONS.contains(&action) && !actions.iter().any(|existing| existing == action)
        {
            actions.push(action.to_string());
        }
    }
    actions
}

fn bounded_client_security_action(
    input: &SecurityReportInput,
    policy: &ClientSecurityPolicy,
    risk_score: i64,
) -> String {
    if !policy.enabled || input.requested_action == "record_only" {
        return "record_only".to_string();
    }
    if input.confidence < policy.min_confidence_for_client_action
        || !policy
            .allowed_client_actions
            .iter()
            .any(|action| action == &input.requested_action)
    {
        return "manual_review".to_string();
    }
    if input.requested_action == "kick_session" && risk_score < policy.kick_score {
        return "manual_review".to_string();
    }
    if input.requested_action == "disable_device"
        && risk_score < policy.client_disable_device_min_score
    {
        return "manual_review".to_string();
    }
    if input.requested_action == "disable_card" && risk_score < policy.client_disable_card_min_score
    {
        return "manual_review".to_string();
    }
    if security_action_rank(&input.requested_action)
        > security_action_rank(&policy.max_client_action)
    {
        return "manual_review".to_string();
    }
    input.requested_action.clone()
}

fn server_score_security_action(risk_score: i64, policy: &ClientSecurityPolicy) -> String {
    if !policy.enabled {
        return "record_only".to_string();
    }
    if risk_score >= policy.disable_card_score {
        return policy.server_critical_action.clone();
    }
    if risk_score >= policy.disable_device_score {
        return policy.server_high_action.clone();
    }
    if risk_score >= policy.kick_score {
        return "kick_session".to_string();
    }
    if risk_score >= 60 {
        return policy.server_medium_action.clone();
    }
    policy.server_low_action.clone()
}

fn security_target_action(
    action: &str,
    session: &ClientSessionRow,
    card: &ClientLoginCard,
    source: &str,
) -> (String, String) {
    if action == "disable_device" && card.card_type == "count" {
        return ("kick_session".to_string(), "server_card_type".to_string());
    }
    if action == "disable_device" && session.device_id.is_none() {
        return ("kick_session".to_string(), "server_target".to_string());
    }
    if action == "disable_card" && card.id.is_none() {
        return ("kick_session".to_string(), "server_target".to_string());
    }
    (action.to_string(), source.to_string())
}

fn security_action_rank(action: &str) -> i64 {
    match action {
        "manual_review" => 1,
        "kick_session" => 2,
        "disable_device" => 3,
        "disable_card" => 4,
        _ => 0,
    }
}

fn security_action_revokes_session(action: &str) -> bool {
    matches!(action, "kick_session" | "disable_device" | "disable_card")
}

fn security_event_base_score(event_type: &str) -> i64 {
    match event_type {
        "debugger_detected" => 70,
        "tracer_detected" => 75,
        "hook_detected" => 85,
        "instrumentation_detected" | "module_tampered" => 90,
        "signature_mismatch" | "attestation_failed" => 95,
        "emulator_detected" => 55,
        "root_detected" => 60,
        "policy_violation" => 65,
        _ => 20,
    }
}

fn security_risk_level_score(risk_level: &str) -> i64 {
    match risk_level {
        "medium" => 50,
        "high" => 75,
        "critical" => 90,
        _ => 20,
    }
}

fn attestation_failed(input: &SecurityReportInput) -> bool {
    input.event_type == "attestation_failed"
        || object_string_field(&input.evidence, "attestation_verdict").is_some_and(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "failed" | "fail" | "rejected"
            )
        })
        || object_string_field(&input.attestation, "verdict").is_some_and(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "failed" | "fail" | "rejected"
            )
        })
}

fn object_string_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.as_object()?.get(key)?.as_str()
}

fn card_security_rate_filters(
    card: &ClientLoginCard,
    since: NaiveDateTime,
) -> SecurityReportCountFilters {
    if let Some(card_id) = card.id {
        return SecurityReportCountFilters {
            card_id: Some(card_id),
            since: Some(since),
            ..Default::default()
        };
    }
    if card.card_hash.trim().is_empty() {
        return SecurityReportCountFilters::default();
    }
    SecurityReportCountFilters {
        card_hash: card.card_hash.clone(),
        since: Some(since),
        ..Default::default()
    }
}

fn security_report_filters_empty(filters: &SecurityReportCountFilters) -> bool {
    filters.session_id.is_none()
        && filters.card_id.is_none()
        && filters.card_hash.is_empty()
        && filters.device_id.is_none()
        && filters.ip.is_empty()
        && filters.event_type.is_empty()
        && filters.since.is_none()
        && filters.risk_levels.is_empty()
}

fn security_message_summary(input: &SecurityReportInput) -> String {
    if !input.message.is_empty() {
        return input.message.clone();
    }
    if !input.action_reason.is_empty() {
        return input.action_reason.clone();
    }
    format!("{} / {}", input.event_type, input.requested_action)
}

fn session_device_touch_id(session: &ClientSessionRow, now: NaiveDateTime) -> Option<u64> {
    let device_id = session.device_id?;
    let should_touch = session
        .device_last_seen_at
        .map(|last_seen_at| (now - last_seen_at).num_seconds() >= DEVICE_TOUCH_INTERVAL_SECONDS)
        .unwrap_or(true);
    should_touch.then_some(device_id)
}

fn route_config(app: &AppDetailRow, route: &str) -> Result<ClientRouteConfig, AppError> {
    let rows = serde_json::from_str::<Value>(&app.api_config_json)
        .ok()
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    let mut used_call_ids = HashSet::new();
    let mut matched_config = None;
    for definition in CLIENT_ROUTES {
        let row = rows
            .iter()
            .rev()
            .find(|row| row.get("route").and_then(Value::as_str) == Some(definition.route));
        let config = ClientRouteConfig {
            call_id: call_id_from_row(row, definition.call_id)?,
            enabled: enabled_from_row(row),
        };
        if !used_call_ids.insert(config.call_id.clone()) {
            return Err(AppError::DuplicateApiCallId);
        }
        if definition.route == route {
            matched_config = Some(config);
        }
    }
    matched_config.ok_or(AppError::RouteNotFound)
}

fn call_id_from_row(row: Option<&Value>, default_call_id: &str) -> Result<String, AppError> {
    let call_id = row
        .and_then(|row| row.get("call_id"))
        .map(php_scalar_string)
        .unwrap_or_default()
        .trim()
        .to_string();
    validate_call_id(if call_id.is_empty() {
        default_call_id
    } else {
        &call_id
    })
}

fn enabled_from_row(row: Option<&Value>) -> i64 {
    let Some(value) = row.and_then(|row| row.get("enabled")) else {
        return FLAG_ENABLED;
    };
    if value_to_i64(value) == Some(FLAG_DISABLED) {
        FLAG_DISABLED
    } else {
        FLAG_ENABLED
    }
}

fn validate_call_id(value: &str) -> Result<String, AppError> {
    if (2..=80).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
    {
        return Ok(value.to_string());
    }
    Err(AppError::InvalidApiCallId)
}

fn resolved_api_token(app: &AppDetailRow, system_key: &str) -> Result<String, AppError> {
    let token = app.api_token.trim();
    if token.is_empty() {
        return legacy_api_token(&app.app_code, system_key);
    }
    validate_api_token(token)
}

fn validate_api_token(value: &str) -> Result<String, AppError> {
    if (16..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Ok(value.to_string());
    }
    Err(AppError::InvalidApiToken)
}

fn legacy_api_token(app_code: &str, system_key: &str) -> Result<String, AppError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(system_key.as_bytes())
        .map_err(|_| AppError::CryptoError("应用 Token 密钥错误"))?;
    mac.update(app_code.as_bytes());
    Ok(crypto::encode_base64_url(&mac.finalize().into_bytes())[..43].to_string())
}

fn hmac_sha256_base64_url(secret: &[u8], value: &str) -> Result<String, AppError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret)
        .map_err(|_| AppError::CryptoError("HMAC 密钥格式错误"))?;
    mac.update(value.as_bytes());
    Ok(crypto::encode_base64_url(&mac.finalize().into_bytes()))
}

fn client_success_code(value: i64) -> i64 {
    if (0..=999_999).contains(&value) {
        value
    } else {
        0
    }
}

fn constant_eq(left: &str, right: &str) -> bool {
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

fn payload_scalar_text(payload: &Value, key: &str) -> String {
    payload.get(key).map(php_scalar_string).unwrap_or_default()
}

fn payload_scalar_text_or(payload: &Value, key: &str, default: &str) -> String {
    match payload.get(key) {
        Some(value) => php_scalar_string(value),
        None => default.to_string(),
    }
}

pub(crate) fn php_scalar_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(true) => "1".to_string(),
        Value::Bool(false) => String::new(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => text.to_string(),
        Value::Array(_) | Value::Object(_) => "Array".to_string(),
    }
}

fn value_to_i64(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => number.as_i64(),
        Value::String(text) => text.trim().parse::<i64>().ok(),
        Value::Bool(true) => Some(1),
        Value::Bool(false) => Some(0),
        _ => None,
    }
}

fn card_hash(app: &AppDetailRow, card_key: &str) -> String {
    crypto::sha256_hex(&format!("{}:{}", app.app_code, card_key))
}

fn normalized_card_type(value: &str) -> String {
    match value {
        "permanent" | "count" => value.to_string(),
        _ => "time".to_string(),
    }
}

fn card_expiry(card_type: &str, card: &CardRow) -> NaiveDateTime {
    card_expiry_from_parts(card_type, card.used_at, card.duration_seconds)
}

fn card_expiry_from_parts(
    card_type: &str,
    used_at: Option<NaiveDateTime>,
    duration_seconds: i64,
) -> NaiveDateTime {
    if matches!(card_type, "permanent" | "count") {
        return permanent_card_expires_at();
    }
    let base_time = used_at.unwrap_or_else(|| Local::now().naive_local());
    base_time + Duration::seconds(duration_seconds.max(1))
}

fn permanent_card_expires_at() -> NaiveDateTime {
    NaiveDateTime::parse_from_str(PERMANENT_CARD_EXPIRES_AT, "%Y-%m-%d %H:%M:%S")
        .expect("valid permanent card expiry")
}

fn local_timestamp(value: NaiveDateTime) -> i64 {
    Local
        .from_local_datetime(&value)
        .single()
        .or_else(|| Local.from_local_datetime(&value).earliest())
        .map(|datetime| datetime.timestamp())
        .unwrap_or(0)
}

fn format_datetime(value: Option<NaiveDateTime>) -> String {
    value.map(format_naive_datetime).unwrap_or_default()
}

fn format_naive_datetime(value: NaiveDateTime) -> String {
    value.format("%Y-%m-%d %H:%M:%S").to_string()
}

fn card_key_fingerprint(card_key: &str) -> String {
    visible_fingerprint(card_key, 6, 4)
}

fn hash_fingerprint(value: &str) -> String {
    visible_fingerprint(value, 8, 6)
}

fn visible_fingerprint(value: &str, head_length: usize, tail_length: usize) -> String {
    if value.len() <= head_length + tail_length {
        return value.to_string();
    }
    let head = value.chars().take(head_length).collect::<String>();
    let tail = value
        .chars()
        .rev()
        .take(tail_length)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    format!("{head}...{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_php_legacy_api_token() {
        let app = app_with_config("[]");
        assert_eq!(
            "gg-C_YT0s5ijtjVySsXm8NGGyBqpcYQcz3wSvalPJ48",
            resolved_api_token(&app, "system-key").expect("legacy token")
        );
    }

    #[test]
    fn normalizes_client_route_config_like_php() {
        let app = app_with_config(r#"[{"route":"/notice","call_id":"custom.notice","enabled":0}]"#);
        let config = route_config(&app, "/notice").expect("notice config");

        assert_eq!("custom.notice", config.call_id);
        assert_eq!(0, config.enabled);
        assert!(matches!(
            route_config(&app, "/missing"),
            Err(AppError::RouteNotFound)
        ));
    }

    #[test]
    fn rejects_duplicate_client_call_ids_like_php_normalizer() {
        let app = app_with_config(
            r#"[
                {"route":"/notice","call_id":"same.call"},
                {"route":"/login","call_id":"same.call"}
            ]"#,
        );

        assert!(matches!(
            route_config(&app, "/notice"),
            Err(AppError::DuplicateApiCallId)
        ));
        assert!(matches!(
            route_config(&app, "/login"),
            Err(AppError::DuplicateApiCallId)
        ));
    }

    #[test]
    fn validates_client_card_key_by_verification_mode() {
        let enabled_app = app_with_config("[]");
        let mut disabled_app = enabled_app.clone();
        disabled_app.verification_enabled = 0;

        assert!(client_card_key(&enabled_app, "ABCDEF12").is_ok());
        assert!(client_card_key(&enabled_app, "中文卡密").is_err());
        assert_eq!(
            "中文卡密",
            client_card_key(&disabled_app, "中文卡密").expect("plain card key")
        );
    }

    #[test]
    fn builds_stateless_login_challenge_like_php() {
        let app = app_with_config("[]");
        let input = challenge_input(&json!({
            "install_id": "install_12345678",
            "device_name": "Windows Client",
            "device_key_mode": "ephemeral_ticket_v1"
        }))
        .expect("challenge input");
        let challenge_id = stateless_login_challenge(
            "system-key",
            &app,
            &input,
            "server_nonce_1234567890",
            1_782_000_000,
        )
        .expect("challenge id");
        let (encoded_payload, signature) = challenge_id.split_once('.').expect("signed payload");

        assert_eq!(
            hmac_sha256_base64_url(b"system-key", encoded_payload).expect("signature"),
            signature
        );
        let decoded = crypto::decode_base64_url(encoded_payload).expect("payload base64");
        let payload: Value = serde_json::from_slice(&decoded).expect("payload json");
        assert_eq!(LOGIN_CHALLENGE_VERSION, payload["v"]);
        assert_eq!(1, payload["a"]);
        assert_eq!("install_12345678", payload["i"]);
        assert_eq!("Windows Client", payload["d"]);
        assert_eq!("", payload["p"]);
        assert_eq!("ephemeral_ticket_v1", payload["m"]);
        assert_eq!("server_nonce_1234567890", payload["n"]);
        assert_eq!(1_782_000_000, payload["e"]);
        assert!(
            payload["r"]
                .as_str()
                .is_some_and(|random| random.len() >= 16)
        );
    }

    #[test]
    fn validates_challenge_input_like_php() {
        assert_eq!(
            PROOF_MODE_LOCAL_KEY,
            normalize_proof_mode(DEVICE_KEY_ALGORITHM).expect("legacy mode")
        );
        assert!(matches!(
            challenge_input(&json!({
                "install_id": "short",
                "device_key_mode": "ephemeral_ticket_v1"
            })),
            Err(AppError::InvalidInput("安装标识格式错误"))
        ));
        assert!(matches!(
            challenge_input(&json!({
                "install_id": "install_12345678",
                "device_key_mode": "bad-mode"
            })),
            Err(AppError::InvalidInput("设备密钥模式格式错误"))
        ));
    }

    #[test]
    fn renders_virtual_card_query_response_like_php() {
        let mut app = app_with_config("[]");
        app.verification_enabled = 0;
        let card = ClientCard::virtual_card("ABCDEF123456", &card_hash(&app, "ABCDEF123456"));
        let response = card_query_response(card);

        assert_eq!("ABCDEF...3456", response["card_fingerprint"]);
        assert_eq!("time", response["card_type"]);
        assert_eq!(0, response["status"]);
        assert_eq!(i64::MAX, response["max_devices"]);
    }

    #[test]
    fn validates_plain_ephemeral_login_input_like_php() {
        let app = app_with_config("[]");
        let payload = json!({
            "card_key": "ABCDEF123456",
            "challenge_id": "ephemeral.12345678901234567890",
            "install_id": "install_12345678",
            "device_name": "Windows Client",
            "machine_profile_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "timestamp": 1782000000_i64,
            "signature": "",
            "device_key_mode": "ephemeral_ticket_v1",
            "client_version": ""
        });
        let input = login_input(&app, &payload).expect("login input");

        assert_eq!("ABCDEF123456", input.card_key);
        assert_eq!("ephemeral.12345678901234567890", input.challenge_id);
        assert_eq!(PROOF_MODE_EPHEMERAL_TICKET, input.device_key_mode);
        assert!(matches!(
            login_input(
                &app,
                &json!({
                    "card_key": "ABCDEF123456",
                    "challenge_id": "ephemeral.short",
                    "install_id": "install_12345678",
                    "device_name": "Windows Client",
                    "machine_profile_hash": "bad",
                    "timestamp": "bad",
                    "signature": "",
                    "device_key_mode": "ephemeral_ticket_v1"
                })
            ),
            Err(AppError::InvalidInput("挑战标识格式错误"))
        ));
    }

    #[test]
    fn renders_ephemeral_login_response_order_like_php() {
        let app = app_with_config("[]");
        let card = ClientLoginCard {
            id: Some(1),
            card_hash: "hash".to_string(),
            card_fingerprint: "ABCDEF...3456".to_string(),
            card_type: "count".to_string(),
            expires_at: permanent_card_expires_at(),
            remaining_uses: 7,
            max_devices: 50,
            first_use: false,
        };
        let response = login_response(
            &app,
            &card,
            "session-token",
            permanent_card_expires_at(),
            PROOF_MODE_EPHEMERAL_TICKET,
            Some("ticket-token"),
            Some(permanent_card_expires_at()),
            "",
        );
        let keys = response
            .as_object()
            .expect("object")
            .keys()
            .cloned()
            .collect::<Vec<_>>();

        assert_eq!(
            vec![
                "token",
                "token_expires_at",
                "card_expires_at",
                "heartbeat_interval",
                "proof_mode",
                "remaining_uses",
                "session_ticket",
                "ticket_expires_at",
                "ip_check"
            ],
            keys
        );
        assert_eq!(7, response["remaining_uses"]);
        assert_eq!(false, response["ip_check"]["enabled"]);
    }

    #[test]
    fn renders_local_key_login_response_without_ticket_like_php() {
        let app = app_with_config("[]");
        let card = ClientLoginCard {
            id: Some(1),
            card_hash: "hash".to_string(),
            card_fingerprint: "ABCDEF...3456".to_string(),
            card_type: "time".to_string(),
            expires_at: permanent_card_expires_at(),
            remaining_uses: 0,
            max_devices: 50,
            first_use: false,
        };
        let response = login_response(
            &app,
            &card,
            "session-token",
            permanent_card_expires_at(),
            PROOF_MODE_LOCAL_KEY,
            None,
            None,
            "",
        );
        let object = response.as_object().expect("object");

        assert_eq!(PROOF_MODE_LOCAL_KEY, object["proof_mode"]);
        assert!(!object.contains_key("session_ticket"));
        assert!(!object.contains_key("ticket_expires_at"));
    }

    #[test]
    fn renders_heartbeat_response_order_like_php() {
        let app = app_with_config("[]");
        let rotated_session = rotated_session("time", 0);
        let response = heartbeat_response(&app, &rotated_session);
        let keys = response
            .as_object()
            .expect("object")
            .keys()
            .cloned()
            .collect::<Vec<_>>();

        assert_eq!(
            vec![
                "ok",
                "token",
                "token_expires_at",
                "card_expires_at",
                "heartbeat_interval",
                "proof_mode",
                "session_ticket",
                "ticket_expires_at"
            ],
            keys
        );
        assert_eq!(true, response["ok"]);
    }

    #[test]
    fn renders_local_key_heartbeat_response_without_ticket_like_php() {
        let app = app_with_config("[]");
        let mut rotated_session = rotated_session("time", 0);
        rotated_session.proof_mode = PROOF_MODE_LOCAL_KEY.to_string();
        rotated_session.session_ticket = None;
        rotated_session.ticket_expires_at = None;
        let response = heartbeat_response(&app, &rotated_session);
        let object = response.as_object().expect("object");

        assert_eq!(PROOF_MODE_LOCAL_KEY, object["proof_mode"]);
        assert!(!object.contains_key("session_ticket"));
        assert!(!object.contains_key("ticket_expires_at"));
    }

    #[test]
    fn renders_config_response_order_like_php() {
        let app = app_with_config("[]");
        let config = RemoteConfigRow {
            app_id: 1,
            notice: "notice".to_string(),
            config_json: "{}".to_string(),
            variables_json: "{}".to_string(),
            version: "1.2.3".to_string(),
            force_update: 1,
            download_url: "https://example.test/app.zip".to_string(),
            status: 1,
        };
        let rotated_session = rotated_session("time", 0);
        let response = config_response(&app, &rotated_session, Some(&config));
        let keys = response
            .as_object()
            .expect("object")
            .keys()
            .cloned()
            .collect::<Vec<_>>();

        assert_eq!(
            vec![
                "token",
                "token_expires_at",
                "card_expires_at",
                "heartbeat_interval",
                "proof_mode",
                "session_ticket",
                "ticket_expires_at",
                "version",
                "download_url",
                "force_update",
                "notice"
            ],
            keys
        );
        assert_eq!("1.2.3", response["version"]);
        assert_eq!(1, response["force_update"]);
    }

    #[test]
    fn renders_variable_response_order_like_php() {
        let app = app_with_config("[]");
        let rotated_session = rotated_session("time", 0);
        let response = variable_response(&app, &rotated_session, Some("plain-value".to_string()));
        let keys = response
            .as_object()
            .expect("object")
            .keys()
            .cloned()
            .collect::<Vec<_>>();

        assert_eq!(
            vec![
                "token",
                "token_expires_at",
                "card_expires_at",
                "heartbeat_interval",
                "proof_mode",
                "session_ticket",
                "ticket_expires_at",
                "value"
            ],
            keys
        );
        assert_eq!("plain-value", response["value"]);
    }

    #[test]
    fn renders_cloud_download_ticket_response_order_like_php() {
        let app = app_with_config("[]");
        let rotated_session = rotated_session("time", 0);
        let ticket = ClientDownloadTicket {
            ticket: "download-ticket".to_string(),
            expires_at: 1_781_200_300,
        };
        let response = cloud_download_ticket_response(&app, &rotated_session, &ticket);
        let keys = response
            .as_object()
            .expect("object")
            .keys()
            .cloned()
            .collect::<Vec<_>>();

        assert_eq!(
            vec![
                "token",
                "token_expires_at",
                "card_expires_at",
                "heartbeat_interval",
                "proof_mode",
                "session_ticket",
                "ticket_expires_at",
                "download_url",
                "download_ticket",
                "expires_at"
            ],
            keys
        );
        assert_eq!(
            "/api/v1/index.php?route=%2Fcloud%2Fdownload&ticket=download-ticket",
            response["download_url"]
        );
        assert_eq!("download-ticket", response["download_ticket"]);
        assert_eq!(1_781_200_300, response["expires_at"]);
    }

    #[test]
    fn renders_logout_response_like_php() {
        assert_eq!(json!({ "logged_out": true }), logout_response());
    }

    #[test]
    fn renders_unbind_response_like_php() {
        assert_eq!(json!({ "unbound": true }), unbind_response(true));
        assert_eq!(json!({ "unbound": false }), unbind_response(false));
    }

    #[test]
    fn validates_unbind_input_like_php() {
        let signature = "A".repeat(64);
        let payload = json!({
            "card_key": "CARDKEY123",
            "install_id": "install_12345678",
            "timestamp": "1781200300",
            "signature": signature
        });
        let input = unbind_input(&app_with_config("[]"), &payload).expect("unbind input");

        assert_eq!("CARDKEY123", input.card_key);
        assert_eq!("install_12345678", input.install_id);
        assert_eq!(1_781_200_300, input.timestamp);
        assert_eq!(
            "POST\n/unbind\ninstall_12345678\n1781200300\ncard-hash",
            unbind_canonical(&input.install_id, input.timestamp, "card-hash")
        );
        assert!(matches!(
            unbind_input(
                &app_with_config("[]"),
                &json!({
                    "card_key": "CARDKEY123",
                    "install_id": "short",
                    "timestamp": "1781200300",
                    "signature": "A".repeat(64)
                })
            ),
            Err(AppError::InvalidInput("安装标识格式错误"))
        ));
    }

    #[test]
    fn builds_client_crypto_aad_like_php() {
        let algorithm = crypto::ClientCryptoAlgorithm::RsaOaepAes256Gcm;

        assert_eq!(
            "client-request\n/unbind\n1781200300\nnonce-token\nrsa_oaep_aes_256_gcm",
            client_request_aad("/unbind", "1781200300", "nonce-token", algorithm)
        );
        assert_eq!(
            "client-response\n/unbind\n1781200300\nnonce-token\nrsa_oaep_aes_256_gcm",
            client_response_aad("/unbind", "1781200300", "nonce-token", algorithm)
        );
    }

    #[test]
    fn validates_client_crypto_algorithm_like_php() {
        let mut app = app_with_config("[]");
        app.client_crypto_alg = "rsa_oaep_aes_128_gcm".to_string();

        assert_eq!(
            crypto::ClientCryptoAlgorithm::RsaOaepAes128Gcm,
            client_crypto_algorithm(&json!({"alg": "rsa_oaep_aes_128_gcm"}), &app)
                .expect("algorithm")
        );
        assert!(matches!(
            client_crypto_algorithm(&json!({"alg": "rsa_oaep_aes_256_gcm"}), &app),
            Err(AppError::CryptoAlgorithmMismatch)
        ));
    }

    #[test]
    fn renders_security_report_response_order_like_php() {
        let input = security_report_input(&json!({
            "event_id": "evt.logout.001",
            "event_type": "debugger_detected",
            "risk_level": "high",
            "confidence": 91,
            "requested_action": "kick_session",
            "action_reason": "debugger attached",
            "title": "Debugger",
            "message": "Debugger detected",
            "evidence": {"detector": "ptrace"},
            "attestation": {},
            "occurred_at": 1781200300,
            "sdk_version": "1.0.0",
            "detector_version": "1.0.0",
            "platform": "Android"
        }))
        .expect("security input");
        let decision = SecurityDecision {
            action: "kick_session".to_string(),
            action_source: "client".to_string(),
            risk_score: 85,
        };
        let result = ClientSecurityReportResult {
            report_id: 11,
            message_id: 22,
            session_revoked: true,
            device_disabled: false,
            card_disabled: false,
            revoked_sessions: 1,
        };
        let response = Value::Object(security_report_response(&input, &decision, &result));
        let keys = response
            .as_object()
            .expect("object")
            .keys()
            .cloned()
            .collect::<Vec<_>>();

        assert_eq!(
            vec![
                "message_id",
                "report_id",
                "risk_score",
                "requested_action",
                "action",
                "action_source",
                "session_revoked",
                "device_disabled",
                "card_disabled",
                "revoked_sessions"
            ],
            keys
        );
        assert_eq!(22, response["message_id"]);
        assert_eq!(true, response["session_revoked"]);
    }

    #[test]
    fn validates_security_report_input_like_php() {
        let payload = json!({
            "event_id": "evt.input.001",
            "event_type": "hook_detected",
            "risk_level": "critical",
            "confidence": "90.9",
            "requested_action": "disable_card",
            "action_reason": "",
            "title": "Hook",
            "message": "Hook detected",
            "evidence": {"hook_count": 1, "process_hashes": ["abc"]},
            "attestation": [],
            "occurred_at": "1781200300",
            "sdk_version": "1.0.0",
            "detector_version": "1.0.0",
            "platform": "WINDOWS"
        });
        let input = security_report_input(&payload).expect("security input");

        assert_eq!("hook_detected", input.event_type);
        assert_eq!("critical", input.risk_level);
        assert_eq!(90, input.confidence);
        assert_eq!("windows", input.platform);
        assert!(!attestation_failed(&input));
        assert!(matches!(
            security_report_input(&json!({"card_id": 1})),
            Err(AppError::SecurityReportInvalid("安全上报不能指定处置目标"))
        ));
        assert!(matches!(
            security_report_input(&json!({
                "event_id": "evt.input.002",
                "event_type": "missing_event",
                "risk_level": "low",
                "confidence": 1,
                "title": "Title",
                "message": "Message",
                "evidence": {"detector": "x"},
                "occurred_at": 1781200300,
                "sdk_version": "1.0.0",
                "detector_version": "1.0.0",
                "platform": "android"
            })),
            Err(AppError::SecurityReportInvalid("安全事件类型不支持"))
        ));
    }

    #[test]
    fn chooses_bounded_client_security_action_like_php() {
        let input = security_report_input(&json!({
            "event_id": "evt.policy.001",
            "event_type": "root_detected",
            "risk_level": "high",
            "confidence": 95,
            "requested_action": "disable_card",
            "title": "Root",
            "message": "Root detected",
            "evidence": {"detector": "su"},
            "attestation": {},
            "occurred_at": 1781200300,
            "sdk_version": "1.0.0",
            "detector_version": "1.0.0",
            "platform": "android"
        }))
        .expect("security input");
        let policy = ClientSecurityPolicy {
            enabled: true,
            mode: "bounded_client".to_string(),
            min_confidence_for_client_action: 80,
            max_client_action: "disable_device".to_string(),
            allowed_client_actions: vec![
                "record_only".to_string(),
                "kick_session".to_string(),
                "disable_device".to_string(),
                "disable_card".to_string(),
            ],
            kick_score: 80,
            disable_device_score: 95,
            disable_card_score: 120,
            client_disable_device_min_score: 80,
            client_disable_card_min_score: 95,
            report_rate_limit_per_minute: 20,
            server_critical_action: "disable_card".to_string(),
            server_high_action: "disable_device".to_string(),
            server_medium_action: "manual_review".to_string(),
            server_low_action: "record_only".to_string(),
        };

        assert_eq!(
            "manual_review",
            bounded_client_security_action(&input, &policy, 100)
        );
    }

    #[test]
    fn builds_cloud_download_ticket_payload_like_php() {
        let ticket = cloud_download_ticket("cf_1234567890ABCDEF", "system-key")
            .expect("ticket should build");
        let decrypted = crypto::decrypt_protected_text(&ticket.ticket, "system-key")
            .expect("ticket should decrypt");
        let payload = serde_json::from_str::<Value>(&decrypted).expect("ticket payload");
        let keys = payload
            .as_object()
            .expect("object")
            .keys()
            .cloned()
            .collect::<Vec<_>>();

        assert_eq!(vec!["v", "file_key", "exp", "nonce"], keys);
        assert_eq!(1, payload["v"]);
        assert_eq!("cf_1234567890ABCDEF", payload["file_key"]);
        assert_eq!(ticket.expires_at, payload["exp"]);
        assert_eq!(16, payload["nonce"].as_str().expect("nonce").len());
        assert!(
            (250..=300).contains(&(ticket.expires_at - Local::now().timestamp())),
            "download ticket TTL should match PHP"
        );
    }

    #[test]
    fn validates_cloud_file_key_like_php() {
        assert_eq!(
            "cf_1234567890ABCDEF",
            cloud_file_key(" cf_1234567890ABCDEF ").expect("file key")
        );
        assert!(matches!(
            cloud_file_key("short"),
            Err(AppError::CloudFileKeyInvalid)
        ));
        assert!(matches!(
            cloud_file_key("cf_1234567890ABCDEF.bad"),
            Err(AppError::CloudFileKeyInvalid)
        ));
    }

    #[test]
    fn parses_request_counter_like_php_numeric_cast() {
        assert_eq!(
            2,
            validate_request_counter(&json!("2.9")).expect("numeric string")
        );
        assert!(matches!(
            validate_request_counter(&json!(true)),
            Err(AppError::InvalidInput("请求计数器格式错误"))
        ));
        assert!(matches!(
            validate_request_counter(&json!(0)),
            Err(AppError::InvalidInput("请求计数器格式错误"))
        ));
    }

    fn app_with_config(api_config_json: &str) -> AppDetailRow {
        AppDetailRow {
            id: 1,
            app_code: "ace_app".to_string(),
            api_token: String::new(),
            name: "ACE".to_string(),
            status: 1,
            max_devices: 50,
            heartbeat_interval: 60,
            heartbeat_enabled: 1,
            verification_enabled: 1,
            device_binding_enabled: 1,
            shared_cards_enabled: 0,
            login_ip_binding_enabled: 0,
            web_card_query_enabled: 1,
            unbind_interval_seconds: 0,
            unbind_deduct_seconds: 0,
            unbind_deduct_uses: 0,
            api_success_code: 0,
            api_config_json: api_config_json.to_string(),
            latest_version: String::new(),
            client_auth_mode: String::new(),
            client_crypto_alg: String::new(),
            client_public_key: String::new(),
            client_private_key_cipher: String::new(),
            remark: String::new(),
            created_at: None,
            updated_at: None,
        }
    }

    fn rotated_session(card_type: &str, remaining_uses: i64) -> RotatedClientSession {
        RotatedClientSession {
            card: ClientLoginCard {
                id: Some(1),
                card_hash: "hash".to_string(),
                card_fingerprint: "ABCDEF...3456".to_string(),
                card_type: card_type.to_string(),
                expires_at: permanent_card_expires_at(),
                remaining_uses,
                max_devices: 50,
                first_use: false,
            },
            token: "next-token".to_string(),
            session_expires_at: permanent_card_expires_at(),
            proof_mode: PROOF_MODE_EPHEMERAL_TICKET.to_string(),
            session_ticket: Some("next-ticket".to_string()),
            ticket_expires_at: Some(permanent_card_expires_at()),
        }
    }
}
