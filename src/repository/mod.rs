use chrono::NaiveDateTime;
use serde_json::Value;
use sqlx::{
    MySql, MySqlPool, QueryBuilder, Row,
    mysql::{MySqlConnectOptions, MySqlPoolOptions},
    types::Json,
};

use crate::{config::DatabaseConfig, error::AppError};

#[derive(Debug, Clone)]
pub struct AuthRepository {
    pool: MySqlPool,
}

const CLOUD_FILE_SELECT_COLUMNS: &str = "f.`id`, f.`file_key`, f.`provider`, f.`config_id`, \
    f.`original_name`, f.`mime_type`, f.`extension`, CAST(f.`size_bytes` AS SIGNED) AS `size_bytes`, \
    f.`sha256`, f.`object_key`, f.`local_path`, f.`status`, f.`remark`, \
    CAST(f.`download_count` AS SIGNED) AS `download_count`, f.`last_download_ip`, \
    f.`last_download_at`, f.`created_at`, f.`updated_at`";

const CLOUD_STORAGE_CONFIG_SELECT_COLUMNS: &str = "`id`, `provider`, \
    CAST(`status` AS SIGNED) AS `status`, CAST(`is_default` AS SIGNED) AS `is_default`, \
    `bucket`, `region`, `endpoint`, `access_key`, `secret_cipher`, `path_prefix`, \
    `custom_domain`, CAST(`max_file_size` AS SIGNED) AS `max_file_size`, \
    `allowed_extensions`, CAST(`signed_url_ttl_seconds` AS SIGNED) AS `signed_url_ttl_seconds`, \
    `last_test_status`, `last_test_message`, `last_test_at`";

const ADMIN_SESSION_SELECT_BY_TOKEN_HASH: &str = "SELECT `id`, `key_cipher`, `ip`, \
    `admin_username`, CAST(`status` AS SIGNED) AS `status`, `expires_at` \
    FROM `auth_admin_sessions` WHERE `token_hash` = ?";
const MIN_CARD_DURATION_SECONDS: i64 = 60;
const MAX_CARD_DURATION_SECONDS: i64 = 315_360_000;
const RESET_COUNT_CARD_USES_CHANGED_FILTER: &str = " AND `remaining_uses` <> `total_uses`";
const CARD_STATUS_CHANGED_FILTER: &str = " AND `status` <> ";
const ADD_TIME_CARD_DURATION_CHANGED_FILTER: &str = " AND `duration_seconds` < ";
const REDUCE_TIME_CARD_DURATION_CHANGED_FILTER: &str = " AND `duration_seconds` > ";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminRow {
    pub username: String,
    pub password: String,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
    pub remember_login_token_hash: String,
    pub remember_login_expires_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminSessionRow {
    pub id: u64,
    pub key_cipher: String,
    pub ip: String,
    pub admin_username: String,
    pub status: i32,
    pub expires_at: NaiveDateTime,
}

pub struct NewAdminSession<'a> {
    pub token_hash: &'a str,
    pub key_cipher: &'a str,
    pub ip: &'a str,
    pub admin_username: &'a str,
    pub expires_at: NaiveDateTime,
    pub status: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientLoginCommand {
    pub app_id: u64,
    pub verification_enabled: bool,
    pub device_binding_enabled: bool,
    pub shared_cards_enabled: bool,
    pub login_ip_binding_enabled: bool,
    pub app_max_devices: i64,
    pub heartbeat_interval: i64,
    pub card_key: String,
    pub card_hash: String,
    pub install_id: String,
    pub device_hash: String,
    pub device_name: String,
    pub machine_profile_hash: String,
    pub ip: String,
    pub bind_ip: String,
    pub bind_region: String,
    pub proof_mode: String,
    pub device_public_key: String,
    pub token_hash: String,
    pub ticket_hash: Option<String>,
    pub ticket_expires_at: Option<NaiveDateTime>,
    pub challenge_nonce_hash: Option<String>,
    pub challenge_expires_at: Option<NaiveDateTime>,
    pub now: NaiveDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientLoginResult {
    pub card: ClientLoginCard,
    pub device_id: Option<u64>,
    pub session_id: u64,
    pub session_expires_at: NaiveDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientLoginCard {
    pub id: Option<u64>,
    pub card_hash: String,
    pub card_fingerprint: String,
    pub card_type: String,
    pub expires_at: NaiveDateTime,
    pub remaining_uses: i64,
    pub max_devices: i64,
    pub first_use: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientLoginDeviceRow {
    pub id: u64,
    pub app_id: u64,
    pub account_id: Option<u64>,
    pub card_id: Option<u64>,
    pub card_hash: String,
    pub device_hash: String,
    pub device_name: String,
    pub install_id: String,
    pub device_public_key: String,
    pub device_key_alg: String,
    pub machine_profile_hash: String,
    pub bind_ip: String,
    pub bind_region: String,
    pub risk_level: i64,
    pub status: i64,
    pub first_seen_at: NaiveDateTime,
    pub last_seen_at: NaiveDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientUnbindDeviceRow {
    pub id: u64,
    pub device_public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientUnbindCommand {
    pub app_id: u64,
    pub verification_enabled: bool,
    pub card_hash: String,
    pub install_id: String,
    pub verified_device_public_key: String,
    pub unbind_interval_seconds: i64,
    pub unbind_deduct_seconds: i64,
    pub unbind_deduct_uses: i64,
    pub now: NaiveDateTime,
    pub ip: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientLoginActiveSession {
    pub id: u64,
    pub device_id: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSessionRow {
    pub id: u64,
    pub app_id: u64,
    pub device_id: Option<u64>,
    pub card_id: Option<u64>,
    pub card_hash: String,
    pub card_fingerprint: String,
    pub token_hash: String,
    pub request_counter: i64,
    pub proof_mode: String,
    pub ticket_hash: Option<String>,
    pub ticket_expires_at: Option<NaiveDateTime>,
    pub status: i64,
    pub expires_at: NaiveDateTime,
    pub device_status: Option<i64>,
    pub install_id: String,
    pub device_public_key: String,
    pub device_key_alg: String,
    pub device_last_seen_at: Option<NaiveDateTime>,
    pub card_status: Option<i64>,
    pub stored_card_hash: String,
    pub stored_card_fingerprint: String,
    pub stored_card_type: String,
    pub stored_card_duration_seconds: i64,
    pub stored_card_remaining_uses: i64,
    pub stored_card_max_devices: i64,
    pub stored_card_used_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSessionRotation {
    pub session_id: u64,
    pub current_token_hash: String,
    pub next_token_hash: String,
    pub request_counter: i64,
    pub heartbeat_at: NaiveDateTime,
    pub expires_at: NaiveDateTime,
    pub ticket_hash: Option<String>,
    pub ticket_expires_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ClientLoginDeviceIdentity {
    id: u64,
    created: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SiteSettingsRow {
    pub hostname: String,
    pub site_subtitle: String,
    pub siteurl: String,
    pub logo_url: String,
    pub announcement: String,
    pub contact: String,
    pub footer_text: String,
    pub custom_json: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SiteSettingsUpdate {
    pub hostname: String,
    pub site_subtitle: String,
    pub siteurl: String,
    pub logo_url: String,
    pub announcement: String,
    pub contact: String,
    pub footer_text: String,
    pub custom_json: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminCredentialsUpdate {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AppRow {
    pub id: u64,
    pub app_code: String,
    pub api_token: String,
    pub name: String,
    pub status: i64,
    pub max_devices: i64,
    pub heartbeat_interval: i64,
    pub heartbeat_enabled: i64,
    pub verification_enabled: i64,
    pub device_binding_enabled: i64,
    pub shared_cards_enabled: i64,
    pub login_ip_binding_enabled: i64,
    pub web_card_query_enabled: i64,
    pub unbind_interval_seconds: i64,
    pub unbind_deduct_seconds: i64,
    pub unbind_deduct_uses: i64,
    pub api_success_code: i64,
    pub api_config_json: String,
    pub latest_version: String,
    pub client_auth_mode: String,
    pub client_crypto_alg: String,
    pub remark: String,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
    pub cards_total: i64,
    pub devices_total: i64,
    pub sessions_active: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AppDetailRow {
    pub id: u64,
    pub app_code: String,
    pub api_token: String,
    pub name: String,
    pub status: i64,
    pub max_devices: i64,
    pub heartbeat_interval: i64,
    pub heartbeat_enabled: i64,
    pub verification_enabled: i64,
    pub device_binding_enabled: i64,
    pub shared_cards_enabled: i64,
    pub login_ip_binding_enabled: i64,
    pub web_card_query_enabled: i64,
    pub unbind_interval_seconds: i64,
    pub unbind_deduct_seconds: i64,
    pub unbind_deduct_uses: i64,
    pub api_success_code: i64,
    pub api_config_json: String,
    pub latest_version: String,
    pub client_auth_mode: String,
    pub client_crypto_alg: String,
    pub client_public_key: String,
    pub client_private_key_cipher: String,
    pub remark: String,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

pub struct NewApp {
    pub app_code: String,
    pub api_token: String,
    pub name: String,
    pub status: i64,
    pub max_devices: i64,
    pub heartbeat_interval: i64,
    pub heartbeat_enabled: i64,
    pub verification_enabled: i64,
    pub device_binding_enabled: i64,
    pub shared_cards_enabled: i64,
    pub login_ip_binding_enabled: i64,
    pub web_card_query_enabled: i64,
    pub unbind_interval_seconds: i64,
    pub unbind_deduct_seconds: i64,
    pub unbind_deduct_uses: i64,
    pub api_success_code: i64,
    pub api_config_json: String,
    pub latest_version: String,
    pub client_auth_mode: String,
    pub client_crypto_alg: String,
    pub client_public_key: String,
    pub client_private_key_cipher: String,
    pub remark: String,
}

pub struct AppSettingsUpdate {
    pub name: String,
    pub max_devices: i64,
    pub heartbeat_interval: i64,
    pub heartbeat_enabled: i64,
    pub verification_enabled: i64,
    pub device_binding_enabled: i64,
    pub shared_cards_enabled: i64,
    pub login_ip_binding_enabled: i64,
    pub latest_version: String,
    pub client_auth_mode: String,
    pub client_crypto_alg: String,
    pub remark: String,
}

pub struct AppApiUpdate {
    pub api_token: String,
    pub login_ip_binding_enabled: i64,
    pub web_card_query_enabled: i64,
    pub unbind_interval_seconds: i64,
    pub unbind_deduct_seconds: i64,
    pub unbind_deduct_uses: i64,
    pub api_success_code: i64,
    pub api_config_json: String,
}

pub struct AppClientCryptoUpdate {
    pub client_crypto_alg: String,
    pub client_public_key: String,
    pub client_private_key_cipher: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteConfigRow {
    pub app_id: u64,
    pub notice: String,
    pub config_json: String,
    pub variables_json: String,
    pub version: String,
    pub force_update: i64,
    pub download_url: String,
    pub status: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteConfigUpsert {
    pub app_id: u64,
    pub notice: String,
    pub config_json: String,
    pub variables_json: String,
    pub version: String,
    pub force_update: i64,
    pub download_url: String,
    pub status: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteVariableRow {
    pub id: u64,
    pub name: String,
    pub value: String,
    pub scope: String,
    pub status: i64,
    pub app_ids_csv: String,
    pub app_names_csv: String,
    pub app_count: i64,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteVariableDetailRow {
    pub id: u64,
    pub name: String,
    pub value: String,
    pub scope: String,
    pub status: i64,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteVariableFilters {
    pub keyword: String,
    pub scope: String,
    pub status: Option<i64>,
    pub app_id: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteVariableInput {
    pub name: String,
    pub value: String,
    pub scope: String,
    pub status: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteApiTokenRow {
    pub id: u64,
    pub name: String,
    pub access_key: String,
    pub status: i64,
    pub expires_at: Option<NaiveDateTime>,
    pub ip_allowlist_json: String,
    pub last_used_at: Option<NaiveDateTime>,
    pub last_ip: String,
    pub created_by: String,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteApiTokenDetailRow {
    pub id: u64,
    pub name: String,
    pub access_key: String,
    pub secret_cipher: String,
    pub status: i64,
    pub expires_at: Option<NaiveDateTime>,
    pub ip_allowlist_json: String,
    pub last_used_at: Option<NaiveDateTime>,
    pub last_ip: String,
    pub created_by: String,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteApiTokenFilters {
    pub keyword: String,
    pub status: Option<i64>,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRemoteApiToken {
    pub name: String,
    pub access_key: String,
    pub secret_cipher: String,
    pub status: i64,
    pub expires_at: Option<NaiveDateTime>,
    pub ip_allowlist_json: String,
    pub created_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteApiLogRow {
    pub id: u64,
    pub token_id: Option<u64>,
    pub access_key: String,
    pub route: String,
    pub target_app_id: Option<u64>,
    pub request_hash: String,
    pub status: String,
    pub error_code: String,
    pub message: String,
    pub ip: String,
    pub created_at: Option<NaiveDateTime>,
    pub token_name: String,
    pub app_code: String,
    pub app_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteApiLogFilters {
    pub token_id: Option<u64>,
    pub target_app_id: Option<u64>,
    pub route: String,
    pub status: String,
    pub keyword: String,
    pub start: Option<NaiveDateTime>,
    pub end: Option<NaiveDateTime>,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteApiLogInput {
    pub token_id: Option<u64>,
    pub access_key: String,
    pub route: String,
    pub target_app_id: Option<u64>,
    pub request_hash: String,
    pub status: String,
    pub error_code: String,
    pub message: String,
    pub ip: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudStorageConfigRow {
    pub id: u64,
    pub provider: String,
    pub status: i64,
    pub is_default: i64,
    pub bucket: String,
    pub region: String,
    pub endpoint: String,
    pub access_key: String,
    pub secret_cipher: Option<String>,
    pub path_prefix: String,
    pub custom_domain: String,
    pub max_file_size: i64,
    pub allowed_extensions: String,
    pub signed_url_ttl_seconds: i64,
    pub last_test_status: String,
    pub last_test_message: String,
    pub last_test_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudStorageConfigInput {
    pub provider: String,
    pub status: i64,
    pub bucket: String,
    pub region: String,
    pub endpoint: String,
    pub access_key: String,
    pub secret_cipher: Option<String>,
    pub path_prefix: String,
    pub custom_domain: String,
    pub max_file_size: i64,
    pub allowed_extensions: String,
    pub signed_url_ttl_seconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudProviderCountRow {
    pub provider: String,
    pub file_count: i64,
    pub size_total: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudStorageSummary {
    pub file_total: i64,
    pub size_total: i64,
    pub providers: Vec<CloudProviderCountRow>,
    pub default_config: Option<CloudStorageConfigRow>,
    pub download_token: Option<CloudDownloadTokenRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudFileRow {
    pub id: u64,
    pub file_key: String,
    pub provider: String,
    pub config_id: Option<u64>,
    pub original_name: String,
    pub mime_type: String,
    pub extension: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub object_key: String,
    pub local_path: String,
    pub status: String,
    pub remark: String,
    pub download_count: i64,
    pub last_download_ip: String,
    pub last_download_at: Option<NaiveDateTime>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
    pub config_test_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudFileFilters {
    pub keyword: String,
    pub provider: String,
    pub status: String,
    pub start: String,
    pub end: String,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudDownloadTokenRow {
    pub token_hash: String,
    pub token_cipher: Option<String>,
    pub status: i64,
    pub last_used_ip: String,
    pub last_used_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudDownloadTokenInput {
    pub token_hash: String,
    pub token_cipher: String,
    pub status: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudUploadTicketInput {
    pub ticket_hash: String,
    pub admin_session_id: Option<u64>,
    pub provider: String,
    pub expected_sha256: String,
    pub expected_size: i64,
    pub original_name: String,
    pub mime_type: String,
    pub remark: String,
    pub status: String,
    pub expires_at: NaiveDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudUploadTicketRow {
    pub id: u64,
    pub admin_session_id: Option<u64>,
    pub provider: String,
    pub expected_sha256: String,
    pub expected_size: i64,
    pub original_name: String,
    pub mime_type: String,
    pub remark: String,
    pub status: String,
    pub expires_at: NaiveDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudFileInput {
    pub file_key: String,
    pub provider: String,
    pub config_id: u64,
    pub original_name: String,
    pub mime_type: String,
    pub extension: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub object_key: String,
    pub local_path: String,
    pub status: String,
    pub remark: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CardRow {
    pub id: u64,
    pub app_id: u64,
    pub card_hash: String,
    pub card_cipher: String,
    pub card_fingerprint: String,
    pub card_type: String,
    pub duration_seconds: i64,
    pub total_uses: i64,
    pub remaining_uses: i64,
    pub max_devices: i64,
    pub card_structure: String,
    pub prefix: String,
    pub unbind_limit: i64,
    pub unbind_count: i64,
    pub last_unbound_at: Option<NaiveDateTime>,
    pub status: i64,
    pub used_account_id: Option<u64>,
    pub used_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub online_count: i64,
    pub login_ips: String,
    pub device_count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRow {
    pub id: u64,
    pub app_id: u64,
    pub account_id: Option<u64>,
    pub card_id: Option<u64>,
    pub card_fingerprint: String,
    pub device_hash: String,
    pub install_id: String,
    pub machine_profile_hash: String,
    pub bind_ip: String,
    pub bind_region: String,
    pub device_name: String,
    pub status: i64,
    pub first_seen_at: NaiveDateTime,
    pub last_seen_at: NaiveDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRow {
    pub id: u64,
    pub app_id: u64,
    pub username: String,
    pub status: i64,
    pub expires_at: NaiveDateTime,
    pub max_devices: i64,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityPolicyRow {
    pub app_id: u64,
    pub enabled: i64,
    pub mode: String,
    pub min_confidence_for_client_action: i64,
    pub max_client_action: String,
    pub kick_score: i64,
    pub disable_device_score: i64,
    pub disable_card_score: i64,
    pub allowed_client_actions: String,
    pub client_disable_device_min_score: i64,
    pub client_disable_card_min_score: i64,
    pub report_rate_limit_per_minute: i64,
    pub report_retention_days: i64,
    pub message_retention_days: i64,
    pub server_critical_action: String,
    pub server_high_action: String,
    pub server_medium_action: String,
    pub server_low_action: String,
    pub trusted_event_types_json: String,
    pub updated_by: String,
    pub updated_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityPolicyInput {
    pub app_id: u64,
    pub enabled: i64,
    pub mode: String,
    pub min_confidence_for_client_action: i64,
    pub max_client_action: String,
    pub kick_score: i64,
    pub disable_device_score: i64,
    pub disable_card_score: i64,
    pub allowed_client_actions: String,
    pub client_disable_device_min_score: i64,
    pub client_disable_card_min_score: i64,
    pub report_rate_limit_per_minute: i64,
    pub report_retention_days: i64,
    pub message_retention_days: i64,
    pub server_critical_action: String,
    pub server_high_action: String,
    pub server_medium_action: String,
    pub server_low_action: String,
    pub trusted_event_types_json: String,
    pub updated_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSecurityReportRow {
    pub id: u64,
    pub requested_action: String,
    pub action: String,
    pub action_source: String,
    pub risk_score: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSecurityMessageRow {
    pub id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecurityReportCountFilters {
    pub session_id: Option<u64>,
    pub card_id: Option<u64>,
    pub card_hash: String,
    pub device_id: Option<u64>,
    pub ip: String,
    pub event_type: String,
    pub since: Option<NaiveDateTime>,
    pub risk_levels: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSecurityReportRecord {
    pub app_id: u64,
    pub session_id: u64,
    pub device_id: Option<u64>,
    pub card_id: Option<u64>,
    pub card_hash: String,
    pub card_fingerprint: String,
    pub install_id: String,
    pub event_id: String,
    pub event_type: String,
    pub risk_level: String,
    pub confidence: i64,
    pub requested_action: String,
    pub action: String,
    pub action_source: String,
    pub risk_score: i64,
    pub action_reason: String,
    pub title: String,
    pub message: String,
    pub evidence_json: String,
    pub attestation_json: String,
    pub sdk_version: String,
    pub detector_version: String,
    pub platform: String,
    pub ip: String,
    pub occurred_at: NaiveDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSecurityMessageRecord {
    pub app_id: u64,
    pub session_id: u64,
    pub device_id: Option<u64>,
    pub card_id: Option<u64>,
    pub severity: String,
    pub title: String,
    pub summary: String,
    pub action: String,
    pub action_source: String,
    pub risk_score: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSecurityActionRecord {
    pub app_id: u64,
    pub session_id: u64,
    pub device_id: Option<u64>,
    pub card_id: Option<u64>,
    pub card_hash: String,
    pub action: String,
    pub action_source: String,
    pub ip: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSecurityReportCommand {
    pub report: ClientSecurityReportRecord,
    pub message: ClientSecurityMessageRecord,
    pub action: ClientSecurityActionRecord,
    pub rotation: Option<ClientSessionRotation>,
    pub touch_device_id: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSecurityReportResult {
    pub report_id: u64,
    pub message_id: u64,
    pub session_revoked: bool,
    pub device_disabled: bool,
    pub card_disabled: bool,
    pub revoked_sessions: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardQuery {
    pub status: String,
    pub duration_category: String,
    pub keyword: String,
    pub card_hash: String,
    pub search_token_hashes: Vec<String>,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCard {
    pub app_id: u64,
    pub card_hash: String,
    pub card_cipher: String,
    pub card_fingerprint: String,
    pub card_type: String,
    pub duration_seconds: i64,
    pub total_uses: i64,
    pub remaining_uses: i64,
    pub max_devices: i64,
    pub card_structure: String,
    pub prefix: String,
    pub unbind_limit: i64,
    pub status: i64,
    pub search_token_hashes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityCleanup {
    pub deleted_security_reports: u64,
    pub deleted_messages: u64,
    pub deleted_message_actions: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditLogRow {
    pub id: u64,
    pub app_id: Option<u64>,
    pub account_id: Option<u64>,
    pub action: String,
    pub message: String,
    pub ip: String,
    pub region: String,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRow {
    pub id: u64,
    pub app_id: u64,
    pub report_id: Option<u64>,
    pub session_id: Option<u64>,
    pub device_id: Option<u64>,
    pub card_id: Option<u64>,
    pub message_type: String,
    pub severity: String,
    pub status: String,
    pub title: String,
    pub summary: String,
    pub action: String,
    pub action_source: String,
    pub risk_score: i64,
    pub handled_by: String,
    pub read_at: Option<NaiveDateTime>,
    pub handled_at: Option<NaiveDateTime>,
    pub archived_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub event_id: String,
    pub event_type: String,
    pub risk_level: String,
    pub confidence: i64,
    pub requested_action: String,
    pub action_reason: String,
    pub report_message: String,
    pub evidence_json: String,
    pub attestation_json: String,
    pub card_hash: String,
    pub card_fingerprint: String,
    pub install_id: String,
    pub sdk_version: String,
    pub detector_version: String,
    pub platform: String,
    pub ip: String,
    pub occurred_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageActionRow {
    pub id: u64,
    pub action: String,
    pub actor_type: String,
    pub actor_name: String,
    pub result: String,
    pub remark: String,
    pub ip: String,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageAuditRow {
    pub id: u64,
    pub action: String,
    pub message: String,
    pub ip: String,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageFilters {
    pub status: String,
    pub action: String,
    pub risk_level: String,
    pub event_type: String,
    pub card_fingerprint: String,
    pub install_id: String,
    pub ip: String,
    pub start: Option<NaiveDateTime>,
    pub end: Option<NaiveDateTime>,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageStatusUpdate {
    pub status: String,
    pub read_at: Option<NaiveDateTime>,
    pub handled_by: String,
    pub handled_at: Option<NaiveDateTime>,
    pub archived_at: Option<NaiveDateTime>,
    pub action: String,
    pub actor_name: String,
    pub remark: String,
    pub ip: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageAdminAction {
    pub action: String,
    pub actor_name: String,
    pub remark: String,
    pub ip: String,
    pub audit_message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageActionEffect {
    pub result: String,
    pub revoked_sessions: u64,
    pub device_disabled: bool,
    pub card_disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppActivityCleanup {
    pub deleted_message_actions: u64,
    pub deleted_messages: u64,
    pub deleted_security_reports: u64,
    pub deleted_audit_logs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overview {
    pub apps_total: i64,
    pub cards_total: i64,
    pub devices_total: i64,
    pub sessions_active: i64,
    pub card_status: CardStatusOverview,
    pub device_status: DeviceStatusOverview,
    pub single_code_ratio: SingleCodeRatio,
    pub login_ip_stats: LoginIpStats,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardStatusOverview {
    pub inactive: i64,
    pub active: i64,
    pub expired: i64,
    pub disabled: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceStatusOverview {
    pub enabled: i64,
    pub disabled: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleCodeRatio {
    pub total: i64,
    pub single_code: i64,
    pub multi_device: i64,
    pub single_percent_basis_points: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginIpStats {
    pub distinct_count: i64,
}

impl AuthRepository {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }

    pub async fn find_admin_by_username(
        &self,
        username: &str,
    ) -> Result<Option<AdminRow>, AppError> {
        let row = sqlx::query(
            "SELECT `username`, `password`, `created_at`, `updated_at`, \
             `remember_login_token_hash`, `remember_login_expires_at` \
             FROM `sub_admin` WHERE `username` = ?",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询后台管理员"))?;
        row.map(admin_row).transpose()
    }

    pub async fn create_admin_session(
        &self,
        session: &NewAdminSession<'_>,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO `auth_admin_sessions` \
             (`token_hash`, `key_cipher`, `ip`, `admin_username`, `expires_at`, `status`) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(session.token_hash)
        .bind(session.key_cipher)
        .bind(session.ip)
        .bind(session.admin_username)
        .bind(session.expires_at)
        .bind(session.status)
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("创建后台会话"))?;
        Ok(())
    }

    pub async fn find_admin_session_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<AdminSessionRow>, AppError> {
        let row = sqlx::query(ADMIN_SESSION_SELECT_BY_TOKEN_HASH)
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("查询后台会话"))?;
        row.map(admin_session_row).transpose()
    }

    pub async fn touch_admin_session(
        &self,
        session_id: u64,
        seen_at: NaiveDateTime,
    ) -> Result<(), AppError> {
        sqlx::query("UPDATE `auth_admin_sessions` SET `last_seen_at` = ? WHERE `id` = ?")
            .bind(seen_at)
            .bind(session_id)
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("更新后台会话活跃时间"))?;
        Ok(())
    }

    pub async fn reserve_admin_nonce(
        &self,
        session_id: u64,
        nonce_hash: &str,
        expires_at: NaiveDateTime,
    ) -> Result<bool, AppError> {
        let result = sqlx::query(
            "INSERT INTO `auth_admin_nonces` (`session_id`, `nonce_hash`, `expires_at`) \
             VALUES (?, ?, ?)",
        )
        .bind(session_id)
        .bind(nonce_hash)
        .bind(expires_at)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(true),
            Err(error) if is_duplicate_or_constraint_error(&error) => Ok(false),
            Err(_) => Err(AppError::DatabaseQueryFailed("登记后台请求随机串")),
        }
    }

    pub async fn get_site_settings(&self) -> Result<Option<SiteSettingsRow>, AppError> {
        let row = sqlx::query(
            "SELECT `hostname`, `site_subtitle`, `siteurl`, `logo_url`, `announcement`, \
             `contact`, `footer_text`, `custom_json` FROM `site_settings` WHERE `id` = 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询站点设置"))?;
        row.map(site_settings_row).transpose()
    }

    pub async fn find_remote_config(
        &self,
        app_id: u64,
    ) -> Result<Option<RemoteConfigRow>, AppError> {
        let row = sqlx::query(
            "SELECT `app_id`, `notice`, `config_json`, `variables_json`, `version`, \
             CAST(`force_update` AS SIGNED) AS `force_update`, `download_url`, \
             CAST(`status` AS SIGNED) AS `status` \
             FROM `auth_remote_configs` WHERE `app_id` = ? AND `status` = 1",
        )
        .bind(app_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询远程配置"))?;
        row.map(remote_config_row).transpose()
    }

    pub async fn upsert_remote_config(&self, config: &RemoteConfigUpsert) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO `auth_remote_configs` \
             (`app_id`, `notice`, `config_json`, `variables_json`, `version`, \
             `force_update`, `download_url`, `status`) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE `notice` = VALUES(`notice`), \
             `config_json` = VALUES(`config_json`), \
             `variables_json` = VALUES(`variables_json`), \
             `version` = VALUES(`version`), \
             `force_update` = VALUES(`force_update`), \
             `download_url` = VALUES(`download_url`), `status` = VALUES(`status`)",
        )
        .bind(config.app_id)
        .bind(&config.notice)
        .bind(&config.config_json)
        .bind(&config.variables_json)
        .bind(&config.version)
        .bind(config.force_update)
        .bind(&config.download_url)
        .bind(config.status)
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("保存远程配置"))?;
        Ok(())
    }

    pub async fn list_remote_variables(
        &self,
        filters: &RemoteVariableFilters,
    ) -> Result<Vec<RemoteVariableRow>, AppError> {
        let mut builder = QueryBuilder::<MySql>::new(
            "SELECT v.`id`, v.`name`, v.`value`, v.`scope`, CAST(v.`status` AS SIGNED) AS `status`, \
             v.`created_at`, v.`updated_at`, \
             COALESCE(GROUP_CONCAT(DISTINCT a.`id` ORDER BY a.`name`, a.`id` SEPARATOR ','), '') AS `app_ids_csv`, \
             COALESCE(GROUP_CONCAT(DISTINCT a.`name` ORDER BY a.`name`, a.`id` SEPARATOR '\n'), '') AS `app_names_csv`, \
             CAST(COUNT(DISTINCT va.`app_id`) AS SIGNED) AS `app_count` \
             FROM `auth_remote_variables` v \
             LEFT JOIN `auth_remote_variable_apps` va ON va.`variable_id` = v.`id` \
             LEFT JOIN `auth_apps` a ON a.`id` = va.`app_id` WHERE ",
        );
        push_remote_variable_filters(&mut builder, filters);
        builder.push(
            " GROUP BY v.`id`, v.`name`, v.`value`, v.`scope`, v.`status`, v.`created_at`, v.`updated_at` \
             ORDER BY v.`updated_at` DESC, v.`id` DESC",
        );
        let rows = builder
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("查询远程变量列表"))?;
        rows.into_iter().map(remote_variable_row).collect()
    }

    pub async fn find_remote_variable_by_id(
        &self,
        variable_id: u64,
    ) -> Result<Option<RemoteVariableDetailRow>, AppError> {
        let row = sqlx::query(
            "SELECT `id`, `name`, `value`, `scope`, CAST(`status` AS SIGNED) AS `status`, \
             `created_at`, `updated_at` FROM `auth_remote_variables` WHERE `id` = ?",
        )
        .bind(variable_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询远程变量"))?;
        row.map(remote_variable_detail_row).transpose()
    }

    pub async fn find_remote_variable_by_name(
        &self,
        name: &str,
    ) -> Result<Option<RemoteVariableDetailRow>, AppError> {
        let row = sqlx::query(
            "SELECT `id`, `name`, `value`, `scope`, CAST(`status` AS SIGNED) AS `status`, \
             `created_at`, `updated_at` FROM `auth_remote_variables` WHERE `name` = ?",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询远程变量名称"))?;
        row.map(remote_variable_detail_row).transpose()
    }

    pub async fn find_readable_remote_variable_value(
        &self,
        app_id: u64,
        name: &str,
    ) -> Result<Option<String>, AppError> {
        let row = sqlx::query(
            "SELECT v.`value` FROM `auth_remote_variables` v \
             WHERE v.`name` = ? AND v.`status` = 1 AND (v.`scope` = ? OR EXISTS (\
             SELECT 1 FROM `auth_remote_variable_apps` va \
             WHERE va.`variable_id` = v.`id` AND va.`app_id` = ?)) LIMIT 1",
        )
        .bind(name)
        .bind("public")
        .bind(app_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询客户端远程变量"))?;
        row.map(|row| row_get(&row, "value", "读取客户端远程变量值"))
            .transpose()
    }

    pub async fn count_apps_by_ids(&self, app_ids: &[u64]) -> Result<i64, AppError> {
        if app_ids.is_empty() {
            return Ok(0);
        }
        let mut builder = QueryBuilder::<MySql>::new(
            "SELECT CAST(COUNT(*) AS SIGNED) AS `count` FROM `auth_apps` WHERE `id` IN (",
        );
        push_id_bindings(&mut builder, app_ids);
        builder.push(")");
        let row = builder
            .build()
            .fetch_one(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("统计应用编号"))?;
        row_get(&row, "count", "读取应用编号数量")
    }

    pub async fn create_remote_variable(
        &self,
        variable: &RemoteVariableInput,
        app_ids: &[u64],
    ) -> Result<u64, AppError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("开启创建远程变量事务"))?;
        let variable_id = insert_remote_variable_in_transaction(&mut transaction, variable).await?;
        replace_remote_variable_apps_in_transaction(&mut transaction, variable_id, app_ids).await?;
        transaction
            .commit()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("提交创建远程变量事务"))?;
        Ok(variable_id)
    }

    pub async fn update_remote_variable(
        &self,
        variable_id: u64,
        variable: &RemoteVariableInput,
        app_ids: &[u64],
    ) -> Result<(), AppError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("开启更新远程变量事务"))?;
        update_remote_variable_in_transaction(&mut transaction, variable_id, variable).await?;
        replace_remote_variable_apps_in_transaction(&mut transaction, variable_id, app_ids).await?;
        transaction
            .commit()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("提交更新远程变量事务"))?;
        Ok(())
    }

    pub async fn update_remote_variable_status(
        &self,
        variable_id: u64,
        status: i64,
    ) -> Result<(), AppError> {
        sqlx::query("UPDATE `auth_remote_variables` SET `status` = ? WHERE `id` = ?")
            .bind(status)
            .bind(variable_id)
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("更新远程变量状态"))?;
        Ok(())
    }

    pub async fn update_remote_variables_status(
        &self,
        variable_ids: &[u64],
        status: i64,
    ) -> Result<u64, AppError> {
        let mut builder =
            QueryBuilder::<MySql>::new("UPDATE `auth_remote_variables` SET `status` = ");
        builder.push_bind(status).push(" WHERE `status` <> ");
        builder.push_bind(status).push(" AND `id` IN (");
        push_id_bindings(&mut builder, variable_ids);
        builder.push(")");
        let result = builder
            .build()
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("批量更新远程变量状态"))?;
        Ok(result.rows_affected())
    }

    pub async fn delete_remote_variable(&self, variable_id: u64) -> Result<(), AppError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("开启删除远程变量事务"))?;
        sqlx::query("DELETE FROM `auth_remote_variable_apps` WHERE `variable_id` = ?")
            .bind(variable_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("删除远程变量授权应用"))?;
        sqlx::query("DELETE FROM `auth_remote_variables` WHERE `id` = ?")
            .bind(variable_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("删除远程变量"))?;
        transaction
            .commit()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("提交删除远程变量事务"))?;
        Ok(())
    }

    pub async fn delete_remote_variables(&self, variable_ids: &[u64]) -> Result<u64, AppError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("开启批量删除远程变量事务"))?;
        delete_remote_variable_apps_in_transaction(&mut transaction, variable_ids).await?;
        let mut builder =
            QueryBuilder::<MySql>::new("DELETE FROM `auth_remote_variables` WHERE `id` IN (");
        push_id_bindings(&mut builder, variable_ids);
        builder.push(")");
        let result = builder
            .build()
            .execute(&mut *transaction)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("批量删除远程变量"))?;
        transaction
            .commit()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("提交批量删除远程变量事务"))?;
        Ok(result.rows_affected())
    }

    pub async fn replace_remote_variable_apps(
        &self,
        variable_id: u64,
        app_ids: &[u64],
    ) -> Result<(), AppError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("开启保存远程变量授权应用事务"))?;
        replace_remote_variable_apps_in_transaction(&mut transaction, variable_id, app_ids).await?;
        transaction
            .commit()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("提交保存远程变量授权应用事务"))?;
        Ok(())
    }

    pub async fn list_remote_api_tokens(
        &self,
        filters: &RemoteApiTokenFilters,
    ) -> Result<Vec<RemoteApiTokenRow>, AppError> {
        let mut builder = QueryBuilder::<MySql>::new(
            "SELECT `id`, `name`, `access_key`, CAST(`status` AS SIGNED) AS `status`, \
             `expires_at`, COALESCE(`ip_allowlist_json`, '[]') AS `ip_allowlist_json`, \
             `last_used_at`, `last_ip`, `created_by`, `created_at`, `updated_at` \
             FROM `auth_remote_api_tokens` WHERE ",
        );
        push_remote_api_token_filters(&mut builder, filters);
        builder.push(" ORDER BY `id` DESC LIMIT ");
        builder.push_bind(filters.limit.clamp(1, 100));
        builder.push(" OFFSET ");
        builder.push_bind(filters.offset.max(0));
        let rows = builder
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("查询远程 API Token 列表"))?;
        rows.into_iter().map(remote_api_token_row).collect()
    }

    pub async fn find_remote_api_token_by_id(
        &self,
        token_id: u64,
    ) -> Result<Option<RemoteApiTokenDetailRow>, AppError> {
        let row = sqlx::query(
            "SELECT `id`, `name`, `access_key`, `secret_cipher`, \
             CAST(`status` AS SIGNED) AS `status`, `expires_at`, \
             COALESCE(`ip_allowlist_json`, '[]') AS `ip_allowlist_json`, \
             `last_used_at`, `last_ip`, `created_by`, `created_at`, `updated_at` \
             FROM `auth_remote_api_tokens` WHERE `id` = ?",
        )
        .bind(token_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询远程 API Token"))?;
        row.map(remote_api_token_detail_row).transpose()
    }

    pub async fn find_remote_api_token_by_access_key(
        &self,
        access_key: &str,
    ) -> Result<Option<RemoteApiTokenDetailRow>, AppError> {
        let row = sqlx::query(
            "SELECT `id`, `name`, `access_key`, `secret_cipher`, \
             CAST(`status` AS SIGNED) AS `status`, `expires_at`, \
             COALESCE(`ip_allowlist_json`, '[]') AS `ip_allowlist_json`, \
             `last_used_at`, `last_ip`, `created_by`, `created_at`, `updated_at` \
             FROM `auth_remote_api_tokens` WHERE `access_key` = ?",
        )
        .bind(access_key)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询远程 API accessKey"))?;
        row.map(remote_api_token_detail_row).transpose()
    }

    pub async fn create_remote_api_token(
        &self,
        token: &NewRemoteApiToken,
    ) -> Result<u64, AppError> {
        let result = sqlx::query(
            "INSERT INTO `auth_remote_api_tokens` \
             (`name`, `access_key`, `secret_cipher`, `status`, `expires_at`, \
             `ip_allowlist_json`, `created_by`) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&token.name)
        .bind(&token.access_key)
        .bind(&token.secret_cipher)
        .bind(token.status)
        .bind(token.expires_at)
        .bind(&token.ip_allowlist_json)
        .bind(&token.created_by)
        .execute(&self.pool)
        .await;
        match result {
            Ok(result) => Ok(result.last_insert_id()),
            Err(error) if is_duplicate_or_constraint_error(&error) => {
                Err(AppError::RemoteApiAccessKeyExists)
            }
            Err(_) => Err(AppError::DatabaseQueryFailed("写入远程 API Token")),
        }
    }

    pub async fn update_remote_api_token_status(
        &self,
        token_id: u64,
        status: i64,
    ) -> Result<(), AppError> {
        sqlx::query("UPDATE `auth_remote_api_tokens` SET `status` = ? WHERE `id` = ?")
            .bind(status)
            .bind(token_id)
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("更新远程 API Token 状态"))?;
        Ok(())
    }

    pub async fn delete_remote_api_token(&self, token_id: u64) -> Result<(), AppError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("开启删除远程 API Token 事务"))?;
        sqlx::query("DELETE FROM `auth_remote_api_nonces` WHERE `token_id` = ?")
            .bind(token_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("删除远程 API Token 随机串"))?;
        sqlx::query("DELETE FROM `auth_remote_api_tokens` WHERE `id` = ?")
            .bind(token_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("删除远程 API Token"))?;
        transaction
            .commit()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("提交删除远程 API Token 事务"))?;
        Ok(())
    }

    pub async fn list_remote_api_logs(
        &self,
        filters: &RemoteApiLogFilters,
    ) -> Result<Vec<RemoteApiLogRow>, AppError> {
        let mut builder = QueryBuilder::<MySql>::new(
            "SELECT l.`id`, l.`token_id`, l.`access_key`, l.`route`, l.`target_app_id`, \
             l.`request_hash`, l.`status`, l.`error_code`, l.`message`, l.`ip`, l.`created_at`, \
             COALESCE(t.`name`, '') AS `token_name`, COALESCE(a.`app_code`, '') AS `app_code`, \
             COALESCE(a.`name`, '') AS `app_name` FROM `auth_remote_api_logs` l \
             LEFT JOIN `auth_remote_api_tokens` t ON t.`id` = l.`token_id` \
             LEFT JOIN `auth_apps` a ON a.`id` = l.`target_app_id` WHERE ",
        );
        push_remote_api_log_filters(&mut builder, filters);
        builder.push(" ORDER BY l.`id` DESC LIMIT ");
        builder.push_bind(filters.limit.clamp(1, 100));
        builder.push(" OFFSET ");
        builder.push_bind(filters.offset.max(0));
        let rows = builder
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("查询远程 API 调用日志"))?;
        rows.into_iter().map(remote_api_log_row).collect()
    }

    pub async fn delete_remote_api_logs(&self, log_ids: &[u64]) -> Result<u64, AppError> {
        if log_ids.is_empty() {
            return Ok(0);
        }
        let mut builder =
            QueryBuilder::<MySql>::new("DELETE FROM `auth_remote_api_logs` WHERE `id` IN (");
        push_id_bindings(&mut builder, log_ids);
        builder.push(")");
        let result = builder
            .build()
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("删除远程 API 调用日志"))?;
        Ok(result.rows_affected())
    }

    pub async fn clear_remote_api_logs(&self) -> Result<u64, AppError> {
        let result = sqlx::query("DELETE FROM `auth_remote_api_logs`")
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("清空远程 API 调用日志"))?;
        Ok(result.rows_affected())
    }

    pub async fn reserve_remote_api_nonce(
        &self,
        token_id: u64,
        nonce_hash: &str,
        expires_at: NaiveDateTime,
    ) -> Result<bool, AppError> {
        let result = sqlx::query(
            "INSERT IGNORE INTO `auth_remote_api_nonces` \
             (`token_id`, `nonce_hash`, `expires_at`) VALUES (?, ?, ?)",
        )
        .bind(token_id)
        .bind(nonce_hash)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("预留远程 API 随机串"))?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn touch_remote_api_token(
        &self,
        token_id: u64,
        ip: &str,
        used_at: NaiveDateTime,
    ) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE `auth_remote_api_tokens` SET `last_used_at` = ?, `last_ip` = ? WHERE `id` = ?",
        )
        .bind(used_at)
        .bind(clip_text(ip, 45))
        .bind(token_id)
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("更新远程 API Token 调用时间"))?;
        Ok(())
    }

    pub async fn write_remote_api_log(&self, log: &RemoteApiLogInput) -> Result<u64, AppError> {
        let result = sqlx::query(
            "INSERT INTO `auth_remote_api_logs` \
             (`token_id`, `access_key`, `route`, `target_app_id`, `request_hash`, \
             `status`, `error_code`, `message`, `ip`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(log.token_id)
        .bind(clip_text(&log.access_key, 64))
        .bind(clip_text(&log.route, 120))
        .bind(log.target_app_id)
        .bind(clip_text(&log.request_hash, 64))
        .bind(clip_text(&log.status, 16))
        .bind(clip_text(&log.error_code, 64))
        .bind(clip_text(&log.message, 255))
        .bind(clip_text(&log.ip, 45))
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("写入远程 API 调用日志"))?;
        Ok(result.last_insert_id())
    }

    pub async fn cloud_storage_summary(&self) -> Result<CloudStorageSummary, AppError> {
        let total_row = sqlx::query(
            "SELECT CAST(COUNT(*) AS SIGNED) AS `file_total`, \
             CAST(COALESCE(SUM(`size_bytes`), 0) AS SIGNED) AS `size_total` \
             FROM `auth_cloud_files` WHERE `status` = 'active'",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("统计云存储文件"))?;
        let provider_rows = sqlx::query(
            "SELECT `provider`, CAST(COUNT(*) AS SIGNED) AS `file_count`, \
             CAST(COALESCE(SUM(`size_bytes`), 0) AS SIGNED) AS `size_total` \
             FROM `auth_cloud_files` WHERE `status` = 'active' GROUP BY `provider`",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("统计云存储来源"))?;
        Ok(CloudStorageSummary {
            file_total: row_get(&total_row, "file_total", "读取云存储文件总数")?,
            size_total: row_get(&total_row, "size_total", "读取云存储文件总大小")?,
            providers: provider_rows
                .into_iter()
                .map(cloud_provider_count_row)
                .collect::<Result<Vec<_>, _>>()?,
            default_config: self.find_default_cloud_storage_config().await?,
            download_token: self.find_cloud_download_token().await?,
        })
    }

    pub async fn list_cloud_storage_configs(&self) -> Result<Vec<CloudStorageConfigRow>, AppError> {
        let sql = format!(
            "SELECT {CLOUD_STORAGE_CONFIG_SELECT_COLUMNS} FROM `auth_cloud_storage_configs` \
             ORDER BY CASE `provider` WHEN 'local' THEN 1 WHEN 'aliyun_oss' THEN 2 \
             WHEN 'tencent_cos' THEN 3 ELSE 4 END, `id` ASC"
        );
        let rows = sqlx::query(&sql)
            .fetch_all(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("查询云存储配置"))?;
        rows.into_iter().map(cloud_storage_config_row).collect()
    }

    pub async fn find_cloud_storage_config_by_provider(
        &self,
        provider: &str,
    ) -> Result<Option<CloudStorageConfigRow>, AppError> {
        let sql = format!(
            "SELECT {CLOUD_STORAGE_CONFIG_SELECT_COLUMNS} FROM `auth_cloud_storage_configs` \
             WHERE `provider` = ?"
        );
        let row = sqlx::query(&sql)
            .bind(provider)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("查询云存储来源配置"))?;
        row.map(cloud_storage_config_row).transpose()
    }

    pub async fn find_cloud_storage_config_by_id(
        &self,
        config_id: u64,
    ) -> Result<Option<CloudStorageConfigRow>, AppError> {
        let sql = format!(
            "SELECT {CLOUD_STORAGE_CONFIG_SELECT_COLUMNS} FROM `auth_cloud_storage_configs` \
             WHERE `id` = ?"
        );
        let row = sqlx::query(&sql)
            .bind(config_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("查询云存储配置编号"))?;
        row.map(cloud_storage_config_row).transpose()
    }

    pub async fn find_default_cloud_storage_config(
        &self,
    ) -> Result<Option<CloudStorageConfigRow>, AppError> {
        let sql = format!(
            "SELECT {CLOUD_STORAGE_CONFIG_SELECT_COLUMNS} FROM `auth_cloud_storage_configs` \
             WHERE `is_default` = 1 ORDER BY `id` ASC LIMIT 1"
        );
        let row = sqlx::query(&sql)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("查询默认云存储配置"))?;
        row.map(cloud_storage_config_row).transpose()
    }

    pub async fn upsert_cloud_storage_config(
        &self,
        config: &CloudStorageConfigInput,
    ) -> Result<u64, AppError> {
        sqlx::query(
            "INSERT INTO `auth_cloud_storage_configs` \
             (`provider`, `status`, `bucket`, `region`, `endpoint`, `access_key`, \
             `secret_cipher`, `path_prefix`, `custom_domain`, `max_file_size`, \
             `allowed_extensions`, `signed_url_ttl_seconds`) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE `status` = VALUES(`status`), \
             `bucket` = VALUES(`bucket`), `region` = VALUES(`region`), \
             `endpoint` = VALUES(`endpoint`), `access_key` = VALUES(`access_key`), \
             `secret_cipher` = VALUES(`secret_cipher`), \
             `path_prefix` = VALUES(`path_prefix`), \
             `custom_domain` = VALUES(`custom_domain`), \
             `max_file_size` = VALUES(`max_file_size`), \
             `allowed_extensions` = VALUES(`allowed_extensions`), \
             `signed_url_ttl_seconds` = VALUES(`signed_url_ttl_seconds`)",
        )
        .bind(&config.provider)
        .bind(config.status)
        .bind(&config.bucket)
        .bind(&config.region)
        .bind(&config.endpoint)
        .bind(&config.access_key)
        .bind(&config.secret_cipher)
        .bind(&config.path_prefix)
        .bind(&config.custom_domain)
        .bind(config.max_file_size)
        .bind(&config.allowed_extensions)
        .bind(config.signed_url_ttl_seconds)
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("保存云存储配置"))?;
        let stored = self
            .find_cloud_storage_config_by_provider(&config.provider)
            .await?
            .ok_or(AppError::DatabaseQueryFailed("读取已保存云存储配置"))?;
        Ok(stored.id)
    }

    pub async fn set_default_cloud_storage_config(&self, config_id: u64) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE `auth_cloud_storage_configs` SET `is_default` = CASE WHEN `id` = ? THEN 1 ELSE 0 END",
        )
        .bind(config_id)
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("设置默认云存储配置"))?;
        Ok(())
    }

    pub async fn update_cloud_storage_test_result(
        &self,
        config_id: u64,
        status: &str,
        message: &str,
        tested_at: Option<NaiveDateTime>,
    ) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE `auth_cloud_storage_configs` SET `last_test_status` = ?, \
             `last_test_message` = ?, `last_test_at` = ? WHERE `id` = ?",
        )
        .bind(status)
        .bind(message)
        .bind(tested_at)
        .bind(config_id)
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("保存云存储测试结果"))?;
        Ok(())
    }

    pub async fn list_cloud_files(
        &self,
        filters: &CloudFileFilters,
    ) -> Result<Vec<CloudFileRow>, AppError> {
        let mut builder = QueryBuilder::<MySql>::new(format!(
            "SELECT {CLOUD_FILE_SELECT_COLUMNS}, COALESCE(c.`last_test_status`, '') AS `config_test_status` \
             FROM `auth_cloud_files` f \
             LEFT JOIN `auth_cloud_storage_configs` c ON c.`id` = f.`config_id` WHERE "
        ));
        push_cloud_file_filters(&mut builder, filters);
        builder.push(" ORDER BY f.`id` DESC LIMIT ");
        builder.push_bind(filters.limit.clamp(1, 100));
        builder.push(" OFFSET ");
        builder.push_bind(filters.offset.max(0));
        let rows = builder
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("查询云存储文件"))?;
        rows.into_iter().map(cloud_file_row).collect()
    }

    pub async fn find_cloud_file_by_id(
        &self,
        file_id: u64,
    ) -> Result<Option<CloudFileRow>, AppError> {
        let query = format!(
            "SELECT {CLOUD_FILE_SELECT_COLUMNS}, '' AS `config_test_status` \
             FROM `auth_cloud_files` f WHERE f.`id` = ?"
        );
        let row = sqlx::query(&query)
            .bind(file_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("查询云存储文件"))?;
        row.map(cloud_file_row).transpose()
    }

    pub async fn find_cloud_file_by_key(
        &self,
        file_key: &str,
    ) -> Result<Option<CloudFileRow>, AppError> {
        let query = format!(
            "SELECT {CLOUD_FILE_SELECT_COLUMNS}, '' AS `config_test_status` \
             FROM `auth_cloud_files` f WHERE f.`file_key` = ?"
        );
        let row = sqlx::query(&query)
            .bind(file_key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("查询云存储文件 Key"))?;
        row.map(cloud_file_row).transpose()
    }

    pub async fn mark_cloud_file_deleted(&self, file_id: u64) -> Result<(), AppError> {
        sqlx::query("UPDATE `auth_cloud_files` SET `status` = 'deleted' WHERE `id` = ?")
            .bind(file_id)
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("标记云存储文件删除"))?;
        Ok(())
    }

    pub async fn touch_cloud_file_download(
        &self,
        file_id: u64,
        ip: &str,
        downloaded_at: NaiveDateTime,
    ) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE `auth_cloud_files` SET `download_count` = `download_count` + 1, \
             `last_download_ip` = ?, `last_download_at` = ? WHERE `id` = ?",
        )
        .bind(ip)
        .bind(downloaded_at)
        .bind(file_id)
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("记录云存储文件下载"))?;
        Ok(())
    }

    pub async fn find_cloud_download_token(
        &self,
    ) -> Result<Option<CloudDownloadTokenRow>, AppError> {
        let row = sqlx::query(
            "SELECT `token_hash`, `token_cipher`, CAST(`status` AS SIGNED) AS `status`, \
             `last_used_ip`, `last_used_at` FROM `auth_cloud_download_token` WHERE `id` = 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询云存储下载 Token"))?;
        row.map(cloud_download_token_row).transpose()
    }

    pub async fn upsert_cloud_download_token(
        &self,
        token: &CloudDownloadTokenInput,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO `auth_cloud_download_token` (`id`, `token_hash`, `token_cipher`, `status`) \
             VALUES (1, ?, ?, ?) ON DUPLICATE KEY UPDATE \
             `token_hash` = VALUES(`token_hash`), `token_cipher` = VALUES(`token_cipher`), \
             `status` = VALUES(`status`)",
        )
        .bind(&token.token_hash)
        .bind(&token.token_cipher)
        .bind(token.status)
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("保存云存储下载 Token"))?;
        Ok(())
    }

    pub async fn update_cloud_download_token_status(&self, status: i64) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO `auth_cloud_download_token` (`id`, `status`) VALUES (1, ?) \
             ON DUPLICATE KEY UPDATE `status` = VALUES(`status`)",
        )
        .bind(status)
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("更新云存储下载 Token 状态"))?;
        Ok(())
    }

    pub async fn touch_cloud_download_token(
        &self,
        ip: &str,
        used_at: NaiveDateTime,
    ) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE `auth_cloud_download_token` SET `last_used_ip` = ?, `last_used_at` = ? \
             WHERE `id` = 1",
        )
        .bind(ip)
        .bind(used_at)
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("记录云存储下载 Token 使用"))?;
        Ok(())
    }

    pub async fn create_cloud_upload_ticket(
        &self,
        ticket: &CloudUploadTicketInput,
    ) -> Result<u64, AppError> {
        let result = sqlx::query(
            "INSERT INTO `auth_cloud_upload_tickets` \
             (`ticket_hash`, `admin_session_id`, `provider`, `expected_sha256`, \
             `expected_size`, `original_name`, `mime_type`, `remark`, `status`, `expires_at`) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&ticket.ticket_hash)
        .bind(ticket.admin_session_id)
        .bind(&ticket.provider)
        .bind(&ticket.expected_sha256)
        .bind(ticket.expected_size)
        .bind(&ticket.original_name)
        .bind(&ticket.mime_type)
        .bind(&ticket.remark)
        .bind(&ticket.status)
        .bind(ticket.expires_at)
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("创建云存储上传票据"))?;
        Ok(result.last_insert_id())
    }

    pub async fn find_cloud_upload_ticket_by_hash(
        &self,
        ticket_hash: &str,
    ) -> Result<Option<CloudUploadTicketRow>, AppError> {
        let row = sqlx::query(
            "SELECT `id`, `admin_session_id`, `provider`, `expected_sha256`, \
             CAST(`expected_size` AS SIGNED) AS `expected_size`, `original_name`, \
             `mime_type`, `remark`, `status`, `expires_at` \
             FROM `auth_cloud_upload_tickets` WHERE `ticket_hash` = ?",
        )
        .bind(ticket_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询云存储上传票据"))?;
        row.map(cloud_upload_ticket_row).transpose()
    }

    pub async fn mark_cloud_upload_ticket_used(
        &self,
        ticket_id: u64,
        used_at: NaiveDateTime,
    ) -> Result<bool, AppError> {
        let result = sqlx::query(
            "UPDATE `auth_cloud_upload_tickets` SET `status` = 'used', `used_at` = ? \
             WHERE `id` = ? AND `status` = 'pending'",
        )
        .bind(used_at)
        .bind(ticket_id)
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("消费云存储上传票据"))?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn create_cloud_file(&self, file: &CloudFileInput) -> Result<u64, AppError> {
        let result = sqlx::query(
            "INSERT INTO `auth_cloud_files` \
             (`file_key`, `provider`, `config_id`, `original_name`, `mime_type`, \
             `extension`, `size_bytes`, `sha256`, `object_key`, `local_path`, `status`, `remark`) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&file.file_key)
        .bind(&file.provider)
        .bind(file.config_id)
        .bind(&file.original_name)
        .bind(&file.mime_type)
        .bind(&file.extension)
        .bind(file.size_bytes)
        .bind(&file.sha256)
        .bind(&file.object_key)
        .bind(&file.local_path)
        .bind(&file.status)
        .bind(&file.remark)
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("写入云存储文件"))?;
        Ok(result.last_insert_id())
    }

    pub async fn update_admin_cookie(
        &self,
        username: &str,
        cookie_value: &str,
    ) -> Result<(), AppError> {
        sqlx::query("UPDATE `sub_admin` SET `cookies` = ? WHERE `username` = ?")
            .bind(cookie_value)
            .bind(username)
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("更新后台登录 Cookie"))?;
        Ok(())
    }

    pub async fn set_admin_remember_login(
        &self,
        username: &str,
        token_hash: &str,
        expires_at: NaiveDateTime,
    ) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE `sub_admin` SET `remember_login_token_hash` = ?, \
             `remember_login_expires_at` = ? WHERE `username` = ?",
        )
        .bind(token_hash)
        .bind(expires_at)
        .bind(username)
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("写入后台记住登录"))?;
        Ok(())
    }

    pub async fn clear_admin_remember_login(&self, username: &str) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE `sub_admin` SET `remember_login_token_hash` = '', \
             `remember_login_expires_at` = NULL WHERE `username` = ?",
        )
        .bind(username)
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("清除后台记住登录"))?;
        Ok(())
    }

    pub async fn update_admin_credentials_and_revoke_sessions(
        &self,
        current_username: &str,
        update: &AdminCredentialsUpdate,
    ) -> Result<(), AppError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("开启管理员资料更新事务"))?;
        sqlx::query(
            "UPDATE `sub_admin` SET `username` = ?, `password` = ?, `cookies` = '', \
             `remember_login_token_hash` = '', `remember_login_expires_at` = NULL \
             WHERE `username` = ?",
        )
        .bind(&update.username)
        .bind(&update.password)
        .bind(current_username)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("更新管理员资料"))?;
        sqlx::query(
            "UPDATE `auth_admin_sessions` SET `status` = 0 \
             WHERE `admin_username` = ? AND `status` = 1",
        )
        .bind(current_username)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("撤销后台会话"))?;
        transaction
            .commit()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("提交管理员资料更新事务"))?;
        Ok(())
    }

    pub async fn save_site_settings(&self, settings: &SiteSettingsUpdate) -> Result<(), AppError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("开启保存站点设置事务"))?;
        sqlx::query(
            "INSERT INTO `site_settings` \
             (`id`, `hostname`, `site_subtitle`, `siteurl`, `logo_url`, `announcement`, \
             `contact`, `footer_text`, `custom_json`) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE `hostname` = VALUES(`hostname`), \
             `site_subtitle` = VALUES(`site_subtitle`), `siteurl` = VALUES(`siteurl`), \
             `logo_url` = VALUES(`logo_url`), `announcement` = VALUES(`announcement`), \
             `contact` = VALUES(`contact`), `footer_text` = VALUES(`footer_text`), \
             `custom_json` = VALUES(`custom_json`)",
        )
        .bind(&settings.hostname)
        .bind(&settings.site_subtitle)
        .bind(&settings.siteurl)
        .bind(&settings.logo_url)
        .bind(&settings.announcement)
        .bind(&settings.contact)
        .bind(&settings.footer_text)
        .bind(Json(settings.custom_json.clone()))
        .execute(&mut *transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("保存站点设置"))?;
        sqlx::query(
            "UPDATE `sub_admin` SET `hostname` = ?, `siteurl` = ? ORDER BY `id` ASC LIMIT 1",
        )
        .bind(&settings.hostname)
        .bind(&settings.siteurl)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("同步旧后台站点设置"))?;
        transaction
            .commit()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("提交保存站点设置事务"))?;
        Ok(())
    }

    pub async fn write_log(
        &self,
        operation: &str,
        message: &str,
        operator: &str,
        ip: &str,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO `log` (`operation`, `msg`, `operationer`, `ip`) VALUES (?, ?, ?, ?)",
        )
        .bind(clip_text(operation, 255))
        .bind(clip_text(message, 255))
        .bind(clip_text(operator, 255))
        .bind(clip_text(ip, 45))
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("写入操作日志"))?;
        Ok(())
    }

    pub async fn list_apps(&self, limit: i64, offset: i64) -> Result<Vec<AppRow>, AppError> {
        let rows = sqlx::query(
            "SELECT \
             a.`id`, a.`app_code`, a.`api_token`, a.`name`, CAST(a.`status` AS SIGNED) AS `status`, \
             CAST(a.`max_devices` AS SIGNED) AS `max_devices`, CAST(a.`heartbeat_interval` AS SIGNED) AS `heartbeat_interval`, CAST(a.`heartbeat_enabled` AS SIGNED) AS `heartbeat_enabled`, \
             CAST(a.`verification_enabled` AS SIGNED) AS `verification_enabled`, CAST(a.`device_binding_enabled` AS SIGNED) AS `device_binding_enabled`, CAST(a.`shared_cards_enabled` AS SIGNED) AS `shared_cards_enabled`, \
             CAST(a.`login_ip_binding_enabled` AS SIGNED) AS `login_ip_binding_enabled`, CAST(a.`web_card_query_enabled` AS SIGNED) AS `web_card_query_enabled`, \
             CAST(a.`unbind_interval_seconds` AS SIGNED) AS `unbind_interval_seconds`, CAST(a.`unbind_deduct_seconds` AS SIGNED) AS `unbind_deduct_seconds`, CAST(a.`unbind_deduct_uses` AS SIGNED) AS `unbind_deduct_uses`, \
             CAST(a.`api_success_code` AS SIGNED) AS `api_success_code`, a.`api_config_json`, a.`latest_version`, \
             a.`client_auth_mode`, a.`client_crypto_alg`, a.`remark`, \
             a.`created_at`, a.`updated_at`, \
             CAST((SELECT COUNT(*) FROM `auth_cards` c WHERE c.`app_id` = a.`id`) AS SIGNED) AS `cards_total`, \
             CAST((SELECT COUNT(*) FROM `auth_devices` d WHERE d.`app_id` = a.`id`) AS SIGNED) AS `devices_total`, \
             CAST((SELECT COUNT(*) FROM `auth_sessions` s WHERE s.`app_id` = a.`id` \
                AND s.`status` = 1 AND s.`expires_at` >= NOW() \
                AND COALESCE(s.`last_heartbeat_at`, s.`created_at`) >= DATE_SUB(NOW(), INTERVAL 300 SECOND)) AS SIGNED) AS `sessions_active` \
             FROM ( \
               SELECT `id`, `app_code`, `api_token`, `name`, `status`, \
                 `max_devices`, `heartbeat_interval`, `heartbeat_enabled`, \
                 `verification_enabled`, `device_binding_enabled`, `shared_cards_enabled`, \
                 `login_ip_binding_enabled`, `web_card_query_enabled`, \
                 `unbind_interval_seconds`, `unbind_deduct_seconds`, `unbind_deduct_uses`, \
                 `api_success_code`, `api_config_json`, `latest_version`, \
                 `client_auth_mode`, `client_crypto_alg`, `remark`, \
                 `created_at`, `updated_at` \
               FROM `auth_apps` ORDER BY `id` DESC LIMIT ? OFFSET ? \
             ) a",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询应用列表"))?;
        rows.into_iter().map(app_row).collect()
    }

    pub async fn find_app_id_by_code(&self, app_code: &str) -> Result<Option<u64>, AppError> {
        let row = sqlx::query("SELECT `id` FROM `auth_apps` WHERE `app_code` = ?")
            .bind(app_code)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("查询应用编号"))?;
        row.map(|row| row_get(&row, "id", "读取应用编号"))
            .transpose()
    }

    pub async fn find_app_by_id(&self, app_id: u64) -> Result<Option<AppDetailRow>, AppError> {
        let row = sqlx::query(APP_DETAIL_SQL_BY_ID)
            .bind(app_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("查询应用详情"))?;
        row.map(app_detail_row).transpose()
    }

    pub async fn find_app_by_code(&self, app_code: &str) -> Result<Option<AppDetailRow>, AppError> {
        let row = sqlx::query(APP_DETAIL_SQL_BY_CODE)
            .bind(app_code)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("查询应用详情"))?;
        row.map(app_detail_row).transpose()
    }

    pub async fn create_app(&self, app: &NewApp) -> Result<u64, AppError> {
        let result = sqlx::query(
            "INSERT INTO `auth_apps` \
             (`app_code`, `api_token`, `name`, `status`, `max_devices`, `heartbeat_interval`, \
             `heartbeat_enabled`, `verification_enabled`, `device_binding_enabled`, \
             `shared_cards_enabled`, `login_ip_binding_enabled`, `web_card_query_enabled`, \
             `unbind_interval_seconds`, `unbind_deduct_seconds`, `unbind_deduct_uses`, \
             `api_success_code`, `api_config_json`, `latest_version`, `client_auth_mode`, \
             `client_crypto_alg`, `client_public_key`, `client_private_key_cipher`, `remark`) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&app.app_code)
        .bind(&app.api_token)
        .bind(&app.name)
        .bind(app.status)
        .bind(app.max_devices)
        .bind(app.heartbeat_interval)
        .bind(app.heartbeat_enabled)
        .bind(app.verification_enabled)
        .bind(app.device_binding_enabled)
        .bind(app.shared_cards_enabled)
        .bind(app.login_ip_binding_enabled)
        .bind(app.web_card_query_enabled)
        .bind(app.unbind_interval_seconds)
        .bind(app.unbind_deduct_seconds)
        .bind(app.unbind_deduct_uses)
        .bind(app.api_success_code)
        .bind(&app.api_config_json)
        .bind(&app.latest_version)
        .bind(&app.client_auth_mode)
        .bind(&app.client_crypto_alg)
        .bind(&app.client_public_key)
        .bind(&app.client_private_key_cipher)
        .bind(&app.remark)
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("创建应用"))?;
        Ok(result.last_insert_id())
    }

    pub async fn update_app(&self, app_id: u64, app: &AppSettingsUpdate) -> Result<(), AppError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("开启应用更新事务"))?;
        sqlx::query(
            "UPDATE `auth_apps` SET `name` = ?, `max_devices` = ?, `heartbeat_interval` = ?, \
             `heartbeat_enabled` = ?, `verification_enabled` = ?, `device_binding_enabled` = ?, \
             `shared_cards_enabled` = ?, `login_ip_binding_enabled` = ?, `latest_version` = ?, \
             `client_auth_mode` = ?, `client_crypto_alg` = ?, `remark` = ? WHERE `id` = ?",
        )
        .bind(&app.name)
        .bind(app.max_devices)
        .bind(app.heartbeat_interval)
        .bind(app.heartbeat_enabled)
        .bind(app.verification_enabled)
        .bind(app.device_binding_enabled)
        .bind(app.shared_cards_enabled)
        .bind(app.login_ip_binding_enabled)
        .bind(&app.latest_version)
        .bind(&app.client_auth_mode)
        .bind(&app.client_crypto_alg)
        .bind(&app.remark)
        .bind(app_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("更新应用设置"))?;
        if app.login_ip_binding_enabled == 0 {
            clear_app_device_bind_ips_in_transaction(&mut transaction, app_id).await?;
        }
        transaction
            .commit()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("提交应用更新事务"))?;
        Ok(())
    }

    pub async fn update_app_api_config(
        &self,
        app_id: u64,
        config: &AppApiUpdate,
    ) -> Result<(), AppError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("开启应用接口配置事务"))?;
        sqlx::query(
            "UPDATE `auth_apps` SET `api_token` = ?, `login_ip_binding_enabled` = ?, \
             `web_card_query_enabled` = ?, `unbind_interval_seconds` = ?, \
             `unbind_deduct_seconds` = ?, `unbind_deduct_uses` = ?, \
             `api_success_code` = ?, `api_config_json` = ? WHERE `id` = ?",
        )
        .bind(&config.api_token)
        .bind(config.login_ip_binding_enabled)
        .bind(config.web_card_query_enabled)
        .bind(config.unbind_interval_seconds)
        .bind(config.unbind_deduct_seconds)
        .bind(config.unbind_deduct_uses)
        .bind(config.api_success_code)
        .bind(&config.api_config_json)
        .bind(app_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("更新应用接口配置"))?;
        if config.login_ip_binding_enabled == 0 {
            clear_app_device_bind_ips_in_transaction(&mut transaction, app_id).await?;
        }
        transaction
            .commit()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("提交应用接口配置事务"))?;
        Ok(())
    }

    pub async fn update_app_client_crypto(
        &self,
        app_id: u64,
        update: &AppClientCryptoUpdate,
    ) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE `auth_apps` SET `client_crypto_alg` = ?, `client_public_key` = ?, \
             `client_private_key_cipher` = ? WHERE `id` = ?",
        )
        .bind(&update.client_crypto_alg)
        .bind(&update.client_public_key)
        .bind(&update.client_private_key_cipher)
        .bind(app_id)
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("更新客户端密钥对"))?;
        Ok(())
    }

    pub async fn update_app_status(&self, app_id: u64, status: i64) -> Result<(), AppError> {
        sqlx::query("UPDATE `auth_apps` SET `status` = ? WHERE `id` = ?")
            .bind(status)
            .bind(app_id)
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("更新应用状态"))?;
        Ok(())
    }

    pub async fn update_apps_status(&self, app_ids: &[u64], status: i64) -> Result<u64, AppError> {
        let mut builder = QueryBuilder::<MySql>::new("UPDATE `auth_apps` SET `status` = ");
        builder.push_bind(status).push(" WHERE `id` IN (");
        push_id_bindings(&mut builder, app_ids);
        builder.push(")");
        let result = builder
            .build()
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("批量更新应用状态"))?;
        Ok(result.rows_affected())
    }

    pub async fn delete_apps(&self, app_ids: &[u64]) -> Result<u64, AppError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("开启删除应用事务"))?;
        for table_name in APP_DEPENDENT_TABLES {
            delete_app_rows_in_transaction(&mut transaction, table_name, app_ids).await?;
        }
        let mut builder = QueryBuilder::<MySql>::new("DELETE FROM `auth_apps` WHERE `id` IN (");
        push_id_bindings(&mut builder, app_ids);
        builder.push(")");
        let result = builder
            .build()
            .execute(&mut *transaction)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("删除应用"))?;
        transaction
            .commit()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("提交删除应用事务"))?;
        Ok(result.rows_affected())
    }

    pub async fn count_cards(&self, app_id: u64, query: &CardQuery) -> Result<i64, AppError> {
        let mut builder = QueryBuilder::<MySql>::new(
            "SELECT CAST(COUNT(*) AS SIGNED) AS `total` FROM `auth_cards` c WHERE ",
        );
        push_card_filters(&mut builder, app_id, query);
        let row = builder
            .build()
            .fetch_one(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("统计卡密数量"))?;
        row_get(&row, "total", "读取卡密数量")
    }

    pub async fn list_cards(
        &self,
        app_id: u64,
        heartbeat_enabled: bool,
        query: &CardQuery,
    ) -> Result<Vec<CardRow>, AppError> {
        let mut builder = QueryBuilder::<MySql>::new(CARD_LIST_SELECT_PREFIX);
        if heartbeat_enabled {
            builder.push(CARD_ONLINE_COUNT_SQL);
            builder.push(" AS `online_count`, ");
            builder.push(CARD_LOGIN_IPS_SQL);
            builder.push(" AS `login_ips`, ");
        } else {
            builder.push("CAST(0 AS SIGNED) AS `online_count`, '' AS `login_ips`, ");
        }
        builder.push(CARD_DEVICE_COUNT_SQL);
        builder.push(" AS `device_count` FROM `auth_cards` c WHERE ");
        push_card_filters(&mut builder, app_id, query);
        builder.push(" ORDER BY c.`id` DESC LIMIT ");
        builder.push_bind(query.limit);
        builder.push(" OFFSET ");
        builder.push_bind(query.offset);
        let rows = builder
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("查询卡密列表"))?;
        rows.into_iter().map(card_row).collect()
    }

    pub async fn list_cards_for_export(
        &self,
        app_id: u64,
        query: &CardQuery,
    ) -> Result<Vec<CardRow>, AppError> {
        self.list_cards(app_id, false, query).await
    }

    pub async fn list_cards_by_ids_for_export(
        &self,
        app_id: u64,
        card_ids: &[u64],
    ) -> Result<Vec<CardRow>, AppError> {
        let mut builder = QueryBuilder::<MySql>::new(CARD_LIST_SELECT_PREFIX);
        builder
            .push("CAST(0 AS SIGNED) AS `online_count`, '' AS `login_ips`, ")
            .push(CARD_DEVICE_COUNT_SQL)
            .push(" AS `device_count` FROM `auth_cards` c WHERE c.`app_id` = ")
            .push_bind(app_id)
            .push(" AND c.`id` IN (");
        push_id_bindings(&mut builder, card_ids);
        builder.push(") ORDER BY c.`id` DESC");
        let rows = builder
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("查询导出卡密"))?;
        rows.into_iter().map(card_row).collect()
    }

    pub async fn find_card_by_id(&self, card_id: u64) -> Result<Option<CardRow>, AppError> {
        let row = sqlx::query(CARD_BY_ID_SQL)
            .bind(card_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("查询卡密详情"))?;
        row.map(card_row).transpose()
    }

    pub async fn find_card_by_hash(
        &self,
        app_id: u64,
        card_hash: &str,
    ) -> Result<Option<CardRow>, AppError> {
        let row = sqlx::query(CARD_BY_HASH_SQL)
            .bind(app_id)
            .bind(card_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("查询卡密哈希"))?;
        row.map(card_row).transpose()
    }

    pub async fn create_plain_ephemeral_login(
        &self,
        command: ClientLoginCommand,
    ) -> Result<ClientLoginResult, AppError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("开启客户端登录事务"))?;
        reserve_client_login_challenge(&mut transaction, &command).await?;
        let mut card = resolve_client_login_card(&mut transaction, &command).await?;
        if is_client_count_card(&card) {
            consume_client_count_card_use(&mut transaction, &mut card).await?;
        }
        let device_identity = if is_client_count_card(&card) {
            None
        } else {
            Some(upsert_client_login_device(&mut transaction, &command, &card).await?)
        };
        let device_id = device_identity.map(|identity| identity.id);
        assert_client_login_session_allowed(&mut transaction, &command, &card, device_id).await?;
        let session_expires_at = client_session_expires_at(&command, &card);
        if let Some(identity) = device_identity {
            if !identity.created {
                revoke_client_device_card_sessions(
                    &mut transaction,
                    command.app_id,
                    identity.id,
                    card.id,
                    &card.card_hash,
                )
                .await?;
            }
        }
        let session_id = create_client_login_session(
            &mut transaction,
            &command,
            &card,
            device_id,
            session_expires_at,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("提交客户端登录事务"))?;
        Ok(ClientLoginResult {
            card,
            device_id,
            session_id,
            session_expires_at,
        })
    }

    pub async fn find_client_session_by_token_hash(
        &self,
        app_id: u64,
        token_hash: &str,
    ) -> Result<Option<ClientSessionRow>, AppError> {
        let row = sqlx::query(CLIENT_SESSION_BY_TOKEN_HASH_SQL)
            .bind(app_id)
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("查询客户端会话"))?;
        row.map(client_session_row).transpose()
    }

    pub async fn rotate_client_session(
        &self,
        rotation: &ClientSessionRotation,
    ) -> Result<bool, AppError> {
        let result = sqlx::query(
            "UPDATE `auth_sessions` SET `token_hash` = ?, `request_counter` = ?, \
             `last_heartbeat_at` = ?, `expires_at` = ?, `ticket_hash` = ?, `ticket_expires_at` = ? \
             WHERE `id` = ? AND `token_hash` = ? AND `status` = 1 AND `request_counter` < ?",
        )
        .bind(&rotation.next_token_hash)
        .bind(rotation.request_counter)
        .bind(rotation.heartbeat_at)
        .bind(rotation.expires_at)
        .bind(&rotation.ticket_hash)
        .bind(rotation.ticket_expires_at)
        .bind(rotation.session_id)
        .bind(&rotation.current_token_hash)
        .bind(rotation.request_counter)
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("更新客户端会话令牌"))?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn revoke_client_session(&self, session_id: u64) -> Result<(), AppError> {
        sqlx::query("UPDATE `auth_sessions` SET `status` = 0 WHERE `id` = ?")
            .bind(session_id)
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("撤销客户端会话"))?;
        Ok(())
    }

    pub async fn touch_client_device(
        &self,
        device_id: u64,
        seen_at: NaiveDateTime,
    ) -> Result<(), AppError> {
        sqlx::query("UPDATE `auth_devices` SET `last_seen_at` = ? WHERE `id` = ?")
            .bind(seen_at)
            .bind(device_id)
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("更新客户端设备活跃时间"))?;
        Ok(())
    }

    pub async fn create_cards(&self, cards: &[NewCard]) -> Result<(), AppError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("开启创建卡密事务"))?;
        for card in cards {
            let card_id = insert_card_in_transaction(&mut transaction, card).await?;
            replace_card_search_tokens_in_transaction(
                &mut transaction,
                card.app_id,
                card_id,
                &card.search_token_hashes,
            )
            .await?;
        }
        transaction
            .commit()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("提交创建卡密事务"))?;
        Ok(())
    }

    pub async fn update_card_status(&self, card_id: u64, status: i64) -> Result<(), AppError> {
        sqlx::query("UPDATE `auth_cards` SET `status` = ? WHERE `id` = ?")
            .bind(status)
            .bind(card_id)
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("更新卡密状态"))?;
        Ok(())
    }

    pub async fn update_card_duration(
        &self,
        card_id: u64,
        duration_seconds: i64,
    ) -> Result<(), AppError> {
        sqlx::query("UPDATE `auth_cards` SET `duration_seconds` = ? WHERE `id` = ?")
            .bind(duration_seconds)
            .bind(card_id)
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("更新卡密时长"))?;
        Ok(())
    }

    pub async fn update_card_durations(
        &self,
        card_durations: &[(u64, i64)],
    ) -> Result<u64, AppError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("开启批量更新卡密时长事务"))?;
        let mut updated = 0_u64;
        for (card_id, duration_seconds) in card_durations {
            let result =
                sqlx::query("UPDATE `auth_cards` SET `duration_seconds` = ? WHERE `id` = ?")
                    .bind(duration_seconds)
                    .bind(card_id)
                    .execute(&mut *transaction)
                    .await
                    .map_err(|_| AppError::DatabaseQueryFailed("批量更新卡密时长"))?;
            updated += result.rows_affected();
        }
        transaction
            .commit()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("提交批量更新卡密时长事务"))?;
        Ok(updated)
    }

    pub async fn reset_time_card_duration(
        &self,
        card: &CardRow,
        duration_seconds: i64,
    ) -> Result<u64, AppError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("开启重置时长卡事务"))?;
        sqlx::query(
            "UPDATE `auth_cards` SET `status` = 0, `used_account_id` = NULL, \
             `used_at` = NULL, `duration_seconds` = ? WHERE `id` = ? AND `card_type` = 'time'",
        )
        .bind(duration_seconds)
        .bind(card.id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("重置时长卡"))?;
        let revoked_sessions = revoke_card_sessions_in_transaction(
            &mut transaction,
            card.app_id,
            card.id,
            &card.card_hash,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("提交重置时长卡事务"))?;
        Ok(revoked_sessions)
    }

    pub async fn update_cards_status(
        &self,
        app_id: u64,
        card_ids: &[u64],
        status: i64,
    ) -> Result<u64, AppError> {
        let mut builder = QueryBuilder::<MySql>::new("UPDATE `auth_cards` SET `status` = ");
        builder
            .push_bind(status)
            .push(" WHERE `app_id` = ")
            .push_bind(app_id)
            .push(" AND `id` IN (");
        push_id_bindings(&mut builder, card_ids);
        builder.push(")");
        let result = builder
            .build()
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("批量更新卡密状态"))?;
        Ok(result.rows_affected())
    }

    pub async fn count_cards_by_activated_range(
        &self,
        app_id: u64,
        activated_start: NaiveDateTime,
        activated_end: NaiveDateTime,
        card_type: &str,
    ) -> Result<i64, AppError> {
        let mut builder = QueryBuilder::<MySql>::new(
            "SELECT CAST(COUNT(*) AS SIGNED) AS `total` FROM `auth_cards` WHERE ",
        );
        push_activated_range_filter(
            &mut builder,
            app_id,
            activated_start,
            activated_end,
            card_type,
        );
        let row = builder
            .build()
            .fetch_one(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("统计激活范围卡密"))?;
        row_get(&row, "total", "读取激活范围卡密数量")
    }

    pub async fn update_cards_status_by_activated_range(
        &self,
        app_id: u64,
        activated_start: NaiveDateTime,
        activated_end: NaiveDateTime,
        status: i64,
    ) -> Result<u64, AppError> {
        let mut builder = QueryBuilder::<MySql>::new("UPDATE `auth_cards` SET `status` = ");
        builder.push_bind(status).push(" WHERE ");
        push_activated_range_filter(&mut builder, app_id, activated_start, activated_end, "");
        builder.push(CARD_STATUS_CHANGED_FILTER).push_bind(status);
        let result = builder
            .build()
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("按激活范围更新卡密状态"))?;
        Ok(result.rows_affected())
    }

    pub async fn reset_time_cards_duration_by_activated_range(
        &self,
        app_id: u64,
        activated_start: NaiveDateTime,
        activated_end: NaiveDateTime,
        duration_seconds: i64,
    ) -> Result<u64, AppError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("开启激活范围重置时长卡事务"))?;
        revoke_time_card_sessions_by_activated_range_in_transaction(
            &mut transaction,
            app_id,
            activated_start,
            activated_end,
        )
        .await?;
        let result = sqlx::query(
            "UPDATE `auth_cards` SET `status` = 0, `used_account_id` = NULL, \
             `used_at` = NULL, `duration_seconds` = ? WHERE `app_id` = ? \
             AND `used_at` IS NOT NULL AND `used_at` >= ? AND `used_at` <= ? \
             AND `card_type` = 'time'",
        )
        .bind(duration_seconds)
        .bind(app_id)
        .bind(activated_start)
        .bind(activated_end)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("按激活范围重置时长卡"))?;
        transaction
            .commit()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("提交激活范围重置时长卡事务"))?;
        Ok(result.rows_affected())
    }

    pub async fn adjust_time_cards_duration_by_activated_range(
        &self,
        app_id: u64,
        activated_start: NaiveDateTime,
        activated_end: NaiveDateTime,
        duration_delta: i64,
        direction: &str,
    ) -> Result<u64, AppError> {
        let mut builder =
            QueryBuilder::<MySql>::new("UPDATE `auth_cards` SET `duration_seconds` = ");
        if direction == "reduce" {
            builder.push("CASE WHEN `duration_seconds` <= ");
            builder.push_bind(duration_delta);
            builder.push(" THEN ");
            builder.push_bind(MIN_CARD_DURATION_SECONDS);
            builder.push(" ELSE GREATEST(");
            builder.push_bind(MIN_CARD_DURATION_SECONDS);
            builder.push(", `duration_seconds` - ");
            builder.push_bind(duration_delta).push(") END");
        } else {
            builder.push("LEAST(");
            builder.push_bind(MAX_CARD_DURATION_SECONDS);
            builder.push(", `duration_seconds` + ");
            builder.push_bind(duration_delta).push(")");
        }
        builder.push(" WHERE ");
        push_activated_range_filter(&mut builder, app_id, activated_start, activated_end, "time");
        if direction == "reduce" {
            builder
                .push(REDUCE_TIME_CARD_DURATION_CHANGED_FILTER)
                .push_bind(MIN_CARD_DURATION_SECONDS);
        } else {
            builder
                .push(ADD_TIME_CARD_DURATION_CHANGED_FILTER)
                .push_bind(MAX_CARD_DURATION_SECONDS);
        }
        let result = builder
            .build()
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("按激活范围调整时长卡"))?;
        Ok(result.rows_affected())
    }

    pub async fn reset_count_cards_uses_by_activated_range(
        &self,
        app_id: u64,
        activated_start: NaiveDateTime,
        activated_end: NaiveDateTime,
    ) -> Result<u64, AppError> {
        let mut builder = QueryBuilder::<MySql>::new(
            "UPDATE `auth_cards` SET `remaining_uses` = `total_uses` WHERE ",
        );
        push_activated_range_filter(
            &mut builder,
            app_id,
            activated_start,
            activated_end,
            "count",
        );
        builder.push(RESET_COUNT_CARD_USES_CHANGED_FILTER);
        let result = builder
            .build()
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("按激活范围重置次数卡"))?;
        Ok(result.rows_affected())
    }

    pub async fn delete_cards_by_activated_range(
        &self,
        app_id: u64,
        activated_start: NaiveDateTime,
        activated_end: NaiveDateTime,
    ) -> Result<u64, AppError> {
        let mut builder = QueryBuilder::<MySql>::new("DELETE FROM `auth_cards` WHERE ");
        push_activated_range_filter(&mut builder, app_id, activated_start, activated_end, "");
        let result = builder
            .build()
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("按激活范围删除卡密"))?;
        Ok(result.rows_affected())
    }

    pub async fn delete_cards(&self, app_id: u64, card_ids: &[u64]) -> Result<u64, AppError> {
        let mut builder = QueryBuilder::<MySql>::new("DELETE FROM `auth_cards` WHERE `app_id` = ");
        builder.push_bind(app_id).push(" AND `id` IN (");
        push_id_bindings(&mut builder, card_ids);
        builder.push(")");
        let result = builder
            .build()
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("删除卡密"))?;
        Ok(result.rows_affected())
    }

    pub async fn reset_count_card_uses(&self, card_id: u64) -> Result<u64, AppError> {
        let result = sqlx::query(
            "UPDATE `auth_cards` SET `remaining_uses` = `total_uses` \
             WHERE `id` = ? AND `card_type` = 'count' AND `remaining_uses` <> `total_uses`",
        )
        .bind(card_id)
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("重置次数卡"))?;
        Ok(result.rows_affected())
    }

    pub async fn reset_count_cards_uses(
        &self,
        app_id: u64,
        card_ids: &[u64],
    ) -> Result<u64, AppError> {
        let mut builder = QueryBuilder::<MySql>::new(
            "UPDATE `auth_cards` SET `remaining_uses` = `total_uses` WHERE `app_id` = ",
        );
        builder
            .push_bind(app_id)
            .push(" AND `card_type` = 'count'")
            .push(RESET_COUNT_CARD_USES_CHANGED_FILTER)
            .push(" AND `id` IN (");
        push_id_bindings(&mut builder, card_ids);
        builder.push(")");
        let result = builder
            .build()
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("批量重置次数卡"))?;
        Ok(result.rows_affected())
    }

    pub async fn list_card_devices(
        &self,
        app_id: u64,
        card_id: u64,
    ) -> Result<Vec<DeviceRow>, AppError> {
        let rows = sqlx::query(
            "SELECT DISTINCT d.`id`, d.`app_id`, d.`account_id`, d.`card_id`, \
             c.`card_fingerprint`, d.`device_hash`, d.`install_id`, d.`machine_profile_hash`, \
             d.`bind_ip`, d.`bind_region`, d.`device_name`, CAST(d.`status` AS SIGNED) AS `status`, \
             d.`first_seen_at`, d.`last_seen_at` FROM `auth_cards` c \
             JOIN `auth_devices` d ON d.`app_id` = c.`app_id` \
             AND (d.`card_id` = c.`id` OR d.`card_hash` = c.`card_hash`) \
             WHERE c.`app_id` = ? AND c.`id` = ? ORDER BY d.`id` DESC",
        )
        .bind(app_id)
        .bind(card_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询卡密设备"))?;
        rows.into_iter().map(device_row).collect()
    }

    pub async fn list_accounts(
        &self,
        app_id: u64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AccountRow>, AppError> {
        let rows = sqlx::query(
            "SELECT `id`, `app_id`, `username`, CAST(`status` AS SIGNED) AS `status`, \
             `expires_at`, CAST(`max_devices` AS SIGNED) AS `max_devices`, `created_at`, \
             `updated_at` FROM `auth_accounts` WHERE `app_id` = ? ORDER BY `id` DESC \
             LIMIT ? OFFSET ?",
        )
        .bind(app_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询账号列表"))?;
        rows.into_iter().map(account_row).collect()
    }

    pub async fn find_account_by_id(
        &self,
        account_id: u64,
    ) -> Result<Option<AccountRow>, AppError> {
        let row = sqlx::query(
            "SELECT `id`, `app_id`, `username`, CAST(`status` AS SIGNED) AS `status`, \
             `expires_at`, CAST(`max_devices` AS SIGNED) AS `max_devices`, `created_at`, \
             `updated_at` FROM `auth_accounts` WHERE `id` = ?",
        )
        .bind(account_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询账号详情"))?;
        row.map(account_row).transpose()
    }

    pub async fn update_account_status(
        &self,
        account_id: u64,
        status: i64,
    ) -> Result<u64, AppError> {
        let result = sqlx::query("UPDATE `auth_accounts` SET `status` = ? WHERE `id` = ?")
            .bind(status)
            .bind(account_id)
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("更新账号状态"))?;
        Ok(result.rows_affected())
    }

    pub async fn update_account_expiry(
        &self,
        account_id: u64,
        expires_at: NaiveDateTime,
    ) -> Result<u64, AppError> {
        let result = sqlx::query("UPDATE `auth_accounts` SET `expires_at` = ? WHERE `id` = ?")
            .bind(expires_at)
            .bind(account_id)
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("更新账号到期时间"))?;
        Ok(result.rows_affected())
    }

    pub async fn list_devices(
        &self,
        app_id: u64,
        account_id: u64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DeviceRow>, AppError> {
        let rows = sqlx::query(
            "SELECT d.`id`, d.`app_id`, d.`account_id`, d.`card_id`, \
             COALESCE(c.`card_fingerprint`, IF(d.`card_hash` = '', '', CONCAT(LEFT(d.`card_hash`, 8), '...', RIGHT(d.`card_hash`, 6)))) AS `card_fingerprint`, \
             d.`device_hash`, d.`install_id`, d.`machine_profile_hash`, d.`bind_ip`, d.`bind_region`, \
             d.`device_name`, CAST(d.`status` AS SIGNED) AS `status`, d.`first_seen_at`, d.`last_seen_at` \
             FROM `auth_devices` d LEFT JOIN `auth_cards` c ON c.`id` = d.`card_id` \
             WHERE d.`app_id` = ? AND (d.`account_id` = ? OR ? = 0) ORDER BY d.`id` DESC \
             LIMIT ? OFFSET ?",
        )
        .bind(app_id)
        .bind(account_id)
        .bind(account_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询设备列表"))?;
        rows.into_iter().map(device_row).collect()
    }

    pub async fn find_device_by_id(&self, device_id: u64) -> Result<Option<DeviceRow>, AppError> {
        let row = sqlx::query(
            "SELECT d.`id`, d.`app_id`, d.`account_id`, d.`card_id`, \
             COALESCE(c.`card_fingerprint`, IF(d.`card_hash` = '', '', CONCAT(LEFT(d.`card_hash`, 8), '...', RIGHT(d.`card_hash`, 6)))) AS `card_fingerprint`, \
             d.`device_hash`, d.`install_id`, d.`machine_profile_hash`, d.`bind_ip`, d.`bind_region`, \
             d.`device_name`, CAST(d.`status` AS SIGNED) AS `status`, d.`first_seen_at`, d.`last_seen_at` \
             FROM `auth_devices` d LEFT JOIN `auth_cards` c ON c.`id` = d.`card_id` WHERE d.`id` = ?",
        )
        .bind(device_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询设备详情"))?;
        row.map(device_row).transpose()
    }

    pub async fn update_device_status(&self, device_id: u64, status: i64) -> Result<u64, AppError> {
        let result = sqlx::query("UPDATE `auth_devices` SET `status` = ? WHERE `id` = ?")
            .bind(status)
            .bind(device_id)
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("更新设备状态"))?;
        Ok(result.rows_affected())
    }

    pub async fn find_security_policy(
        &self,
        app_id: u64,
    ) -> Result<Option<SecurityPolicyRow>, AppError> {
        let row = sqlx::query(
            "SELECT `app_id`, CAST(`enabled` AS SIGNED) AS `enabled`, `mode`, \
             CAST(`min_confidence_for_client_action` AS SIGNED) AS `min_confidence_for_client_action`, \
             `max_client_action`, CAST(`kick_score` AS SIGNED) AS `kick_score`, \
             CAST(`disable_device_score` AS SIGNED) AS `disable_device_score`, \
             CAST(`disable_card_score` AS SIGNED) AS `disable_card_score`, \
             `allowed_client_actions`, \
             CAST(`client_disable_device_min_score` AS SIGNED) AS `client_disable_device_min_score`, \
             CAST(`client_disable_card_min_score` AS SIGNED) AS `client_disable_card_min_score`, \
             CAST(`report_rate_limit_per_minute` AS SIGNED) AS `report_rate_limit_per_minute`, \
             CAST(`report_retention_days` AS SIGNED) AS `report_retention_days`, \
             CAST(`message_retention_days` AS SIGNED) AS `message_retention_days`, \
             `server_critical_action`, `server_high_action`, `server_medium_action`, `server_low_action`, \
             `trusted_event_types_json`, `updated_by`, `updated_at` \
             FROM `auth_security_policies` WHERE `app_id` = ?",
        )
        .bind(app_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询安全策略"))?;
        row.map(security_policy_row).transpose()
    }

    pub async fn upsert_security_policy(
        &self,
        policy: &SecurityPolicyInput,
    ) -> Result<u64, AppError> {
        let result = sqlx::query(
            "INSERT INTO `auth_security_policies` \
             (`app_id`, `enabled`, `mode`, `min_confidence_for_client_action`, \
              `max_client_action`, `kick_score`, `disable_device_score`, `disable_card_score`, \
              `allowed_client_actions`, `client_disable_device_min_score`, \
              `client_disable_card_min_score`, `report_rate_limit_per_minute`, \
              `report_retention_days`, `message_retention_days`, `server_critical_action`, \
              `server_high_action`, `server_medium_action`, `server_low_action`, \
              `trusted_event_types_json`, `updated_by`) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE \
              `enabled` = VALUES(`enabled`), \
              `mode` = VALUES(`mode`), \
              `min_confidence_for_client_action` = VALUES(`min_confidence_for_client_action`), \
              `max_client_action` = VALUES(`max_client_action`), \
              `kick_score` = VALUES(`kick_score`), \
              `disable_device_score` = VALUES(`disable_device_score`), \
              `disable_card_score` = VALUES(`disable_card_score`), \
              `allowed_client_actions` = VALUES(`allowed_client_actions`), \
              `client_disable_device_min_score` = VALUES(`client_disable_device_min_score`), \
              `client_disable_card_min_score` = VALUES(`client_disable_card_min_score`), \
              `report_rate_limit_per_minute` = VALUES(`report_rate_limit_per_minute`), \
              `report_retention_days` = VALUES(`report_retention_days`), \
              `message_retention_days` = VALUES(`message_retention_days`), \
              `server_critical_action` = VALUES(`server_critical_action`), \
              `server_high_action` = VALUES(`server_high_action`), \
              `server_medium_action` = VALUES(`server_medium_action`), \
              `server_low_action` = VALUES(`server_low_action`), \
              `trusted_event_types_json` = VALUES(`trusted_event_types_json`), \
              `updated_by` = VALUES(`updated_by`)",
        )
        .bind(policy.app_id)
        .bind(policy.enabled)
        .bind(&policy.mode)
        .bind(policy.min_confidence_for_client_action)
        .bind(&policy.max_client_action)
        .bind(policy.kick_score)
        .bind(policy.disable_device_score)
        .bind(policy.disable_card_score)
        .bind(&policy.allowed_client_actions)
        .bind(policy.client_disable_device_min_score)
        .bind(policy.client_disable_card_min_score)
        .bind(policy.report_rate_limit_per_minute)
        .bind(policy.report_retention_days)
        .bind(policy.message_retention_days)
        .bind(&policy.server_critical_action)
        .bind(&policy.server_high_action)
        .bind(&policy.server_medium_action)
        .bind(&policy.server_low_action)
        .bind(&policy.trusted_event_types_json)
        .bind(&policy.updated_by)
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("保存安全策略"))?;
        Ok(result.rows_affected())
    }

    pub async fn find_security_report_by_event(
        &self,
        app_id: u64,
        session_id: u64,
        event_id: &str,
    ) -> Result<Option<ClientSecurityReportRow>, AppError> {
        let row = sqlx::query(
            "SELECT `id`, `requested_action`, `action`, `action_source`, \
             CAST(`risk_score` AS SIGNED) AS `risk_score` \
             FROM `auth_security_reports` WHERE `app_id` = ? AND `session_id` = ? AND `event_id` = ?",
        )
        .bind(app_id)
        .bind(session_id)
        .bind(event_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询客户端安全上报"))?;
        row.map(client_security_report_row).transpose()
    }

    pub async fn find_message_by_report(
        &self,
        app_id: u64,
        report_id: u64,
    ) -> Result<Option<ClientSecurityMessageRow>, AppError> {
        let row = sqlx::query(
            "SELECT `id` FROM `auth_messages` WHERE `app_id` = ? AND `report_id` = ? \
             ORDER BY `id` ASC LIMIT 1",
        )
        .bind(app_id)
        .bind(report_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询安全上报消息"))?;
        row.map(client_security_message_row).transpose()
    }

    pub async fn count_security_reports(
        &self,
        app_id: u64,
        filters: &SecurityReportCountFilters,
    ) -> Result<i64, AppError> {
        let mut builder = QueryBuilder::<MySql>::new(
            "SELECT CAST(COUNT(*) AS SIGNED) AS `count` FROM `auth_security_reports` WHERE `app_id` = ",
        );
        builder.push_bind(app_id);
        push_security_report_count_filters(&mut builder, filters);
        let row = builder
            .build()
            .fetch_one(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("统计安全上报"))?;
        row_get(&row, "count", "读取安全上报数量")
    }

    pub async fn count_distinct_security_report_cards(
        &self,
        app_id: u64,
        ip: &str,
        since: NaiveDateTime,
        risk_levels: &[String],
    ) -> Result<i64, AppError> {
        if risk_levels.is_empty() {
            return Ok(0);
        }
        let mut builder = QueryBuilder::<MySql>::new(
            "SELECT CAST(COUNT(DISTINCT COALESCE(NULLIF(`card_hash`, ''), CAST(`card_id` AS CHAR))) AS SIGNED) AS `count` \
             FROM `auth_security_reports` WHERE `app_id` = ",
        );
        builder
            .push_bind(app_id)
            .push(" AND `ip` = ")
            .push_bind(ip.to_string())
            .push(" AND `created_at` >= ")
            .push_bind(since)
            .push(" AND `risk_level` IN (");
        push_string_bindings(&mut builder, risk_levels);
        builder.push(")");
        let row = builder
            .build()
            .fetch_one(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("统计安全上报卡密"))?;
        row_get(&row, "count", "读取安全上报卡密数量")
    }

    pub async fn create_client_security_report(
        &self,
        command: &ClientSecurityReportCommand,
    ) -> Result<ClientSecurityReportResult, AppError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("开启安全上报事务"))?;
        let report_id =
            create_client_security_report_in_transaction(&mut transaction, &command.report).await?;
        let message_id = create_client_security_message_in_transaction(
            &mut transaction,
            report_id,
            &command.message,
        )
        .await?;
        let action_result = apply_client_security_action_in_transaction(
            &mut transaction,
            &command.action,
            message_id,
        )
        .await?;
        if !action_result.session_revoked {
            if let Some(rotation) = &command.rotation {
                let rotated =
                    rotate_client_session_in_transaction(&mut transaction, rotation).await?;
                if !rotated {
                    return Err(AppError::SessionInvalid("会话已被更新，请使用最新令牌"));
                }
                if let Some(device_id) = command.touch_device_id {
                    touch_client_device_in_transaction(
                        &mut transaction,
                        device_id,
                        rotation.heartbeat_at,
                    )
                    .await?;
                }
            }
        }
        transaction
            .commit()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("提交安全上报事务"))?;
        Ok(ClientSecurityReportResult {
            report_id,
            message_id,
            session_revoked: action_result.session_revoked,
            device_disabled: action_result.device_disabled,
            card_disabled: action_result.card_disabled,
            revoked_sessions: action_result.revoked_sessions,
        })
    }

    pub async fn delete_device(&self, device_id: u64) -> Result<u64, AppError> {
        let result = sqlx::query("DELETE FROM `auth_devices` WHERE `id` = ?")
            .bind(device_id)
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("删除设备绑定"))?;
        Ok(result.rows_affected())
    }

    pub async fn find_client_unbind_device(
        &self,
        app_id: u64,
        install_id: &str,
    ) -> Result<Option<ClientUnbindDeviceRow>, AppError> {
        let row = sqlx::query(
            "SELECT `id`, COALESCE(`device_public_key`, '') AS `device_public_key` \
             FROM `auth_devices` WHERE `app_id` = ? AND `install_id` = ?",
        )
        .bind(app_id)
        .bind(install_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询客户端解绑设备"))?;
        row.map(client_unbind_device_row).transpose()
    }

    pub async fn unbind_client_device(
        &self,
        command: &ClientUnbindCommand,
    ) -> Result<bool, AppError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("开启客户端解绑事务"))?;
        let Some(device) =
            find_client_device_by_install_id(&mut transaction, command.app_id, &command.install_id)
                .await?
        else {
            transaction
                .commit()
                .await
                .map_err(|_| AppError::DatabaseQueryFailed("提交客户端解绑事务"))?;
            return Ok(false);
        };
        if device.device_public_key != command.verified_device_public_key {
            return Err(AppError::BadDeviceSignature("设备签名错误"));
        }
        let card = if command.verification_enabled {
            let card = find_client_unbind_card_for_update(&mut transaction, command).await?;
            assert_client_unbind_allowed(&card, command)?;
            Some(card)
        } else {
            None
        };
        delete_client_device_in_transaction(&mut transaction, device.id).await?;
        if let Some(card) = card {
            record_client_card_unbind_in_transaction(&mut transaction, &card, command).await?;
        }
        write_audit_in_transaction(
            &mut transaction,
            Some(command.app_id),
            "unbind",
            "设备解绑成功",
            &command.ip,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("提交客户端解绑事务"))?;
        Ok(true)
    }

    pub async fn update_app_devices_status(
        &self,
        app_id: u64,
        device_ids: &[u64],
        status: i64,
    ) -> Result<u64, AppError> {
        if device_ids.is_empty() {
            return Ok(0);
        }
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("开启批量更新设备状态事务"))?;
        let mut update_builder =
            QueryBuilder::<MySql>::new("UPDATE `auth_devices` SET `status` = ");
        update_builder
            .push_bind(status)
            .push(" WHERE `app_id` = ")
            .push_bind(app_id)
            .push(" AND `id` IN (");
        push_id_bindings(&mut update_builder, device_ids);
        update_builder.push(")");
        update_builder
            .build()
            .execute(&mut *transaction)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("批量更新设备状态"))?;
        let revoked_sessions = if status == 0 {
            revoke_device_sessions_by_ids_in_transaction(&mut transaction, app_id, device_ids)
                .await?
        } else {
            0
        };
        transaction
            .commit()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("提交批量更新设备状态事务"))?;
        Ok(revoked_sessions)
    }

    pub async fn delete_app_devices(
        &self,
        app_id: u64,
        device_ids: &[u64],
    ) -> Result<u64, AppError> {
        if device_ids.is_empty() {
            return Ok(0);
        }
        let mut builder =
            QueryBuilder::<MySql>::new("DELETE FROM `auth_devices` WHERE `app_id` = ");
        builder.push_bind(app_id).push(" AND `id` IN (");
        push_id_bindings(&mut builder, device_ids);
        builder.push(")");
        let result = builder
            .build()
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("批量删除设备绑定"))?;
        Ok(result.rows_affected())
    }

    pub async fn delete_card_devices(&self, app_id: u64, card_id: u64) -> Result<u64, AppError> {
        let result = sqlx::query(
            "DELETE d FROM `auth_devices` d JOIN `auth_cards` c ON d.`app_id` = c.`app_id` \
             AND (d.`card_id` = c.`id` OR d.`card_hash` = c.`card_hash`) \
             WHERE c.`app_id` = ? AND c.`id` = ?",
        )
        .bind(app_id)
        .bind(card_id)
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("删除卡密绑定设备"))?;
        Ok(result.rows_affected())
    }

    pub async fn revoke_device_sessions(
        &self,
        app_id: u64,
        device_id: u64,
    ) -> Result<u64, AppError> {
        let result = sqlx::query(
            "UPDATE `auth_sessions` SET `status` = 0 \
             WHERE `app_id` = ? AND `device_id` = ? AND `status` = 1",
        )
        .bind(app_id)
        .bind(device_id)
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("撤销设备会话"))?;
        Ok(result.rows_affected())
    }

    pub async fn delete_expired_nonces(&self, now: NaiveDateTime) -> Result<u64, AppError> {
        self.delete_expired_rows("auth_nonces", "`expires_at` < ?", now, "清理客户端随机串")
            .await
    }

    pub async fn delete_expired_sessions(&self, now: NaiveDateTime) -> Result<u64, AppError> {
        self.delete_expired_rows(
            "auth_sessions",
            "`expires_at` < ? OR `status` = 0",
            now,
            "清理客户端会话",
        )
        .await
    }

    pub async fn delete_expired_login_challenges(
        &self,
        now: NaiveDateTime,
    ) -> Result<u64, AppError> {
        self.delete_expired_rows(
            "auth_login_challenges",
            "`used_at` IS NOT NULL OR `expires_at` < ?",
            now,
            "清理登录挑战",
        )
        .await
    }

    pub async fn delete_expired_admin_nonces(&self, now: NaiveDateTime) -> Result<u64, AppError> {
        self.delete_expired_rows(
            "auth_admin_nonces",
            "`expires_at` < ?",
            now,
            "清理后台随机串",
        )
        .await
    }

    pub async fn delete_expired_admin_sessions(&self, now: NaiveDateTime) -> Result<u64, AppError> {
        self.delete_expired_rows(
            "auth_admin_sessions",
            "`expires_at` < ? OR `status` = 0",
            now,
            "清理后台会话",
        )
        .await
    }

    pub async fn delete_expired_remote_api_nonces(
        &self,
        now: NaiveDateTime,
    ) -> Result<u64, AppError> {
        self.delete_expired_rows(
            "auth_remote_api_nonces",
            "`expires_at` < ?",
            now,
            "清理远程 API 随机串",
        )
        .await
    }

    pub async fn delete_expired_cloud_upload_tickets(
        &self,
        now: NaiveDateTime,
    ) -> Result<u64, AppError> {
        self.delete_expired_rows(
            "auth_cloud_upload_tickets",
            "`expires_at` < ?",
            now,
            "清理云存储上传票据",
        )
        .await
    }

    pub async fn cleanup_security_data(
        &self,
        now: NaiveDateTime,
        limit: i64,
    ) -> Result<SecurityCleanup, AppError> {
        let bounded_limit = limit.clamp(1, 1000);
        let report_ids = self.security_report_cleanup_ids(now, bounded_limit).await?;
        let archived_message_ids = self
            .archived_security_message_cleanup_ids(now, bounded_limit)
            .await?;
        let handled_limit = bounded_limit.saturating_sub(archived_message_ids.len() as i64);
        let handled_message_ids = self
            .handled_security_message_cleanup_ids(now, handled_limit)
            .await?;
        let message_ids = unique_ids(
            archived_message_ids
                .into_iter()
                .chain(handled_message_ids)
                .collect(),
        );
        let deleted_message_actions = delete_rows_by_ids(
            &self.pool,
            "auth_message_actions",
            "message_id",
            &message_ids,
            "清理消息动作",
        )
        .await?;
        let deleted_messages =
            delete_rows_by_ids(&self.pool, "auth_messages", "id", &message_ids, "清理消息").await?;
        let deleted_security_reports = delete_rows_by_ids(
            &self.pool,
            "auth_security_reports",
            "id",
            &report_ids,
            "清理安全上报",
        )
        .await?;
        Ok(SecurityCleanup {
            deleted_security_reports,
            deleted_messages,
            deleted_message_actions,
        })
    }

    async fn delete_expired_rows(
        &self,
        table_name: &'static str,
        condition_sql: &'static str,
        now: NaiveDateTime,
        action: &'static str,
    ) -> Result<u64, AppError> {
        let mut builder = QueryBuilder::<MySql>::new("DELETE FROM `");
        builder
            .push(table_name)
            .push("` WHERE ")
            .push(condition_sql);
        let result = builder
            .build()
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed(action))?;
        Ok(result.rows_affected())
    }

    async fn security_report_cleanup_ids(
        &self,
        now: NaiveDateTime,
        limit: i64,
    ) -> Result<Vec<u64>, AppError> {
        let rows = sqlx::query(
            "SELECT r.`id` FROM `auth_security_reports` r \
             LEFT JOIN `auth_security_policies` p ON p.`app_id` = r.`app_id` \
             WHERE r.`created_at` < DATE_SUB(?, INTERVAL COALESCE(p.`report_retention_days`, 90) DAY) \
             ORDER BY r.`id` ASC LIMIT ?",
        )
        .bind(now)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询可清理安全上报"))?;
        rows.into_iter()
            .map(|row| row_get(&row, "id", "读取可清理安全上报编号"))
            .collect()
    }

    async fn archived_security_message_cleanup_ids(
        &self,
        now: NaiveDateTime,
        limit: i64,
    ) -> Result<Vec<u64>, AppError> {
        let rows = sqlx::query(
            "SELECT m.`id` FROM `auth_messages` m \
             LEFT JOIN `auth_security_policies` p ON p.`app_id` = m.`app_id` \
             WHERE m.`status` = 'archived' AND m.`severity` IN ('low', 'medium') \
             AND m.`created_at` < DATE_SUB(?, INTERVAL COALESCE(p.`message_retention_days`, 180) DAY) \
             ORDER BY m.`id` ASC LIMIT ?",
        )
        .bind(now)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询可清理归档消息"))?;
        rows.into_iter()
            .map(|row| row_get(&row, "id", "读取可清理归档消息编号"))
            .collect()
    }

    async fn handled_security_message_cleanup_ids(
        &self,
        now: NaiveDateTime,
        limit: i64,
    ) -> Result<Vec<u64>, AppError> {
        if limit <= 0 {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            "SELECT m.`id` FROM `auth_messages` m \
             LEFT JOIN `auth_security_policies` p ON p.`app_id` = m.`app_id` \
             WHERE m.`status` IN ('handled', 'archived') AND m.`severity` IN ('high', 'critical') \
             AND m.`created_at` < DATE_SUB(?, INTERVAL 365 DAY) \
             ORDER BY m.`id` ASC LIMIT ?",
        )
        .bind(now)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询可清理高危消息"))?;
        rows.into_iter()
            .map(|row| row_get(&row, "id", "读取可清理高危消息编号"))
            .collect()
    }

    pub async fn admin_overview(&self, app_id: Option<u64>) -> Result<Overview, AppError> {
        let apps_total = self.count_all_apps().await?;
        let card_summary = self.card_overview(app_id).await?;
        let device_status = self.device_overview(app_id).await?;
        let (sessions_active, distinct_count) = self.session_overview(app_id).await?;
        let single_percent_basis_points = if card_summary.cards_total == 0 {
            0
        } else {
            card_summary.single_code * 10_000 / card_summary.cards_total
        };
        Ok(Overview {
            apps_total,
            cards_total: card_summary.cards_total,
            devices_total: device_status.enabled + device_status.disabled,
            sessions_active,
            card_status: CardStatusOverview {
                inactive: card_summary.inactive,
                active: card_summary.active,
                expired: card_summary.expired,
                disabled: card_summary.disabled,
            },
            device_status,
            single_code_ratio: SingleCodeRatio {
                total: card_summary.cards_total,
                single_code: card_summary.single_code,
                multi_device: (card_summary.cards_total - card_summary.single_code).max(0),
                single_percent_basis_points,
            },
            login_ip_stats: LoginIpStats { distinct_count },
        })
    }

    pub async fn list_audit_logs(
        &self,
        app_id: u64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditLogRow>, AppError> {
        let rows = sqlx::query(
            "SELECT `id`, `app_id`, `account_id`, `action`, `message`, `ip`, `region`, `created_at` \
             FROM `auth_audit_logs` WHERE `app_id` = ? ORDER BY `id` DESC LIMIT ? OFFSET ?",
        )
        .bind(app_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询审计日志"))?;
        rows.into_iter().map(audit_log_row).collect()
    }

    pub async fn write_audit(
        &self,
        app_id: Option<u64>,
        account_id: Option<u64>,
        action: &str,
        message: &str,
        ip: &str,
    ) -> Result<u64, AppError> {
        let result = sqlx::query(
            "INSERT INTO `auth_audit_logs` \
             (`app_id`, `account_id`, `action`, `message`, `ip`, `region`) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(app_id)
        .bind(account_id)
        .bind(clip_text(action, 40))
        .bind(clip_text(message, 255))
        .bind(clip_text(ip, 45))
        .bind(ip_region(ip))
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("写入审计日志"))?;
        Ok(result.last_insert_id())
    }

    pub async fn list_messages(
        &self,
        app_id: u64,
        filters: &MessageFilters,
    ) -> Result<Vec<MessageRow>, AppError> {
        let mut builder = QueryBuilder::<MySql>::new(MESSAGE_SELECT_PREFIX);
        builder.push(" WHERE m.`app_id` = ").push_bind(app_id);
        push_message_filter(&mut builder, "m.`status`", &filters.status);
        push_message_filter(&mut builder, "m.`action`", &filters.action);
        push_message_filter(&mut builder, "r.`risk_level`", &filters.risk_level);
        push_message_filter(&mut builder, "r.`event_type`", &filters.event_type);
        push_message_filter(
            &mut builder,
            "r.`card_fingerprint`",
            &filters.card_fingerprint,
        );
        push_message_filter(&mut builder, "r.`install_id`", &filters.install_id);
        push_message_filter(&mut builder, "r.`ip`", &filters.ip);
        if let Some(start) = filters.start {
            builder.push(" AND m.`created_at` >= ").push_bind(start);
        }
        if let Some(end) = filters.end {
            builder.push(" AND m.`created_at` <= ").push_bind(end);
        }
        builder
            .push(" ORDER BY m.`id` DESC LIMIT ")
            .push_bind(filters.limit)
            .push(" OFFSET ")
            .push_bind(filters.offset);
        let rows = builder
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("查询消息列表"))?;
        rows.into_iter().map(message_row).collect()
    }

    pub async fn find_message_detail(
        &self,
        app_id: u64,
        message_id: u64,
    ) -> Result<Option<MessageRow>, AppError> {
        let mut builder = QueryBuilder::<MySql>::new(MESSAGE_SELECT_PREFIX);
        builder
            .push(" WHERE m.`app_id` = ")
            .push_bind(app_id)
            .push(" AND m.`id` = ")
            .push_bind(message_id);
        let row = builder
            .build()
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("查询消息详情"))?;
        row.map(message_row).transpose()
    }

    pub async fn list_message_actions(
        &self,
        app_id: u64,
        message_id: u64,
    ) -> Result<Vec<MessageActionRow>, AppError> {
        let rows = sqlx::query(
            "SELECT `id`, `action`, `actor_type`, `actor_name`, `result`, `remark`, `ip`, `created_at` \
             FROM `auth_message_actions` WHERE `app_id` = ? AND `message_id` = ? ORDER BY `id` DESC",
        )
        .bind(app_id)
        .bind(message_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询消息动作"))?;
        rows.into_iter().map(message_action_row).collect()
    }

    pub async fn list_message_audit_logs(
        &self,
        app_id: u64,
        message_id: u64,
        limit: i64,
    ) -> Result<Vec<MessageAuditRow>, AppError> {
        let rows = sqlx::query(
            "SELECT `id`, `action`, `message`, `ip`, `created_at` FROM `auth_audit_logs` \
             WHERE `app_id` = ? AND `message` LIKE ? ORDER BY `id` DESC LIMIT ?",
        )
        .bind(app_id)
        .bind(format!("%消息#{message_id}%"))
        .bind(limit.clamp(1, 100))
        .fetch_all(&self.pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询消息审计"))?;
        rows.into_iter().map(message_audit_row).collect()
    }

    pub async fn update_messages_status(
        &self,
        app_id: u64,
        message_ids: &[u64],
        update: &MessageStatusUpdate,
    ) -> Result<u64, AppError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("开启消息状态事务"))?;
        let updated =
            update_messages_status_in_transaction(&mut transaction, app_id, message_ids, update)
                .await?;
        for message_id in message_ids {
            create_message_action_in_transaction(
                &mut transaction,
                &MessageActionRecord {
                    app_id,
                    message_id: *message_id,
                    action: &update.action,
                    actor_type: "admin",
                    actor_name: &update.actor_name,
                    result: "updated",
                    remark: &update.remark,
                    ip: &update.ip,
                },
            )
            .await?;
        }
        let audit_action = format!("messages_{}", update.action);
        let audit_message = message_status_audit_message(message_ids, &update.status, updated);
        write_audit_in_transaction(
            &mut transaction,
            Some(app_id),
            &audit_action,
            &audit_message,
            &update.ip,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("提交消息状态事务"))?;
        Ok(updated)
    }

    pub async fn delete_messages(
        &self,
        app_id: u64,
        message_ids: &[u64],
        ip: &str,
    ) -> Result<u64, AppError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("开启删除消息事务"))?;
        delete_message_actions_in_transaction(&mut transaction, app_id, message_ids).await?;
        let deleted = delete_messages_in_transaction(&mut transaction, app_id, message_ids).await?;
        let audit_message = format!(
            "删除消息：{}，{} 条",
            message_audit_labels(message_ids),
            deleted
        );
        write_audit_in_transaction(
            &mut transaction,
            Some(app_id),
            "messages_delete",
            &audit_message,
            ip,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("提交删除消息事务"))?;
        Ok(deleted)
    }

    pub async fn clear_app_activity_data(
        &self,
        app_id: u64,
    ) -> Result<AppActivityCleanup, AppError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("开启清理应用活动事务"))?;
        let deleted_message_actions =
            delete_app_rows_in_transaction(&mut transaction, "auth_message_actions", &[app_id])
                .await?;
        let deleted_messages =
            delete_app_rows_in_transaction(&mut transaction, "auth_messages", &[app_id]).await?;
        let deleted_security_reports =
            delete_app_rows_in_transaction(&mut transaction, "auth_security_reports", &[app_id])
                .await?;
        let deleted_audit_logs =
            delete_app_rows_in_transaction(&mut transaction, "auth_audit_logs", &[app_id]).await?;
        transaction
            .commit()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("提交清理应用活动事务"))?;
        Ok(AppActivityCleanup {
            deleted_message_actions,
            deleted_messages,
            deleted_security_reports,
            deleted_audit_logs,
        })
    }

    pub async fn act_message(
        &self,
        app_id: u64,
        message: &MessageRow,
        action: &MessageAdminAction,
    ) -> Result<MessageActionEffect, AppError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("开启消息处置事务"))?;
        let effect =
            apply_message_action_in_transaction(&mut transaction, app_id, message, &action.action)
                .await?;
        create_message_action_in_transaction(
            &mut transaction,
            &MessageActionRecord {
                app_id,
                message_id: message.id,
                action: &action.action,
                actor_type: "admin",
                actor_name: &action.actor_name,
                result: &effect.result,
                remark: &action.remark,
                ip: &action.ip,
            },
        )
        .await?;
        let handled_at = chrono::Local::now().naive_local();
        let update = MessageStatusUpdate {
            status: "handled".to_string(),
            read_at: None,
            handled_by: action.actor_name.clone(),
            handled_at: Some(handled_at),
            archived_at: None,
            action: action.action.clone(),
            actor_name: action.actor_name.clone(),
            remark: action.remark.clone(),
            ip: action.ip.clone(),
        };
        update_messages_status_in_transaction(&mut transaction, app_id, &[message.id], &update)
            .await?;
        let audit_action = format!("message_{}", action.action);
        write_audit_in_transaction(
            &mut transaction,
            Some(app_id),
            &audit_action,
            &action.audit_message,
            &action.ip,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("提交消息处置事务"))?;
        Ok(effect)
    }

    async fn count_all_apps(&self) -> Result<i64, AppError> {
        let row = sqlx::query("SELECT COUNT(*) AS `apps_total` FROM `auth_apps`")
            .fetch_one(&self.pool)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("统计应用总数"))?;
        row_get(&row, "apps_total", "读取应用总数")
    }

    async fn card_overview(&self, app_id: Option<u64>) -> Result<CardOverviewRow, AppError> {
        let now = chrono::Local::now().naive_local();
        let row = if let Some(app_id) = app_id {
            sqlx::query(CARD_OVERVIEW_SQL_WITH_APP)
                .bind(now)
                .bind(now)
                .bind(app_id)
                .fetch_one(&self.pool)
                .await
        } else {
            sqlx::query(CARD_OVERVIEW_SQL_ALL)
                .bind(now)
                .bind(now)
                .fetch_one(&self.pool)
                .await
        }
        .map_err(|_| AppError::DatabaseQueryFailed("统计卡密概览"))?;
        Ok(CardOverviewRow {
            cards_total: row_get(&row, "cards_total", "读取卡密总数")?,
            inactive: row_get(&row, "inactive", "读取未激活卡密数")?,
            active: row_get(&row, "active", "读取已激活卡密数")?,
            expired: row_get(&row, "expired", "读取过期卡密数")?,
            disabled: row_get(&row, "disabled", "读取禁用卡密数")?,
            single_code: row_get(&row, "single_code", "读取单码卡密数")?,
        })
    }

    async fn device_overview(&self, app_id: Option<u64>) -> Result<DeviceStatusOverview, AppError> {
        let row = if let Some(app_id) = app_id {
            sqlx::query(
                "SELECT COUNT(*) AS `devices_total`, \
                 CAST(COALESCE(SUM(CASE WHEN `status` = 1 THEN 1 ELSE 0 END), 0) AS SIGNED) AS `enabled`, \
                 CAST(COALESCE(SUM(CASE WHEN `status` = 0 THEN 1 ELSE 0 END), 0) AS SIGNED) AS `disabled` \
                 FROM `auth_devices` WHERE `app_id` = ?",
            )
            .bind(app_id)
            .fetch_one(&self.pool)
            .await
        } else {
            sqlx::query(
                "SELECT COUNT(*) AS `devices_total`, \
                 CAST(COALESCE(SUM(CASE WHEN `status` = 1 THEN 1 ELSE 0 END), 0) AS SIGNED) AS `enabled`, \
                 CAST(COALESCE(SUM(CASE WHEN `status` = 0 THEN 1 ELSE 0 END), 0) AS SIGNED) AS `disabled` \
                 FROM `auth_devices`",
            )
            .fetch_one(&self.pool)
            .await
        }
        .map_err(|_| AppError::DatabaseQueryFailed("统计设备概览"))?;
        Ok(DeviceStatusOverview {
            enabled: row_get(&row, "enabled", "读取启用设备数")?,
            disabled: row_get(&row, "disabled", "读取禁用设备数")?,
        })
    }

    async fn session_overview(&self, app_id: Option<u64>) -> Result<(i64, i64), AppError> {
        let row = if let Some(app_id) = app_id {
            sqlx::query(
                "SELECT \
                 CAST(COALESCE(SUM(CASE WHEN `status` = 1 AND `expires_at` >= NOW() \
                   AND COALESCE(`last_heartbeat_at`, `created_at`) >= DATE_SUB(NOW(), INTERVAL 300 SECOND) \
                   THEN 1 ELSE 0 END), 0) AS SIGNED) AS `sessions_active`, \
                 COUNT(DISTINCT CASE WHEN `status` = 1 AND `expires_at` >= NOW() \
                   AND COALESCE(`last_heartbeat_at`, `created_at`) >= DATE_SUB(NOW(), INTERVAL 300 SECOND) \
                   THEN `ip` END) AS `distinct_ips` \
                 FROM `auth_sessions` WHERE `app_id` = ?",
            )
            .bind(app_id)
            .fetch_one(&self.pool)
            .await
        } else {
            sqlx::query(
                "SELECT \
                 CAST(COALESCE(SUM(CASE WHEN `status` = 1 AND `expires_at` >= NOW() \
                   AND COALESCE(`last_heartbeat_at`, `created_at`) >= DATE_SUB(NOW(), INTERVAL 300 SECOND) \
                   THEN 1 ELSE 0 END), 0) AS SIGNED) AS `sessions_active`, \
                 COUNT(DISTINCT CASE WHEN `status` = 1 AND `expires_at` >= NOW() \
                   AND COALESCE(`last_heartbeat_at`, `created_at`) >= DATE_SUB(NOW(), INTERVAL 300 SECOND) \
                   THEN `ip` END) AS `distinct_ips` \
                 FROM `auth_sessions`",
            )
            .fetch_one(&self.pool)
            .await
        }
        .map_err(|_| AppError::DatabaseQueryFailed("统计会话概览"))?;
        Ok((
            row_get(&row, "sessions_active", "读取在线会话数")?,
            row_get(&row, "distinct_ips", "读取登录 IP 数")?,
        ))
    }
}

#[derive(Debug)]
struct CardOverviewRow {
    cards_total: i64,
    inactive: i64,
    active: i64,
    expired: i64,
    disabled: i64,
    single_code: i64,
}

const APP_DEPENDENT_TABLES: &[&str] = &[
    "auth_sessions",
    "auth_login_challenges",
    "auth_nonces",
    "auth_devices",
    "auth_cards",
    "auth_accounts",
    "auth_remote_variable_apps",
    "auth_remote_configs",
    "auth_message_actions",
    "auth_messages",
    "auth_security_reports",
    "auth_security_policies",
    "auth_audit_logs",
    "auth_app_secrets",
];

const APP_DETAIL_SQL_BY_ID: &str = "SELECT `id`, `app_code`, `api_token`, `name`, \
    CAST(`status` AS SIGNED) AS `status`, CAST(`max_devices` AS SIGNED) AS `max_devices`, \
    CAST(`heartbeat_interval` AS SIGNED) AS `heartbeat_interval`, \
    CAST(`heartbeat_enabled` AS SIGNED) AS `heartbeat_enabled`, \
    CAST(`verification_enabled` AS SIGNED) AS `verification_enabled`, \
    CAST(`device_binding_enabled` AS SIGNED) AS `device_binding_enabled`, \
    CAST(`shared_cards_enabled` AS SIGNED) AS `shared_cards_enabled`, \
    CAST(`login_ip_binding_enabled` AS SIGNED) AS `login_ip_binding_enabled`, \
    CAST(`web_card_query_enabled` AS SIGNED) AS `web_card_query_enabled`, \
    CAST(`unbind_interval_seconds` AS SIGNED) AS `unbind_interval_seconds`, \
    CAST(`unbind_deduct_seconds` AS SIGNED) AS `unbind_deduct_seconds`, \
    CAST(`unbind_deduct_uses` AS SIGNED) AS `unbind_deduct_uses`, \
    CAST(`api_success_code` AS SIGNED) AS `api_success_code`, `api_config_json`, \
    `latest_version`, `client_auth_mode`, `client_crypto_alg`, `client_public_key`, \
    `client_private_key_cipher`, `remark`, `created_at`, `updated_at` FROM `auth_apps` \
    WHERE `id` = ?";

const APP_DETAIL_SQL_BY_CODE: &str = "SELECT `id`, `app_code`, `api_token`, `name`, \
    CAST(`status` AS SIGNED) AS `status`, CAST(`max_devices` AS SIGNED) AS `max_devices`, \
    CAST(`heartbeat_interval` AS SIGNED) AS `heartbeat_interval`, \
    CAST(`heartbeat_enabled` AS SIGNED) AS `heartbeat_enabled`, \
    CAST(`verification_enabled` AS SIGNED) AS `verification_enabled`, \
    CAST(`device_binding_enabled` AS SIGNED) AS `device_binding_enabled`, \
    CAST(`shared_cards_enabled` AS SIGNED) AS `shared_cards_enabled`, \
    CAST(`login_ip_binding_enabled` AS SIGNED) AS `login_ip_binding_enabled`, \
    CAST(`web_card_query_enabled` AS SIGNED) AS `web_card_query_enabled`, \
    CAST(`unbind_interval_seconds` AS SIGNED) AS `unbind_interval_seconds`, \
    CAST(`unbind_deduct_seconds` AS SIGNED) AS `unbind_deduct_seconds`, \
    CAST(`unbind_deduct_uses` AS SIGNED) AS `unbind_deduct_uses`, \
    CAST(`api_success_code` AS SIGNED) AS `api_success_code`, `api_config_json`, \
    `latest_version`, `client_auth_mode`, `client_crypto_alg`, `client_public_key`, \
    `client_private_key_cipher`, `remark`, `created_at`, `updated_at` FROM `auth_apps` \
    WHERE `app_code` = ?";

const MESSAGE_SELECT_PREFIX: &str = "SELECT m.`id`, m.`app_id`, m.`report_id`, m.`session_id`, \
    m.`device_id`, m.`card_id`, m.`message_type`, m.`severity`, m.`status`, m.`title`, \
    m.`summary`, m.`action`, m.`action_source`, CAST(m.`risk_score` AS SIGNED) AS `risk_score`, \
    m.`handled_by`, m.`read_at`, m.`handled_at`, m.`archived_at`, m.`created_at`, \
    COALESCE(r.`event_id`, '') AS `event_id`, COALESCE(r.`event_type`, '') AS `event_type`, \
    COALESCE(r.`risk_level`, m.`severity`) AS `risk_level`, \
    CAST(COALESCE(r.`confidence`, 0) AS SIGNED) AS `confidence`, \
    COALESCE(r.`requested_action`, '') AS `requested_action`, \
    COALESCE(r.`action_reason`, '') AS `action_reason`, \
    COALESCE(r.`message`, '') AS `report_message`, \
    COALESCE(r.`evidence_json`, '{}') AS `evidence_json`, \
    COALESCE(r.`attestation_json`, '{}') AS `attestation_json`, \
    COALESCE(r.`card_hash`, '') AS `card_hash`, \
    COALESCE(r.`card_fingerprint`, '') AS `card_fingerprint`, \
    COALESCE(r.`install_id`, '') AS `install_id`, \
    COALESCE(r.`sdk_version`, '') AS `sdk_version`, \
    COALESCE(r.`detector_version`, '') AS `detector_version`, \
    COALESCE(r.`platform`, '') AS `platform`, COALESCE(r.`ip`, '') AS `ip`, \
    r.`occurred_at` FROM `auth_messages` m \
    LEFT JOIN `auth_security_reports` r ON r.`id` = m.`report_id`";

const CARD_OVERVIEW_SQL_ALL: &str = "SELECT COUNT(*) AS `cards_total`, \
    CAST(COALESCE(SUM(CASE WHEN `status` = 0 THEN 1 ELSE 0 END), 0) AS SIGNED) AS `inactive`, \
    CAST(COALESCE(SUM(CASE WHEN `status` = 1 AND (`card_type` IN ('permanent', 'count') \
        OR (`used_at` IS NOT NULL AND DATE_ADD(`used_at`, INTERVAL `duration_seconds` SECOND) >= ?)) THEN 1 ELSE 0 END), 0) AS SIGNED) AS `active`, \
    CAST(COALESCE(SUM(CASE WHEN `status` = 1 AND `card_type` = 'time' AND `used_at` IS NOT NULL \
        AND DATE_ADD(`used_at`, INTERVAL `duration_seconds` SECOND) < ? THEN 1 ELSE 0 END), 0) AS SIGNED) AS `expired`, \
    CAST(COALESCE(SUM(CASE WHEN `status` = 2 THEN 1 ELSE 0 END), 0) AS SIGNED) AS `disabled`, \
    CAST(COALESCE(SUM(CASE WHEN `max_devices` = 1 THEN 1 ELSE 0 END), 0) AS SIGNED) AS `single_code` \
    FROM `auth_cards`";

const CARD_OVERVIEW_SQL_WITH_APP: &str = "SELECT COUNT(*) AS `cards_total`, \
    CAST(COALESCE(SUM(CASE WHEN `status` = 0 THEN 1 ELSE 0 END), 0) AS SIGNED) AS `inactive`, \
    CAST(COALESCE(SUM(CASE WHEN `status` = 1 AND (`card_type` IN ('permanent', 'count') \
        OR (`used_at` IS NOT NULL AND DATE_ADD(`used_at`, INTERVAL `duration_seconds` SECOND) >= ?)) THEN 1 ELSE 0 END), 0) AS SIGNED) AS `active`, \
    CAST(COALESCE(SUM(CASE WHEN `status` = 1 AND `card_type` = 'time' AND `used_at` IS NOT NULL \
        AND DATE_ADD(`used_at`, INTERVAL `duration_seconds` SECOND) < ? THEN 1 ELSE 0 END), 0) AS SIGNED) AS `expired`, \
    CAST(COALESCE(SUM(CASE WHEN `status` = 2 THEN 1 ELSE 0 END), 0) AS SIGNED) AS `disabled`, \
    CAST(COALESCE(SUM(CASE WHEN `max_devices` = 1 THEN 1 ELSE 0 END), 0) AS SIGNED) AS `single_code` \
    FROM `auth_cards` WHERE `app_id` = ?";

const CARD_LIST_SELECT_PREFIX: &str = "SELECT c.`id`, c.`app_id`, c.`card_hash`, \
    c.`card_cipher`, c.`card_fingerprint`, c.`card_type`, \
    CAST(c.`duration_seconds` AS SIGNED) AS `duration_seconds`, \
    CAST(c.`total_uses` AS SIGNED) AS `total_uses`, \
    CAST(c.`remaining_uses` AS SIGNED) AS `remaining_uses`, \
    CAST(c.`max_devices` AS SIGNED) AS `max_devices`, \
    c.`card_structure`, c.`prefix`, CAST(c.`unbind_limit` AS SIGNED) AS `unbind_limit`, \
    CAST(c.`unbind_count` AS SIGNED) AS `unbind_count`, c.`last_unbound_at`, \
    CAST(c.`status` AS SIGNED) AS `status`, c.`used_account_id`, c.`used_at`, c.`created_at`, ";

const CARD_ONLINE_COUNT_SQL: &str = "CAST((SELECT COUNT(*) FROM `auth_sessions` s \
    WHERE s.`app_id` = c.`app_id` AND s.`card_id` = c.`id` AND s.`status` = 1 \
    AND s.`expires_at` >= NOW() \
    AND COALESCE(s.`last_heartbeat_at`, s.`created_at`) >= DATE_SUB(NOW(), INTERVAL 300 SECOND)) AS SIGNED)";

const CARD_LOGIN_IPS_SQL: &str = "COALESCE((SELECT GROUP_CONCAT(DISTINCT s.`ip` ORDER BY s.`ip` SEPARATOR ',') \
    FROM `auth_sessions` s WHERE s.`app_id` = c.`app_id` AND s.`card_id` = c.`id` \
    AND s.`status` = 1 AND s.`expires_at` >= NOW() \
    AND COALESCE(s.`last_heartbeat_at`, s.`created_at`) >= DATE_SUB(NOW(), INTERVAL 300 SECOND)), '')";

const CARD_DEVICE_COUNT_SQL: &str = "CAST(((SELECT COUNT(*) FROM `auth_devices` d \
    WHERE d.`app_id` = c.`app_id` AND d.`card_id` = c.`id`) \
    + (SELECT COUNT(*) FROM `auth_devices` d WHERE d.`app_id` = c.`app_id` \
    AND d.`card_id` IS NULL AND d.`card_hash` = c.`card_hash`)) AS SIGNED)";

const CARD_BY_ID_SQL: &str = "SELECT c.`id`, c.`app_id`, c.`card_hash`, \
    c.`card_cipher`, c.`card_fingerprint`, c.`card_type`, \
    CAST(c.`duration_seconds` AS SIGNED) AS `duration_seconds`, \
    CAST(c.`total_uses` AS SIGNED) AS `total_uses`, \
    CAST(c.`remaining_uses` AS SIGNED) AS `remaining_uses`, \
    CAST(c.`max_devices` AS SIGNED) AS `max_devices`, \
    c.`card_structure`, c.`prefix`, CAST(c.`unbind_limit` AS SIGNED) AS `unbind_limit`, \
    CAST(c.`unbind_count` AS SIGNED) AS `unbind_count`, c.`last_unbound_at`, \
    CAST(c.`status` AS SIGNED) AS `status`, c.`used_account_id`, c.`used_at`, c.`created_at`, \
    CAST(0 AS SIGNED) AS `online_count`, '' AS `login_ips`, CAST(0 AS SIGNED) AS `device_count` \
    FROM `auth_cards` c WHERE c.`id` = ?";

const CARD_BY_HASH_SQL: &str = "SELECT c.`id`, c.`app_id`, c.`card_hash`, \
    c.`card_cipher`, c.`card_fingerprint`, c.`card_type`, \
    CAST(c.`duration_seconds` AS SIGNED) AS `duration_seconds`, \
    CAST(c.`total_uses` AS SIGNED) AS `total_uses`, \
    CAST(c.`remaining_uses` AS SIGNED) AS `remaining_uses`, \
    CAST(c.`max_devices` AS SIGNED) AS `max_devices`, \
    c.`card_structure`, c.`prefix`, CAST(c.`unbind_limit` AS SIGNED) AS `unbind_limit`, \
    CAST(c.`unbind_count` AS SIGNED) AS `unbind_count`, c.`last_unbound_at`, \
    CAST(c.`status` AS SIGNED) AS `status`, c.`used_account_id`, c.`used_at`, c.`created_at`, \
    CAST(0 AS SIGNED) AS `online_count`, '' AS `login_ips`, CAST(0 AS SIGNED) AS `device_count` \
    FROM `auth_cards` c WHERE c.`app_id` = ? AND c.`card_hash` = ?";

const CLIENT_DEVICE_BY_INSTALL_ID_SQL: &str = "SELECT `id`, `app_id`, `account_id`, \
    `card_id`, `card_hash`, `device_hash`, `device_name`, `install_id`, `device_public_key`, \
    `device_key_alg`, `machine_profile_hash`, `bind_ip`, `bind_region`, \
    CAST(`risk_level` AS SIGNED) AS `risk_level`, CAST(`status` AS SIGNED) AS `status`, \
    `first_seen_at`, `last_seen_at` FROM `auth_devices` \
    WHERE `app_id` = ? AND `install_id` = ? FOR UPDATE";

const CLIENT_SESSION_BY_TOKEN_HASH_SQL: &str = "SELECT s.`id`, s.`app_id`, s.`device_id`, \
    s.`card_id`, s.`card_hash`, s.`card_fingerprint`, s.`token_hash`, \
    CAST(s.`request_counter` AS SIGNED) AS `request_counter`, s.`proof_mode`, \
    s.`ticket_hash`, s.`ticket_expires_at`, CAST(s.`status` AS SIGNED) AS `status`, \
    s.`expires_at`, CAST(d.`status` AS SIGNED) AS `device_status`, COALESCE(d.`install_id`, '') AS `install_id`, \
    COALESCE(d.`device_public_key`, '') AS `device_public_key`, \
    COALESCE(d.`device_key_alg`, '') AS `device_key_alg`, d.`last_seen_at` AS `device_last_seen_at`, \
    CAST(c.`status` AS SIGNED) AS `card_status`, COALESCE(c.`card_hash`, '') AS `stored_card_hash`, \
    COALESCE(c.`card_fingerprint`, '') AS `stored_card_fingerprint`, \
    COALESCE(c.`card_type`, '') AS `stored_card_type`, \
    CAST(COALESCE(c.`duration_seconds`, 0) AS SIGNED) AS `stored_card_duration_seconds`, \
    CAST(COALESCE(c.`remaining_uses`, 0) AS SIGNED) AS `stored_card_remaining_uses`, \
    CAST(COALESCE(c.`max_devices`, 0) AS SIGNED) AS `stored_card_max_devices`, \
    c.`used_at` AS `stored_card_used_at` FROM `auth_sessions` s \
    LEFT JOIN `auth_devices` d ON d.`id` = s.`device_id` \
    LEFT JOIN `auth_cards` c ON c.`id` = s.`card_id` \
    WHERE s.`app_id` = ? AND s.`token_hash` = ?";

pub async fn connect_database(config: &DatabaseConfig) -> Result<MySqlPool, AppError> {
    let options = MySqlConnectOptions::new()
        .host(&config.host)
        .port(config.port)
        .username(&config.username)
        .password(&config.password)
        .database(&config.database_name);

    MySqlPoolOptions::new()
        .max_connections(10)
        .connect_with(options)
        .await
        .map_err(|_| AppError::DatabaseConnectFailed)
}

fn admin_row(row: sqlx::mysql::MySqlRow) -> Result<AdminRow, AppError> {
    Ok(AdminRow {
        username: row_get(&row, "username", "读取管理员账号")?,
        password: row_get(&row, "password", "读取管理员密码")?,
        created_at: row_get(&row, "created_at", "读取管理员创建时间")?,
        updated_at: row_get(&row, "updated_at", "读取管理员更新时间")?,
        remember_login_token_hash: row_get(&row, "remember_login_token_hash", "读取记住登录状态")?,
        remember_login_expires_at: row_get(
            &row,
            "remember_login_expires_at",
            "读取记住登录到期时间",
        )?,
    })
}

fn admin_session_row(row: sqlx::mysql::MySqlRow) -> Result<AdminSessionRow, AppError> {
    Ok(AdminSessionRow {
        id: row_get(&row, "id", "读取后台会话编号")?,
        key_cipher: row_get(&row, "key_cipher", "读取后台会话密钥")?,
        ip: row_get(&row, "ip", "读取后台会话 IP")?,
        admin_username: row_get(&row, "admin_username", "读取后台会话管理员")?,
        status: row_get(&row, "status", "读取后台会话状态")?,
        expires_at: row_get(&row, "expires_at", "读取后台会话到期时间")?,
    })
}

fn site_settings_row(row: sqlx::mysql::MySqlRow) -> Result<SiteSettingsRow, AppError> {
    let custom_json: Option<Json<Value>> = row_get(&row, "custom_json", "读取站点扩展设置")?;
    Ok(SiteSettingsRow {
        hostname: row_get(&row, "hostname", "读取系统名称")?,
        site_subtitle: row_get(&row, "site_subtitle", "读取系统副标题")?,
        siteurl: row_get(&row, "siteurl", "读取站点地址")?,
        logo_url: row_get(&row, "logo_url", "读取站点 Logo")?,
        announcement: row_get(&row, "announcement", "读取站点公告")?,
        contact: row_get(&row, "contact", "读取联系方式")?,
        footer_text: row_get(&row, "footer_text", "读取页脚文案")?,
        custom_json: object_or_empty(custom_json.map(|json| json.0)),
    })
}

fn remote_config_row(row: sqlx::mysql::MySqlRow) -> Result<RemoteConfigRow, AppError> {
    Ok(RemoteConfigRow {
        app_id: row_get(&row, "app_id", "读取远程配置应用编号")?,
        notice: row_get(&row, "notice", "读取应用公告")?,
        config_json: row_get(&row, "config_json", "读取远程配置 JSON")?,
        variables_json: row_get(&row, "variables_json", "读取远程变量 JSON")?,
        version: row_get(&row, "version", "读取远程配置版本")?,
        force_update: row_get(&row, "force_update", "读取强制更新开关")?,
        download_url: row_get(&row, "download_url", "读取下载地址")?,
        status: row_get(&row, "status", "读取远程配置状态")?,
    })
}

fn remote_variable_row(row: sqlx::mysql::MySqlRow) -> Result<RemoteVariableRow, AppError> {
    Ok(RemoteVariableRow {
        id: row_get(&row, "id", "读取远程变量编号")?,
        name: row_get(&row, "name", "读取远程变量名")?,
        value: row_get(&row, "value", "读取远程变量值")?,
        scope: row_get(&row, "scope", "读取远程变量作用域")?,
        status: row_get(&row, "status", "读取远程变量状态")?,
        app_ids_csv: row_get(&row, "app_ids_csv", "读取远程变量授权应用编号")?,
        app_names_csv: row_get(&row, "app_names_csv", "读取远程变量授权应用名称")?,
        app_count: row_get(&row, "app_count", "读取远程变量授权应用数量")?,
        created_at: row_get(&row, "created_at", "读取远程变量创建时间")?,
        updated_at: row_get(&row, "updated_at", "读取远程变量更新时间")?,
    })
}

fn remote_variable_detail_row(
    row: sqlx::mysql::MySqlRow,
) -> Result<RemoteVariableDetailRow, AppError> {
    Ok(RemoteVariableDetailRow {
        id: row_get(&row, "id", "读取远程变量编号")?,
        name: row_get(&row, "name", "读取远程变量名")?,
        value: row_get(&row, "value", "读取远程变量值")?,
        scope: row_get(&row, "scope", "读取远程变量作用域")?,
        status: row_get(&row, "status", "读取远程变量状态")?,
        created_at: row_get(&row, "created_at", "读取远程变量创建时间")?,
        updated_at: row_get(&row, "updated_at", "读取远程变量更新时间")?,
    })
}

fn remote_api_token_row(row: sqlx::mysql::MySqlRow) -> Result<RemoteApiTokenRow, AppError> {
    Ok(RemoteApiTokenRow {
        id: row_get(&row, "id", "读取远程 API Token 编号")?,
        name: row_get(&row, "name", "读取远程 API Token 名称")?,
        access_key: row_get(&row, "access_key", "读取远程 API accessKey")?,
        status: row_get(&row, "status", "读取远程 API Token 状态")?,
        expires_at: row_get(&row, "expires_at", "读取远程 API Token 过期时间")?,
        ip_allowlist_json: row_get(&row, "ip_allowlist_json", "读取远程 API IP 白名单")?,
        last_used_at: row_get(&row, "last_used_at", "读取远程 API 最后调用时间")?,
        last_ip: row_get(&row, "last_ip", "读取远程 API 最后来源 IP")?,
        created_by: row_get(&row, "created_by", "读取远程 API 创建人")?,
        created_at: row_get(&row, "created_at", "读取远程 API 创建时间")?,
        updated_at: row_get(&row, "updated_at", "读取远程 API 更新时间")?,
    })
}

fn remote_api_token_detail_row(
    row: sqlx::mysql::MySqlRow,
) -> Result<RemoteApiTokenDetailRow, AppError> {
    Ok(RemoteApiTokenDetailRow {
        id: row_get(&row, "id", "读取远程 API Token 编号")?,
        name: row_get(&row, "name", "读取远程 API Token 名称")?,
        access_key: row_get(&row, "access_key", "读取远程 API accessKey")?,
        secret_cipher: row_get(&row, "secret_cipher", "读取远程 API secret 密文")?,
        status: row_get(&row, "status", "读取远程 API Token 状态")?,
        expires_at: row_get(&row, "expires_at", "读取远程 API Token 过期时间")?,
        ip_allowlist_json: row_get(&row, "ip_allowlist_json", "读取远程 API IP 白名单")?,
        last_used_at: row_get(&row, "last_used_at", "读取远程 API 最后调用时间")?,
        last_ip: row_get(&row, "last_ip", "读取远程 API 最后来源 IP")?,
        created_by: row_get(&row, "created_by", "读取远程 API 创建人")?,
        created_at: row_get(&row, "created_at", "读取远程 API 创建时间")?,
        updated_at: row_get(&row, "updated_at", "读取远程 API 更新时间")?,
    })
}

fn remote_api_log_row(row: sqlx::mysql::MySqlRow) -> Result<RemoteApiLogRow, AppError> {
    Ok(RemoteApiLogRow {
        id: row_get(&row, "id", "读取远程 API 日志编号")?,
        token_id: row_get(&row, "token_id", "读取远程 API 日志 Token")?,
        access_key: row_get(&row, "access_key", "读取远程 API 日志 accessKey")?,
        route: row_get(&row, "route", "读取远程 API 日志路由")?,
        target_app_id: row_get(&row, "target_app_id", "读取远程 API 日志应用")?,
        request_hash: row_get(&row, "request_hash", "读取远程 API 日志请求摘要")?,
        status: row_get(&row, "status", "读取远程 API 日志状态")?,
        error_code: row_get(&row, "error_code", "读取远程 API 日志错误码")?,
        message: row_get(&row, "message", "读取远程 API 日志消息")?,
        ip: row_get(&row, "ip", "读取远程 API 日志来源 IP")?,
        created_at: row_get(&row, "created_at", "读取远程 API 日志时间")?,
        token_name: row_get(&row, "token_name", "读取远程 API 日志 Token 名称")?,
        app_code: row_get(&row, "app_code", "读取远程 API 日志应用编号")?,
        app_name: row_get(&row, "app_name", "读取远程 API 日志应用名称")?,
    })
}

fn cloud_storage_config_row(row: sqlx::mysql::MySqlRow) -> Result<CloudStorageConfigRow, AppError> {
    Ok(CloudStorageConfigRow {
        id: row_get(&row, "id", "读取云存储配置编号")?,
        provider: row_get(&row, "provider", "读取云存储来源")?,
        status: row_get(&row, "status", "读取云存储状态")?,
        is_default: row_get(&row, "is_default", "读取默认云存储标记")?,
        bucket: row_get(&row, "bucket", "读取云存储 bucket")?,
        region: row_get(&row, "region", "读取云存储 region")?,
        endpoint: row_get(&row, "endpoint", "读取云存储 endpoint")?,
        access_key: row_get(&row, "access_key", "读取云存储 accessKey")?,
        secret_cipher: row_get(&row, "secret_cipher", "读取云存储 secret")?,
        path_prefix: row_get(&row, "path_prefix", "读取云存储路径前缀")?,
        custom_domain: row_get(&row, "custom_domain", "读取云存储自定义域名")?,
        max_file_size: row_get(&row, "max_file_size", "读取云存储大小限制")?,
        allowed_extensions: row_get(&row, "allowed_extensions", "读取云存储扩展名限制")?,
        signed_url_ttl_seconds: row_get(&row, "signed_url_ttl_seconds", "读取云存储短签时长")?,
        last_test_status: row_get(&row, "last_test_status", "读取云存储测试状态")?,
        last_test_message: row_get(&row, "last_test_message", "读取云存储测试消息")?,
        last_test_at: row_get(&row, "last_test_at", "读取云存储测试时间")?,
    })
}

fn cloud_provider_count_row(row: sqlx::mysql::MySqlRow) -> Result<CloudProviderCountRow, AppError> {
    Ok(CloudProviderCountRow {
        provider: row_get(&row, "provider", "读取云存储来源")?,
        file_count: row_get(&row, "file_count", "读取云存储文件数")?,
        size_total: row_get(&row, "size_total", "读取云存储来源大小")?,
    })
}

fn cloud_file_row(row: sqlx::mysql::MySqlRow) -> Result<CloudFileRow, AppError> {
    Ok(CloudFileRow {
        id: row_get(&row, "id", "读取云存储文件编号")?,
        file_key: row_get(&row, "file_key", "读取云存储文件 Key")?,
        provider: row_get(&row, "provider", "读取云存储文件来源")?,
        config_id: row_get(&row, "config_id", "读取云存储文件配置")?,
        original_name: row_get(&row, "original_name", "读取云存储文件名")?,
        mime_type: row_get(&row, "mime_type", "读取云存储 MIME")?,
        extension: row_get(&row, "extension", "读取云存储扩展名")?,
        size_bytes: row_get(&row, "size_bytes", "读取云存储文件大小")?,
        sha256: row_get(&row, "sha256", "读取云存储 SHA256")?,
        object_key: row_get(&row, "object_key", "读取云存储对象 Key")?,
        local_path: row_get(&row, "local_path", "读取云存储本地路径")?,
        status: row_get(&row, "status", "读取云存储文件状态")?,
        remark: row_get(&row, "remark", "读取云存储备注")?,
        download_count: row_get(&row, "download_count", "读取云存储下载次数")?,
        last_download_ip: row_get(&row, "last_download_ip", "读取云存储最后下载 IP")?,
        last_download_at: row_get(&row, "last_download_at", "读取云存储最后下载时间")?,
        created_at: row_get(&row, "created_at", "读取云存储创建时间")?,
        updated_at: row_get(&row, "updated_at", "读取云存储更新时间")?,
        config_test_status: row_get(&row, "config_test_status", "读取云存储配置测试状态")?,
    })
}

fn cloud_download_token_row(row: sqlx::mysql::MySqlRow) -> Result<CloudDownloadTokenRow, AppError> {
    Ok(CloudDownloadTokenRow {
        token_hash: row_get(&row, "token_hash", "读取云存储下载 Token 摘要")?,
        token_cipher: row_get(&row, "token_cipher", "读取云存储下载 Token 密文")?,
        status: row_get(&row, "status", "读取云存储下载 Token 状态")?,
        last_used_ip: row_get(&row, "last_used_ip", "读取云存储下载 Token 来源 IP")?,
        last_used_at: row_get(&row, "last_used_at", "读取云存储下载 Token 时间")?,
    })
}

fn cloud_upload_ticket_row(row: sqlx::mysql::MySqlRow) -> Result<CloudUploadTicketRow, AppError> {
    Ok(CloudUploadTicketRow {
        id: row_get(&row, "id", "读取云存储上传票据编号")?,
        admin_session_id: row_get(&row, "admin_session_id", "读取云存储上传票据会话")?,
        provider: row_get(&row, "provider", "读取云存储上传票据来源")?,
        expected_sha256: row_get(&row, "expected_sha256", "读取云存储上传票据 SHA256")?,
        expected_size: row_get(&row, "expected_size", "读取云存储上传票据大小")?,
        original_name: row_get(&row, "original_name", "读取云存储上传票据文件名")?,
        mime_type: row_get(&row, "mime_type", "读取云存储上传票据 MIME")?,
        remark: row_get(&row, "remark", "读取云存储上传票据备注")?,
        status: row_get(&row, "status", "读取云存储上传票据状态")?,
        expires_at: row_get(&row, "expires_at", "读取云存储上传票据过期时间")?,
    })
}

fn app_row(row: sqlx::mysql::MySqlRow) -> Result<AppRow, AppError> {
    Ok(AppRow {
        id: row_get(&row, "id", "读取应用编号")?,
        app_code: row_get(&row, "app_code", "读取应用代码")?,
        api_token: row_get(&row, "api_token", "读取应用请求 Token")?,
        name: row_get(&row, "name", "读取应用名称")?,
        status: row_get(&row, "status", "读取应用状态")?,
        max_devices: row_get(&row, "max_devices", "读取默认设备上限")?,
        heartbeat_interval: row_get(&row, "heartbeat_interval", "读取会话过期秒数")?,
        heartbeat_enabled: row_get(&row, "heartbeat_enabled", "读取心跳开关")?,
        verification_enabled: row_get(&row, "verification_enabled", "读取验证开关")?,
        device_binding_enabled: row_get(&row, "device_binding_enabled", "读取设备绑定开关")?,
        shared_cards_enabled: row_get(&row, "shared_cards_enabled", "读取共享卡开关")?,
        login_ip_binding_enabled: row_get(
            &row,
            "login_ip_binding_enabled",
            "读取登录 IP 绑定开关",
        )?,
        web_card_query_enabled: row_get(&row, "web_card_query_enabled", "读取网页查卡开关")?,
        unbind_interval_seconds: row_get(&row, "unbind_interval_seconds", "读取解绑冷却秒数")?,
        unbind_deduct_seconds: row_get(&row, "unbind_deduct_seconds", "读取解绑扣时秒数")?,
        unbind_deduct_uses: row_get(&row, "unbind_deduct_uses", "读取解绑扣次数")?,
        api_success_code: row_get(&row, "api_success_code", "读取成功状态码")?,
        api_config_json: row_get(&row, "api_config_json", "读取接口配置")?,
        latest_version: row_get(&row, "latest_version", "读取最新版本")?,
        client_auth_mode: row_get(&row, "client_auth_mode", "读取客户端认证模式")?,
        client_crypto_alg: row_get(&row, "client_crypto_alg", "读取客户端加密算法")?,
        remark: row_get(&row, "remark", "读取应用备注")?,
        created_at: row_get(&row, "created_at", "读取应用创建时间")?,
        updated_at: row_get(&row, "updated_at", "读取应用更新时间")?,
        cards_total: row_get(&row, "cards_total", "读取卡密总数")?,
        devices_total: row_get(&row, "devices_total", "读取设备总数")?,
        sessions_active: row_get(&row, "sessions_active", "读取在线会话数")?,
    })
}

fn app_detail_row(row: sqlx::mysql::MySqlRow) -> Result<AppDetailRow, AppError> {
    Ok(AppDetailRow {
        id: row_get(&row, "id", "读取应用编号")?,
        app_code: row_get(&row, "app_code", "读取应用代码")?,
        api_token: row_get(&row, "api_token", "读取应用请求 Token")?,
        name: row_get(&row, "name", "读取应用名称")?,
        status: row_get(&row, "status", "读取应用状态")?,
        max_devices: row_get(&row, "max_devices", "读取默认设备上限")?,
        heartbeat_interval: row_get(&row, "heartbeat_interval", "读取会话过期秒数")?,
        heartbeat_enabled: row_get(&row, "heartbeat_enabled", "读取心跳开关")?,
        verification_enabled: row_get(&row, "verification_enabled", "读取验证开关")?,
        device_binding_enabled: row_get(&row, "device_binding_enabled", "读取设备绑定开关")?,
        shared_cards_enabled: row_get(&row, "shared_cards_enabled", "读取共享卡开关")?,
        login_ip_binding_enabled: row_get(
            &row,
            "login_ip_binding_enabled",
            "读取登录 IP 绑定开关",
        )?,
        web_card_query_enabled: row_get(&row, "web_card_query_enabled", "读取网页查卡开关")?,
        unbind_interval_seconds: row_get(&row, "unbind_interval_seconds", "读取解绑冷却秒数")?,
        unbind_deduct_seconds: row_get(&row, "unbind_deduct_seconds", "读取解绑扣时秒数")?,
        unbind_deduct_uses: row_get(&row, "unbind_deduct_uses", "读取解绑扣次数")?,
        api_success_code: row_get(&row, "api_success_code", "读取成功状态码")?,
        api_config_json: row_get(&row, "api_config_json", "读取接口配置")?,
        latest_version: row_get(&row, "latest_version", "读取最新版本")?,
        client_auth_mode: row_get(&row, "client_auth_mode", "读取客户端认证模式")?,
        client_crypto_alg: row_get(&row, "client_crypto_alg", "读取客户端加密算法")?,
        client_public_key: row_get(&row, "client_public_key", "读取客户端公钥")?,
        client_private_key_cipher: row_get(&row, "client_private_key_cipher", "读取客户端私钥")?,
        remark: row_get(&row, "remark", "读取应用备注")?,
        created_at: row_get(&row, "created_at", "读取应用创建时间")?,
        updated_at: row_get(&row, "updated_at", "读取应用更新时间")?,
    })
}

fn message_row(row: sqlx::mysql::MySqlRow) -> Result<MessageRow, AppError> {
    Ok(MessageRow {
        id: row_get(&row, "id", "读取消息编号")?,
        app_id: row_get(&row, "app_id", "读取消息应用编号")?,
        report_id: row_get(&row, "report_id", "读取消息上报编号")?,
        session_id: row_get(&row, "session_id", "读取消息会话编号")?,
        device_id: row_get(&row, "device_id", "读取消息设备编号")?,
        card_id: row_get(&row, "card_id", "读取消息卡密编号")?,
        message_type: row_get(&row, "message_type", "读取消息类型")?,
        severity: row_get(&row, "severity", "读取消息严重级别")?,
        status: row_get(&row, "status", "读取消息状态")?,
        title: row_get(&row, "title", "读取消息标题")?,
        summary: row_get(&row, "summary", "读取消息摘要")?,
        action: row_get(&row, "action", "读取消息处置动作")?,
        action_source: row_get(&row, "action_source", "读取消息处置来源")?,
        risk_score: row_get(&row, "risk_score", "读取消息风险分")?,
        handled_by: row_get(&row, "handled_by", "读取消息处理人")?,
        read_at: row_get(&row, "read_at", "读取消息已读时间")?,
        handled_at: row_get(&row, "handled_at", "读取消息处理时间")?,
        archived_at: row_get(&row, "archived_at", "读取消息归档时间")?,
        created_at: row_get(&row, "created_at", "读取消息创建时间")?,
        event_id: row_get(&row, "event_id", "读取安全事件编号")?,
        event_type: row_get(&row, "event_type", "读取安全事件类型")?,
        risk_level: row_get(&row, "risk_level", "读取安全风险等级")?,
        confidence: row_get(&row, "confidence", "读取安全事件置信度")?,
        requested_action: row_get(&row, "requested_action", "读取客户端请求动作")?,
        action_reason: row_get(&row, "action_reason", "读取安全动作原因")?,
        report_message: row_get(&row, "report_message", "读取安全上报正文")?,
        evidence_json: row_get(&row, "evidence_json", "读取安全证据")?,
        attestation_json: row_get(&row, "attestation_json", "读取安全证明")?,
        card_hash: row_get(&row, "card_hash", "读取安全上报卡密哈希")?,
        card_fingerprint: row_get(&row, "card_fingerprint", "读取安全上报卡密指纹")?,
        install_id: row_get(&row, "install_id", "读取安全上报安装标识")?,
        sdk_version: row_get(&row, "sdk_version", "读取 SDK 版本")?,
        detector_version: row_get(&row, "detector_version", "读取检测器版本")?,
        platform: row_get(&row, "platform", "读取安全上报平台")?,
        ip: row_get(&row, "ip", "读取安全上报 IP")?,
        occurred_at: row_get(&row, "occurred_at", "读取安全上报发生时间")?,
    })
}

fn message_action_row(row: sqlx::mysql::MySqlRow) -> Result<MessageActionRow, AppError> {
    Ok(MessageActionRow {
        id: row_get(&row, "id", "读取消息动作编号")?,
        action: row_get(&row, "action", "读取消息动作")?,
        actor_type: row_get(&row, "actor_type", "读取消息动作发起类型")?,
        actor_name: row_get(&row, "actor_name", "读取消息动作发起人")?,
        result: row_get(&row, "result", "读取消息动作结果")?,
        remark: row_get(&row, "remark", "读取消息动作备注")?,
        ip: row_get(&row, "ip", "读取消息动作 IP")?,
        created_at: row_get(&row, "created_at", "读取消息动作时间")?,
    })
}

fn message_audit_row(row: sqlx::mysql::MySqlRow) -> Result<MessageAuditRow, AppError> {
    Ok(MessageAuditRow {
        id: row_get(&row, "id", "读取消息审计编号")?,
        action: row_get(&row, "action", "读取消息审计动作")?,
        message: row_get(&row, "message", "读取消息审计内容")?,
        ip: row_get(&row, "ip", "读取消息审计 IP")?,
        created_at: row_get(&row, "created_at", "读取消息审计时间")?,
    })
}

fn audit_log_row(row: sqlx::mysql::MySqlRow) -> Result<AuditLogRow, AppError> {
    Ok(AuditLogRow {
        id: row_get(&row, "id", "读取审计日志编号")?,
        app_id: row_get(&row, "app_id", "读取审计日志应用编号")?,
        account_id: row_get(&row, "account_id", "读取审计日志账号编号")?,
        action: row_get(&row, "action", "读取审计动作")?,
        message: row_get(&row, "message", "读取审计消息")?,
        ip: row_get(&row, "ip", "读取审计 IP")?,
        region: row_get(&row, "region", "读取审计地区")?,
        created_at: row_get(&row, "created_at", "读取审计时间")?,
    })
}

fn card_row(row: sqlx::mysql::MySqlRow) -> Result<CardRow, AppError> {
    Ok(CardRow {
        id: row_get(&row, "id", "读取卡密编号")?,
        app_id: row_get(&row, "app_id", "读取卡密应用编号")?,
        card_hash: row_get(&row, "card_hash", "读取卡密哈希")?,
        card_cipher: row_get(&row, "card_cipher", "读取卡密密文")?,
        card_fingerprint: row_get(&row, "card_fingerprint", "读取卡密指纹")?,
        card_type: row_get(&row, "card_type", "读取卡密类型")?,
        duration_seconds: row_get(&row, "duration_seconds", "读取卡密时长")?,
        total_uses: row_get(&row, "total_uses", "读取卡密总次数")?,
        remaining_uses: row_get(&row, "remaining_uses", "读取卡密剩余次数")?,
        max_devices: row_get(&row, "max_devices", "读取卡密设备上限")?,
        card_structure: row_get(&row, "card_structure", "读取卡密结构")?,
        prefix: row_get(&row, "prefix", "读取卡密前缀")?,
        unbind_limit: row_get(&row, "unbind_limit", "读取解绑上限")?,
        unbind_count: row_get(&row, "unbind_count", "读取解绑次数")?,
        last_unbound_at: row_get(&row, "last_unbound_at", "读取最近解绑时间")?,
        status: row_get(&row, "status", "读取卡密状态")?,
        used_account_id: row_get(&row, "used_account_id", "读取使用账号")?,
        used_at: row_get(&row, "used_at", "读取使用时间")?,
        created_at: row_get(&row, "created_at", "读取卡密创建时间")?,
        online_count: row_get(&row, "online_count", "读取在线数量")?,
        login_ips: row_get(&row, "login_ips", "读取登录 IP")?,
        device_count: row_get(&row, "device_count", "读取设备数量")?,
    })
}

fn device_row(row: sqlx::mysql::MySqlRow) -> Result<DeviceRow, AppError> {
    Ok(DeviceRow {
        id: row_get(&row, "id", "读取设备编号")?,
        app_id: row_get(&row, "app_id", "读取设备应用编号")?,
        account_id: row_get(&row, "account_id", "读取设备账号编号")?,
        card_id: row_get(&row, "card_id", "读取设备卡密编号")?,
        card_fingerprint: row_get(&row, "card_fingerprint", "读取设备卡密指纹")?,
        device_hash: row_get(&row, "device_hash", "读取设备哈希")?,
        install_id: row_get(&row, "install_id", "读取安装标识")?,
        machine_profile_hash: row_get(&row, "machine_profile_hash", "读取设备摘要")?,
        bind_ip: row_get(&row, "bind_ip", "读取绑定 IP")?,
        bind_region: row_get(&row, "bind_region", "读取绑定地区")?,
        device_name: row_get(&row, "device_name", "读取设备名称")?,
        status: row_get(&row, "status", "读取设备状态")?,
        first_seen_at: row_get(&row, "first_seen_at", "读取首次出现时间")?,
        last_seen_at: row_get(&row, "last_seen_at", "读取最近出现时间")?,
    })
}

fn client_login_device_row(row: sqlx::mysql::MySqlRow) -> Result<ClientLoginDeviceRow, AppError> {
    Ok(ClientLoginDeviceRow {
        id: row_get(&row, "id", "读取客户端设备编号")?,
        app_id: row_get(&row, "app_id", "读取客户端设备应用")?,
        account_id: row_get(&row, "account_id", "读取客户端设备账号")?,
        card_id: row_get(&row, "card_id", "读取客户端设备卡密")?,
        card_hash: row_get(&row, "card_hash", "读取客户端设备卡密哈希")?,
        device_hash: row_get(&row, "device_hash", "读取客户端设备哈希")?,
        device_name: row_get(&row, "device_name", "读取客户端设备名称")?,
        install_id: row_get(&row, "install_id", "读取客户端安装标识")?,
        device_public_key: row_get(&row, "device_public_key", "读取客户端设备公钥")?,
        device_key_alg: row_get(&row, "device_key_alg", "读取客户端设备密钥模式")?,
        machine_profile_hash: row_get(&row, "machine_profile_hash", "读取客户端设备摘要")?,
        bind_ip: row_get(&row, "bind_ip", "读取客户端设备绑定 IP")?,
        bind_region: row_get(&row, "bind_region", "读取客户端设备绑定地区")?,
        risk_level: row_get(&row, "risk_level", "读取客户端设备风险等级")?,
        status: row_get(&row, "status", "读取客户端设备状态")?,
        first_seen_at: row_get(&row, "first_seen_at", "读取客户端设备首次出现")?,
        last_seen_at: row_get(&row, "last_seen_at", "读取客户端设备最近出现")?,
    })
}

fn client_active_session_row(
    row: sqlx::mysql::MySqlRow,
) -> Result<ClientLoginActiveSession, AppError> {
    Ok(ClientLoginActiveSession {
        id: row_get(&row, "id", "读取客户端会话编号")?,
        device_id: row_get(&row, "device_id", "读取客户端会话设备")?,
    })
}

fn client_unbind_device_row(row: sqlx::mysql::MySqlRow) -> Result<ClientUnbindDeviceRow, AppError> {
    Ok(ClientUnbindDeviceRow {
        id: row_get(&row, "id", "读取客户端解绑设备编号")?,
        device_public_key: row_get(&row, "device_public_key", "读取客户端解绑设备公钥")?,
    })
}

fn client_session_row(row: sqlx::mysql::MySqlRow) -> Result<ClientSessionRow, AppError> {
    Ok(ClientSessionRow {
        id: row_get(&row, "id", "读取客户端会话编号")?,
        app_id: row_get(&row, "app_id", "读取客户端会话应用")?,
        device_id: row_get(&row, "device_id", "读取客户端会话设备")?,
        card_id: row_get(&row, "card_id", "读取客户端会话卡密")?,
        card_hash: row_get(&row, "card_hash", "读取客户端会话卡密哈希")?,
        card_fingerprint: row_get(&row, "card_fingerprint", "读取客户端会话卡密指纹")?,
        token_hash: row_get(&row, "token_hash", "读取客户端会话令牌摘要")?,
        request_counter: row_get(&row, "request_counter", "读取客户端会话计数器")?,
        proof_mode: row_get(&row, "proof_mode", "读取客户端会话证明模式")?,
        ticket_hash: row_get(&row, "ticket_hash", "读取客户端会话票据摘要")?,
        ticket_expires_at: row_get(&row, "ticket_expires_at", "读取客户端会话票据过期时间")?,
        status: row_get(&row, "status", "读取客户端会话状态")?,
        expires_at: row_get(&row, "expires_at", "读取客户端会话过期时间")?,
        device_status: row_get(&row, "device_status", "读取客户端会话设备状态")?,
        install_id: row_get(&row, "install_id", "读取客户端会话安装标识")?,
        device_public_key: row_get(&row, "device_public_key", "读取客户端会话设备公钥")?,
        device_key_alg: row_get(&row, "device_key_alg", "读取客户端会话设备密钥模式")?,
        device_last_seen_at: row_get(&row, "device_last_seen_at", "读取客户端会话设备活跃时间")?,
        card_status: row_get(&row, "card_status", "读取客户端会话卡密状态")?,
        stored_card_hash: row_get(&row, "stored_card_hash", "读取客户端会话存储卡密哈希")?,
        stored_card_fingerprint: row_get(
            &row,
            "stored_card_fingerprint",
            "读取客户端会话存储卡密指纹",
        )?,
        stored_card_type: row_get(&row, "stored_card_type", "读取客户端会话存储卡密类型")?,
        stored_card_duration_seconds: row_get(
            &row,
            "stored_card_duration_seconds",
            "读取客户端会话存储卡密时长",
        )?,
        stored_card_remaining_uses: row_get(
            &row,
            "stored_card_remaining_uses",
            "读取客户端会话存储卡密剩余次数",
        )?,
        stored_card_max_devices: row_get(
            &row,
            "stored_card_max_devices",
            "读取客户端会话存储卡密设备上限",
        )?,
        stored_card_used_at: row_get(&row, "stored_card_used_at", "读取客户端会话卡密使用时间")?,
    })
}

fn account_row(row: sqlx::mysql::MySqlRow) -> Result<AccountRow, AppError> {
    Ok(AccountRow {
        id: row_get(&row, "id", "读取账号编号")?,
        app_id: row_get(&row, "app_id", "读取账号应用编号")?,
        username: row_get(&row, "username", "读取账号名称")?,
        status: row_get(&row, "status", "读取账号状态")?,
        expires_at: row_get(&row, "expires_at", "读取账号到期时间")?,
        max_devices: row_get(&row, "max_devices", "读取账号设备上限")?,
        created_at: row_get(&row, "created_at", "读取账号创建时间")?,
        updated_at: row_get(&row, "updated_at", "读取账号更新时间")?,
    })
}

fn security_policy_row(row: sqlx::mysql::MySqlRow) -> Result<SecurityPolicyRow, AppError> {
    Ok(SecurityPolicyRow {
        app_id: row_get(&row, "app_id", "读取安全策略应用编号")?,
        enabled: row_get(&row, "enabled", "读取安全策略状态")?,
        mode: row_get(&row, "mode", "读取安全策略模式")?,
        min_confidence_for_client_action: row_get(
            &row,
            "min_confidence_for_client_action",
            "读取安全策略最低置信度",
        )?,
        max_client_action: row_get(&row, "max_client_action", "读取客户端最大动作")?,
        kick_score: row_get(&row, "kick_score", "读取踢下线分数")?,
        disable_device_score: row_get(&row, "disable_device_score", "读取禁用设备分数")?,
        disable_card_score: row_get(&row, "disable_card_score", "读取禁用卡密分数")?,
        allowed_client_actions: row_get(&row, "allowed_client_actions", "读取客户端允许动作")?,
        client_disable_device_min_score: row_get(
            &row,
            "client_disable_device_min_score",
            "读取客户端禁用设备分数",
        )?,
        client_disable_card_min_score: row_get(
            &row,
            "client_disable_card_min_score",
            "读取客户端禁用卡密分数",
        )?,
        report_rate_limit_per_minute: row_get(
            &row,
            "report_rate_limit_per_minute",
            "读取安全上报限速",
        )?,
        report_retention_days: row_get(&row, "report_retention_days", "读取安全上报保留天数")?,
        message_retention_days: row_get(&row, "message_retention_days", "读取消息保留天数")?,
        server_critical_action: row_get(&row, "server_critical_action", "读取严重风险动作")?,
        server_high_action: row_get(&row, "server_high_action", "读取高风险动作")?,
        server_medium_action: row_get(&row, "server_medium_action", "读取中风险动作")?,
        server_low_action: row_get(&row, "server_low_action", "读取低风险动作")?,
        trusted_event_types_json: row_get(&row, "trusted_event_types_json", "读取可信事件类型")?,
        updated_by: row_get(&row, "updated_by", "读取安全策略更新人")?,
        updated_at: row_get(&row, "updated_at", "读取安全策略更新时间")?,
    })
}

fn client_security_report_row(
    row: sqlx::mysql::MySqlRow,
) -> Result<ClientSecurityReportRow, AppError> {
    Ok(ClientSecurityReportRow {
        id: row_get(&row, "id", "读取安全上报编号")?,
        requested_action: row_get(&row, "requested_action", "读取安全上报请求动作")?,
        action: row_get(&row, "action", "读取安全上报动作")?,
        action_source: row_get(&row, "action_source", "读取安全上报动作来源")?,
        risk_score: row_get(&row, "risk_score", "读取安全上报风险分")?,
    })
}

fn client_security_message_row(
    row: sqlx::mysql::MySqlRow,
) -> Result<ClientSecurityMessageRow, AppError> {
    Ok(ClientSecurityMessageRow {
        id: row_get(&row, "id", "读取安全上报消息编号")?,
    })
}

async fn clear_app_device_bind_ips_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    app_id: u64,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE `auth_devices` SET `bind_ip` = '', `bind_region` = '' \
         WHERE `app_id` = ? AND (`bind_ip` <> '' OR `bind_region` <> '')",
    )
    .bind(app_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::DatabaseQueryFailed("清理应用设备绑定 IP"))?;
    Ok(())
}

async fn delete_app_rows_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    table_name: &str,
    app_ids: &[u64],
) -> Result<u64, AppError> {
    let mut builder = QueryBuilder::<MySql>::new("DELETE FROM `");
    builder.push(table_name).push("` WHERE `app_id` IN (");
    push_id_bindings(&mut builder, app_ids);
    builder.push(")");
    let result = builder
        .build()
        .execute(&mut **transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("删除应用依赖数据"))?;
    Ok(result.rows_affected())
}

async fn insert_card_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    card: &NewCard,
) -> Result<u64, AppError> {
    let result = sqlx::query(
        "INSERT INTO `auth_cards` \
         (`app_id`, `card_hash`, `card_cipher`, `card_fingerprint`, `card_type`, \
         `duration_seconds`, `total_uses`, `remaining_uses`, `max_devices`, \
         `card_structure`, `prefix`, `unbind_limit`, `status`) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(card.app_id)
    .bind(&card.card_hash)
    .bind(&card.card_cipher)
    .bind(&card.card_fingerprint)
    .bind(&card.card_type)
    .bind(card.duration_seconds)
    .bind(card.total_uses)
    .bind(card.remaining_uses)
    .bind(card.max_devices)
    .bind(&card.card_structure)
    .bind(&card.prefix)
    .bind(card.unbind_limit)
    .bind(card.status)
    .execute(&mut **transaction)
    .await;

    match result {
        Ok(result) => Ok(result.last_insert_id()),
        Err(error) if is_duplicate_or_constraint_error(&error) => {
            Err(AppError::InvalidInput("卡密已存在"))
        }
        Err(_) => Err(AppError::DatabaseQueryFailed("写入卡密")),
    }
}

async fn insert_remote_variable_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    variable: &RemoteVariableInput,
) -> Result<u64, AppError> {
    let result = sqlx::query(
        "INSERT INTO `auth_remote_variables` (`name`, `value`, `scope`, `status`) \
         VALUES (?, ?, ?, ?)",
    )
    .bind(&variable.name)
    .bind(&variable.value)
    .bind(&variable.scope)
    .bind(variable.status)
    .execute(&mut **transaction)
    .await;

    match result {
        Ok(result) => Ok(result.last_insert_id()),
        Err(error) if is_duplicate_or_constraint_error(&error) => {
            Err(AppError::DuplicateVariable(variable.name.clone()))
        }
        Err(_) => Err(AppError::DatabaseQueryFailed("写入远程变量")),
    }
}

async fn update_remote_variable_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    variable_id: u64,
    variable: &RemoteVariableInput,
) -> Result<(), AppError> {
    let result = sqlx::query(
        "UPDATE `auth_remote_variables` SET `name` = ?, `value` = ?, `scope` = ?, `status` = ? \
         WHERE `id` = ?",
    )
    .bind(&variable.name)
    .bind(&variable.value)
    .bind(&variable.scope)
    .bind(variable.status)
    .bind(variable_id)
    .execute(&mut **transaction)
    .await;

    match result {
        Ok(_) => Ok(()),
        Err(error) if is_duplicate_or_constraint_error(&error) => {
            Err(AppError::DuplicateVariable(variable.name.clone()))
        }
        Err(_) => Err(AppError::DatabaseQueryFailed("更新远程变量")),
    }
}

async fn replace_remote_variable_apps_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    variable_id: u64,
    app_ids: &[u64],
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM `auth_remote_variable_apps` WHERE `variable_id` = ?")
        .bind(variable_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("清理远程变量授权应用"))?;
    for chunk in app_ids.chunks(200) {
        insert_remote_variable_app_chunk(transaction, variable_id, chunk).await?;
    }
    Ok(())
}

async fn insert_remote_variable_app_chunk(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    variable_id: u64,
    app_ids: &[u64],
) -> Result<(), AppError> {
    if app_ids.is_empty() {
        return Ok(());
    }
    let mut builder = QueryBuilder::<MySql>::new(
        "INSERT IGNORE INTO `auth_remote_variable_apps` (`variable_id`, `app_id`) ",
    );
    builder.push_values(app_ids, |mut values, app_id| {
        values.push_bind(variable_id).push_bind(*app_id);
    });
    builder
        .build()
        .execute(&mut **transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("写入远程变量授权应用"))?;
    Ok(())
}

async fn delete_remote_variable_apps_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    variable_ids: &[u64],
) -> Result<(), AppError> {
    let mut builder = QueryBuilder::<MySql>::new(
        "DELETE FROM `auth_remote_variable_apps` WHERE `variable_id` IN (",
    );
    push_id_bindings(&mut builder, variable_ids);
    builder.push(")");
    builder
        .build()
        .execute(&mut **transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("批量删除远程变量授权应用"))?;
    Ok(())
}

async fn replace_card_search_tokens_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    app_id: u64,
    card_id: u64,
    token_hashes: &[String],
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM `auth_card_search_tokens` WHERE `app_id` = ? AND `card_id` = ?")
        .bind(app_id)
        .bind(card_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("清理卡密搜索索引"))?;
    for chunk in valid_token_hashes(token_hashes).chunks(200) {
        insert_card_search_token_chunk(transaction, app_id, card_id, chunk).await?;
    }
    Ok(())
}

async fn insert_card_search_token_chunk(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    app_id: u64,
    card_id: u64,
    token_hashes: &[String],
) -> Result<(), AppError> {
    if token_hashes.is_empty() {
        return Ok(());
    }
    let mut builder = QueryBuilder::<MySql>::new(
        "INSERT IGNORE INTO `auth_card_search_tokens` (`app_id`, `card_id`, `token_hash`) ",
    );
    builder.push_values(token_hashes, |mut values, token_hash| {
        values
            .push_bind(app_id)
            .push_bind(card_id)
            .push_bind(token_hash);
    });
    builder
        .build()
        .execute(&mut **transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("写入卡密搜索索引"))?;
    Ok(())
}

fn valid_token_hashes(token_hashes: &[String]) -> Vec<String> {
    let mut hashes = token_hashes
        .iter()
        .filter(|value| is_lower_hex_hash(value))
        .cloned()
        .collect::<Vec<_>>();
    hashes.sort();
    hashes.dedup();
    hashes
}

fn is_lower_hex_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn push_id_bindings(builder: &mut QueryBuilder<'_, MySql>, ids: &[u64]) {
    for (index, id) in ids.iter().enumerate() {
        if index > 0 {
            builder.push(", ");
        }
        builder.push_bind(*id);
    }
}

fn push_message_filter(
    builder: &mut QueryBuilder<'_, MySql>,
    column_sql: &'static str,
    value: &str,
) {
    if value.is_empty() {
        return;
    }
    builder.push(" AND ").push(column_sql).push(" = ");
    builder.push_bind(value.to_string());
}

fn push_security_report_count_filters(
    builder: &mut QueryBuilder<'_, MySql>,
    filters: &SecurityReportCountFilters,
) {
    if let Some(session_id) = filters.session_id {
        builder.push(" AND `session_id` = ").push_bind(session_id);
    }
    if let Some(card_id) = filters.card_id {
        builder.push(" AND `card_id` = ").push_bind(card_id);
    }
    if !filters.card_hash.is_empty() {
        builder
            .push(" AND `card_hash` = ")
            .push_bind(filters.card_hash.clone());
    }
    if let Some(device_id) = filters.device_id {
        builder.push(" AND `device_id` = ").push_bind(device_id);
    }
    if !filters.ip.is_empty() {
        builder.push(" AND `ip` = ").push_bind(filters.ip.clone());
    }
    if !filters.event_type.is_empty() {
        builder
            .push(" AND `event_type` = ")
            .push_bind(filters.event_type.clone());
    }
    if let Some(since) = filters.since {
        builder.push(" AND `created_at` >= ").push_bind(since);
    }
    if !filters.risk_levels.is_empty() {
        builder.push(" AND `risk_level` IN (");
        push_string_bindings(builder, &filters.risk_levels);
        builder.push(")");
    }
}

fn push_card_filters(builder: &mut QueryBuilder<'_, MySql>, app_id: u64, query: &CardQuery) {
    builder.push("c.`app_id` = ").push_bind(app_id);
    push_card_status_filter(builder, &query.status);
    push_card_duration_filter(builder, &query.duration_category);
    push_card_keyword_filter(builder, app_id, query);
}

fn push_remote_variable_filters(
    builder: &mut QueryBuilder<'_, MySql>,
    filters: &RemoteVariableFilters,
) {
    builder.push("1 = 1");
    if !filters.keyword.is_empty() {
        builder.push(" AND v.`name` LIKE ");
        builder.push_bind(format!("%{}%", escape_like(&filters.keyword)));
    }
    if !filters.scope.is_empty() {
        builder.push(" AND v.`scope` = ");
        builder.push_bind(filters.scope.clone());
    }
    if let Some(status) = filters.status {
        builder.push(" AND v.`status` = ");
        builder.push_bind(status);
    }
    if let Some(app_id) = filters.app_id {
        builder.push(" AND (v.`scope` = 'public' OR EXISTS (SELECT 1 FROM `auth_remote_variable_apps` vf WHERE vf.`variable_id` = v.`id` AND vf.`app_id` = ");
        builder.push_bind(app_id);
        builder.push("))");
    }
}

fn push_remote_api_token_filters(
    builder: &mut QueryBuilder<'_, MySql>,
    filters: &RemoteApiTokenFilters,
) {
    builder.push("1 = 1");
    if !filters.keyword.is_empty() {
        let like_keyword = format!("%{}%", escape_like(&filters.keyword));
        builder.push(" AND (`name` LIKE ");
        builder.push_bind(like_keyword.clone());
        builder.push(" OR `access_key` LIKE ");
        builder.push_bind(like_keyword);
        builder.push(")");
    }
    if let Some(status) = filters.status {
        builder.push(" AND `status` = ");
        builder.push_bind(status);
    }
}

fn push_remote_api_log_filters(
    builder: &mut QueryBuilder<'_, MySql>,
    filters: &RemoteApiLogFilters,
) {
    builder.push("1 = 1");
    if let Some(token_id) = filters.token_id {
        builder.push(" AND l.`token_id` = ");
        builder.push_bind(token_id);
    }
    if let Some(target_app_id) = filters.target_app_id {
        builder.push(" AND l.`target_app_id` = ");
        builder.push_bind(target_app_id);
    }
    push_remote_api_log_text_filters(builder, filters);
    if let Some(start) = filters.start {
        builder.push(" AND l.`created_at` >= ");
        builder.push_bind(start);
    }
    if let Some(end) = filters.end {
        builder.push(" AND l.`created_at` <= ");
        builder.push_bind(end);
    }
}

fn push_remote_api_log_text_filters(
    builder: &mut QueryBuilder<'_, MySql>,
    filters: &RemoteApiLogFilters,
) {
    if !filters.route.is_empty() {
        builder.push(" AND l.`route` = ");
        builder.push_bind(filters.route.clone());
    }
    if !filters.status.is_empty() {
        builder.push(" AND l.`status` = ");
        builder.push_bind(filters.status.clone());
    }
    if !filters.keyword.is_empty() {
        let like_keyword = format!("%{}%", escape_like(&filters.keyword));
        builder.push(" AND (l.`access_key` LIKE ");
        builder.push_bind(like_keyword.clone());
        builder.push(" OR l.`message` LIKE ");
        builder.push_bind(like_keyword.clone());
        builder.push(" OR t.`name` LIKE ");
        builder.push_bind(like_keyword);
        builder.push(")");
    }
}

fn push_cloud_file_filters(builder: &mut QueryBuilder<'_, MySql>, filters: &CloudFileFilters) {
    builder.push("1 = 1");
    if !filters.provider.is_empty() {
        builder.push(" AND f.`provider` = ");
        builder.push_bind(filters.provider.clone());
    }
    if !filters.status.is_empty() {
        builder.push(" AND f.`status` = ");
        builder.push_bind(filters.status.clone());
    }
    if !filters.keyword.is_empty() {
        let like_keyword = format!("%{}%", escape_like(&filters.keyword));
        builder.push(" AND (f.`original_name` LIKE ");
        builder.push_bind(like_keyword.clone());
        builder.push(" OR f.`file_key` LIKE ");
        builder.push_bind(like_keyword.clone());
        builder.push(" OR f.`sha256` LIKE ");
        builder.push_bind(like_keyword);
        builder.push(")");
    }
    if !filters.start.is_empty() {
        builder.push(" AND f.`created_at` >= ");
        builder.push_bind(filters.start.clone());
    }
    if !filters.end.is_empty() {
        builder.push(" AND f.`created_at` <= ");
        builder.push_bind(filters.end.clone());
    }
}

fn push_activated_range_filter(
    builder: &mut QueryBuilder<'_, MySql>,
    app_id: u64,
    activated_start: NaiveDateTime,
    activated_end: NaiveDateTime,
    card_type: &str,
) {
    builder
        .push("`app_id` = ")
        .push_bind(app_id)
        .push(" AND `used_at` IS NOT NULL AND `used_at` >= ")
        .push_bind(activated_start)
        .push(" AND `used_at` <= ")
        .push_bind(activated_end);
    if !card_type.is_empty() {
        builder
            .push(" AND `card_type` = ")
            .push_bind(card_type.to_string());
    }
}

fn push_card_status_filter(builder: &mut QueryBuilder<'_, MySql>, status: &str) {
    match status {
        "active" => {
            builder.push(" AND c.`status` = 1 AND (c.`card_type` IN ('permanent', 'count') ");
            builder.push("OR (c.`used_at` IS NOT NULL AND DATE_ADD(c.`used_at`, INTERVAL c.`duration_seconds` SECOND) >= NOW()))");
        }
        "expired" => {
            builder.push(
                " AND c.`status` = 1 AND c.`card_type` = 'time' AND c.`used_at` IS NOT NULL ",
            );
            builder.push("AND DATE_ADD(c.`used_at`, INTERVAL c.`duration_seconds` SECOND) < NOW()");
        }
        "" => {}
        _ => {
            if let Ok(value) = status.parse::<i64>() {
                builder.push(" AND c.`status` = ").push_bind(value);
            }
        }
    }
}

fn push_card_duration_filter(builder: &mut QueryBuilder<'_, MySql>, duration_category: &str) {
    match duration_category {
        "custom" => {
            builder.push(" AND c.`card_type` = 'time' AND c.`duration_seconds` NOT IN ");
            builder.push("(86400, 604800, 2592000, 7776000, 31536000)");
        }
        "day" | "week" | "month" | "season" | "year" => {
            builder
                .push(" AND c.`card_type` = 'time' AND c.`duration_seconds` = ")
                .push_bind(duration_category_seconds(duration_category));
        }
        _ => {}
    }
}

fn push_card_keyword_filter(builder: &mut QueryBuilder<'_, MySql>, app_id: u64, query: &CardQuery) {
    if query.keyword.is_empty() {
        return;
    }
    let like_keyword = format!("%{}%", escape_like(&query.keyword));
    builder.push(" AND (CAST(c.`id` AS CHAR) LIKE ");
    builder.push_bind(like_keyword.clone());
    builder.push(" OR c.`card_fingerprint` LIKE ");
    builder.push_bind(like_keyword);
    if !query.card_hash.is_empty() {
        builder.push(" OR c.`card_hash` = ");
        builder.push_bind(query.card_hash.clone());
    }
    if !query.search_token_hashes.is_empty() {
        builder.push(" OR c.`id` IN (SELECT `card_id` FROM `auth_card_search_tokens` ");
        builder.push("WHERE `app_id` = ");
        builder.push_bind(app_id);
        builder.push(" AND `token_hash` IN (");
        push_string_bindings(builder, &query.search_token_hashes);
        builder.push(") GROUP BY `card_id` HAVING COUNT(DISTINCT `token_hash`) = ");
        builder.push_bind(query.search_token_hashes.len() as i64);
        builder.push(")");
    }
    builder.push(")");
}

fn push_string_bindings(builder: &mut QueryBuilder<'_, MySql>, values: &[String]) {
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            builder.push(", ");
        }
        builder.push_bind(value.clone());
    }
}

fn duration_category_seconds(duration_category: &str) -> i64 {
    match duration_category {
        "day" => 86_400,
        "week" => 604_800,
        "month" => 2_592_000,
        "season" => 7_776_000,
        "year" => 31_536_000,
        _ => 0,
    }
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

async fn resolve_client_login_card(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    command: &ClientLoginCommand,
) -> Result<ClientLoginCard, AppError> {
    if !command.verification_enabled {
        return Ok(client_virtual_login_card(command));
    }
    let card = find_client_login_card_for_update(transaction, command).await?;
    let card = client_login_card_from_row(card, &command.card_hash, command.now);
    if card.first_use {
        mark_client_login_card_used(transaction, card.id, command.now).await?;
    }
    if is_client_count_card(&card) && card.remaining_uses <= 0 {
        return Err(AppError::CardExhausted);
    }
    if card.expires_at < command.now {
        return Err(AppError::CardExpired);
    }
    Ok(card)
}

async fn reserve_client_login_challenge(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    command: &ClientLoginCommand,
) -> Result<(), AppError> {
    let Some(nonce_hash) = command.challenge_nonce_hash.as_deref() else {
        return Ok(());
    };
    let Some(expires_at) = command.challenge_expires_at else {
        return Err(AppError::DatabaseQueryFailed("登记客户端登录挑战"));
    };
    let result = sqlx::query(
        "INSERT INTO `auth_nonces` (`app_id`, `nonce_hash`, `expires_at`) VALUES (?, ?, ?)",
    )
    .bind(command.app_id)
    .bind(nonce_hash)
    .bind(expires_at)
    .execute(&mut **transaction)
    .await;
    match result {
        Ok(_) => Ok(()),
        Err(error) if is_duplicate_or_constraint_error(&error) => {
            Err(AppError::LoginChallengeInvalid("登录挑战已失效"))
        }
        Err(_) => Err(AppError::DatabaseQueryFailed("登记客户端登录挑战")),
    }
}

async fn find_client_login_card_for_update(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    command: &ClientLoginCommand,
) -> Result<CardRow, AppError> {
    let query = format!("{CARD_BY_HASH_SQL} FOR UPDATE");
    let row = sqlx::query(&query)
        .bind(command.app_id)
        .bind(&command.card_hash)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("锁定客户端登录卡密"))?;
    match row.map(card_row).transpose()? {
        Some(card) if card.status != 2 => Ok(card),
        _ => Err(AppError::CardInvalid),
    }
}

async fn find_client_unbind_card_for_update(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    command: &ClientUnbindCommand,
) -> Result<CardRow, AppError> {
    let query = format!("{CARD_BY_HASH_SQL} FOR UPDATE");
    let row = sqlx::query(&query)
        .bind(command.app_id)
        .bind(&command.card_hash)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("锁定客户端解绑卡密"))?;
    let Some(card) = row.map(card_row).transpose()? else {
        return Err(AppError::CardInvalid);
    };
    if card.status == 2 {
        return Err(AppError::CardInvalid);
    }
    let card_type = normalized_client_card_type(&card.card_type);
    let expires_at = client_card_expires_at(&card_type, card.used_at, card.duration_seconds);
    if expires_at < command.now {
        return Err(AppError::CardExpired);
    }
    Ok(card)
}

fn assert_client_unbind_allowed(
    card: &CardRow,
    command: &ClientUnbindCommand,
) -> Result<(), AppError> {
    if card.unbind_limit > 0 && card.unbind_count >= card.unbind_limit {
        return Err(AppError::UnbindLimitExceeded);
    }
    let interval = command.unbind_interval_seconds.max(0);
    if let Some(last_unbound_at) = card.last_unbound_at {
        if interval > 0 && last_unbound_at + chrono::Duration::seconds(interval) > command.now {
            return Err(AppError::UnbindCooldown);
        }
    }
    Ok(())
}

async fn delete_client_device_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    device_id: u64,
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM `auth_devices` WHERE `id` = ?")
        .bind(device_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("删除设备绑定"))?;
    Ok(())
}

async fn record_client_card_unbind_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    card: &CardRow,
    command: &ClientUnbindCommand,
) -> Result<(), AppError> {
    let card_type = normalized_client_card_type(&card.card_type);
    let duration_seconds = if card_type == "time" {
        (card.duration_seconds - command.unbind_deduct_seconds.max(0)).max(60)
    } else {
        card.duration_seconds
    };
    let remaining_uses = if card_type == "count" {
        (card.remaining_uses - command.unbind_deduct_uses.max(0)).max(0)
    } else {
        card.remaining_uses
    };
    sqlx::query(
        "UPDATE `auth_cards` SET `duration_seconds` = ?, `remaining_uses` = ?, \
         `unbind_count` = `unbind_count` + 1, `last_unbound_at` = ? WHERE `id` = ?",
    )
    .bind(duration_seconds)
    .bind(remaining_uses)
    .bind(command.now)
    .bind(card.id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::DatabaseQueryFailed("记录卡密解绑"))?;
    Ok(())
}

fn client_virtual_login_card(command: &ClientLoginCommand) -> ClientLoginCard {
    ClientLoginCard {
        id: None,
        card_hash: command.card_hash.clone(),
        card_fingerprint: visible_fingerprint(&command.card_key, 6, 4),
        card_type: "time".to_string(),
        expires_at: command.now + chrono::Duration::seconds(315_360_000),
        remaining_uses: 0,
        max_devices: i64::MAX,
        first_use: false,
    }
}

fn client_login_card_from_row(
    card: CardRow,
    card_hash: &str,
    now: NaiveDateTime,
) -> ClientLoginCard {
    let card_type = normalized_client_card_type(&card.card_type);
    let first_use = card.status == 0 || card.used_at.is_none();
    let used_at = if first_use { Some(now) } else { card.used_at };
    let expires_at = client_card_expires_at(&card_type, used_at, card.duration_seconds);
    ClientLoginCard {
        id: Some(card.id),
        card_hash: if card.card_hash.is_empty() {
            card_hash.to_string()
        } else {
            card.card_hash
        },
        card_fingerprint: if card.card_fingerprint.is_empty() {
            visible_fingerprint(card_hash, 8, 6)
        } else {
            card.card_fingerprint
        },
        card_type,
        expires_at,
        remaining_uses: card.remaining_uses,
        max_devices: card.max_devices,
        first_use,
    }
}

async fn mark_client_login_card_used(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    card_id: Option<u64>,
    used_at: NaiveDateTime,
) -> Result<(), AppError> {
    let Some(card_id) = card_id else {
        return Ok(());
    };
    sqlx::query(
        "UPDATE `auth_cards` SET `status` = 1, `used_account_id` = NULL, \
         `used_at` = IFNULL(`used_at`, ?) WHERE `id` = ? AND `status` <> 2",
    )
    .bind(used_at)
    .bind(card_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::DatabaseQueryFailed("标记客户端登录卡密已使用"))?;
    Ok(())
}

async fn consume_client_count_card_use(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    card: &mut ClientLoginCard,
) -> Result<(), AppError> {
    let Some(card_id) = card.id else {
        return Ok(());
    };
    let result = sqlx::query(
        "UPDATE `auth_cards` SET `remaining_uses` = `remaining_uses` - 1 \
         WHERE `id` = ? AND `card_type` = 'count' AND `remaining_uses` > 0 AND `status` <> 2",
    )
    .bind(card_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::DatabaseQueryFailed("次数卡扣次"))?;
    if result.rows_affected() != 1 {
        return Err(AppError::CardExhausted);
    }
    card.remaining_uses = (card.remaining_uses - 1).max(0);
    Ok(())
}

async fn upsert_client_login_device(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    command: &ClientLoginCommand,
    card: &ClientLoginCard,
) -> Result<ClientLoginDeviceIdentity, AppError> {
    let mut device = if !card.first_use {
        find_client_device_by_install_id(transaction, command.app_id, &command.install_id).await?
    } else {
        None
    };
    if device.is_none() && card.first_use {
        if let Some(device_id) = try_insert_client_login_device(transaction, command, card).await? {
            return Ok(ClientLoginDeviceIdentity {
                id: device_id,
                created: true,
            });
        }
        device = find_client_device_by_install_id(transaction, command.app_id, &command.install_id)
            .await?;
    }
    if let Some(existing_device) = &device {
        assert_client_device_can_login(existing_device, command)?;
    }
    assert_client_card_device_limit(transaction, command, card, device.as_ref()).await?;
    if let Some(existing_device) = device {
        update_client_login_device(transaction, existing_device.id, command, card).await?;
        return Ok(ClientLoginDeviceIdentity {
            id: existing_device.id,
            created: false,
        });
    }
    let device_id = insert_client_login_device(transaction, command, card).await?;
    Ok(ClientLoginDeviceIdentity {
        id: device_id,
        created: true,
    })
}

async fn find_client_device_by_install_id(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    app_id: u64,
    install_id: &str,
) -> Result<Option<ClientLoginDeviceRow>, AppError> {
    let row = sqlx::query(CLIENT_DEVICE_BY_INSTALL_ID_SQL)
        .bind(app_id)
        .bind(install_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询客户端登录设备"))?;
    row.map(client_login_device_row).transpose()
}

fn assert_client_device_can_login(
    device: &ClientLoginDeviceRow,
    command: &ClientLoginCommand,
) -> Result<(), AppError> {
    if device.status != 1 {
        return Err(AppError::DeviceDisabled);
    }
    if command.login_ip_binding_enabled && !client_device_ip_matches(device, command)? {
        return Err(AppError::LoginIpMismatch);
    }
    let stored_proof_mode = normalize_client_stored_proof_mode(&device.device_key_alg)?;
    if command.proof_mode == "ephemeral_ticket_v1" && stored_proof_mode != "ephemeral_ticket_v1" {
        return Err(AppError::DeviceKeyModeDowngrade);
    }
    assert_client_device_public_key_matches(device, command)?;
    Ok(())
}

fn normalize_client_stored_proof_mode(value: &str) -> Result<String, AppError> {
    match value.trim() {
        "" | "local_key_v1" | "platform_key_v1" | "ecdsa_p256_sha256_v1" => {
            Ok("local_key_v1".to_string())
        }
        "ephemeral_ticket_v1" => Ok("ephemeral_ticket_v1".to_string()),
        _ => Err(AppError::DeviceKeyModeInvalid("设备密钥模式不支持")),
    }
}

fn assert_client_device_public_key_matches(
    device: &ClientLoginDeviceRow,
    command: &ClientLoginCommand,
) -> Result<(), AppError> {
    if command.proof_mode != "local_key_v1" {
        return Ok(());
    }
    let stored_public_key = device.device_public_key.trim();
    if stored_public_key.is_empty() {
        return Ok(());
    }
    if crate::crypto::p256_public_key_fingerprint(stored_public_key)?
        != crate::crypto::p256_public_key_fingerprint(&command.device_public_key)?
    {
        return Err(AppError::DeviceKeyChanged);
    }
    Ok(())
}

fn client_device_ip_matches(
    device: &ClientLoginDeviceRow,
    command: &ClientLoginCommand,
) -> Result<bool, AppError> {
    if !device.bind_region.is_empty() {
        return Ok(device.bind_region == command.bind_region);
    }
    if device.bind_ip.is_empty() {
        return Ok(true);
    }
    Ok(client_ip_binding_key(&device.bind_ip)? == command.bind_region)
}

async fn assert_client_card_device_limit(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    command: &ClientLoginCommand,
    card: &ClientLoginCard,
    device: Option<&ClientLoginDeviceRow>,
) -> Result<(), AppError> {
    if device.is_some() || card.first_use || !client_should_limit_card_devices(command) {
        return Ok(());
    }
    let active_devices =
        count_client_active_card_devices(transaction, command.app_id, &card.card_hash).await?;
    if active_devices >= client_card_device_limit(command, card) {
        return Err(AppError::DeviceLimit);
    }
    Ok(())
}

async fn count_client_active_card_devices(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    app_id: u64,
    card_hash: &str,
) -> Result<i64, AppError> {
    let row = sqlx::query(
        "SELECT CAST(COUNT(*) AS SIGNED) AS `count` FROM `auth_devices` \
         WHERE `app_id` = ? AND `card_hash` = ? AND `status` = 1",
    )
    .bind(app_id)
    .bind(card_hash)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| AppError::DatabaseQueryFailed("统计卡密绑定设备"))?;
    row_get(&row, "count", "读取卡密绑定设备数量")
}

async fn assert_client_login_session_allowed(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    command: &ClientLoginCommand,
    card: &ClientLoginCard,
    device_id: Option<u64>,
) -> Result<(), AppError> {
    if command.shared_cards_enabled || is_client_count_card(card) {
        return Ok(());
    }
    let active_sessions =
        list_client_active_card_sessions(transaction, command.app_id, card).await?;
    for session in active_sessions {
        if session.device_id != device_id {
            return Err(AppError::CardInUse);
        }
    }
    Ok(())
}

async fn list_client_active_card_sessions(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    app_id: u64,
    card: &ClientLoginCard,
) -> Result<Vec<ClientLoginActiveSession>, AppError> {
    let rows = if let Some(card_id) = card.id {
        sqlx::query(
            "SELECT `id`, `device_id` FROM `auth_sessions` FORCE INDEX (`idx_auth_sessions_card`) \
             WHERE `app_id` = ? AND `status` = 1 AND `expires_at` >= NOW() \
             AND (`card_id` = ? OR `card_hash` = ?) ORDER BY `id` ASC",
        )
        .bind(app_id)
        .bind(card_id)
        .bind(&card.card_hash)
        .fetch_all(&mut **transaction)
        .await
    } else {
        sqlx::query(
            "SELECT `id`, `device_id` FROM `auth_sessions` FORCE INDEX (`idx_auth_sessions_card`) \
             WHERE `app_id` = ? AND `status` = 1 AND `expires_at` >= NOW() \
             AND `card_id` IS NULL AND `card_hash` = ? ORDER BY `id` ASC",
        )
        .bind(app_id)
        .bind(&card.card_hash)
        .fetch_all(&mut **transaction)
        .await
    }
    .map_err(|_| AppError::DatabaseQueryFailed("查询卡密在线会话"))?;
    rows.into_iter().map(client_active_session_row).collect()
}

async fn try_insert_client_login_device(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    command: &ClientLoginCommand,
    card: &ClientLoginCard,
) -> Result<Option<u64>, AppError> {
    let result = client_login_device_insert_query(command, card)
        .execute(&mut **transaction)
        .await;
    match result {
        Ok(result) => Ok(Some(result.last_insert_id())),
        Err(error) if is_duplicate_or_constraint_error(&error) => Ok(None),
        Err(_) => Err(AppError::DatabaseQueryFailed("创建客户端登录设备")),
    }
}

async fn insert_client_login_device(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    command: &ClientLoginCommand,
    card: &ClientLoginCard,
) -> Result<u64, AppError> {
    let result = client_login_device_insert_query(command, card)
        .execute(&mut **transaction)
        .await;
    match result {
        Ok(result) => Ok(result.last_insert_id()),
        Err(error) if is_duplicate_or_constraint_error(&error) => {
            Err(AppError::DatabaseQueryFailed("设备已存在"))
        }
        Err(_) => Err(AppError::DatabaseQueryFailed("创建客户端登录设备")),
    }
}

fn client_login_device_insert_query<'a>(
    command: &'a ClientLoginCommand,
    card: &'a ClientLoginCard,
) -> sqlx::query::Query<'a, MySql, sqlx::mysql::MySqlArguments> {
    sqlx::query(
        "INSERT INTO `auth_devices` \
         (`app_id`, `account_id`, `card_id`, `card_hash`, `device_hash`, `device_name`, \
          `install_id`, `device_public_key`, `device_key_alg`, `machine_profile_hash`, \
          `bind_ip`, `bind_region`, `risk_level`, `status`) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(command.app_id)
    .bind(Option::<u64>::None)
    .bind(card.id)
    .bind(&card.card_hash)
    .bind(&command.device_hash)
    .bind(&command.device_name)
    .bind(&command.install_id)
    .bind(&command.device_public_key)
    .bind(&command.proof_mode)
    .bind(&command.machine_profile_hash)
    .bind(&command.bind_ip)
    .bind(&command.bind_region)
    .bind(0_i64)
    .bind(1_i64)
}

async fn update_client_login_device(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    device_id: u64,
    command: &ClientLoginCommand,
    card: &ClientLoginCard,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE `auth_devices` SET `card_id` = ?, `card_hash` = ?, `device_hash` = ?, \
         `device_name` = ?, `install_id` = ?, `device_public_key` = ?, `device_key_alg` = ?, \
         `machine_profile_hash` = ?, `bind_ip` = CASE WHEN ? = '' THEN '' WHEN `bind_ip` = '' THEN ? ELSE `bind_ip` END, \
         `bind_region` = CASE WHEN ? = '' THEN '' WHEN `bind_region` = '' THEN ? ELSE `bind_region` END, \
         `risk_level` = ?, `status` = ?, `last_seen_at` = ? WHERE `id` = ?",
    )
    .bind(card.id)
    .bind(&card.card_hash)
    .bind(&command.device_hash)
    .bind(&command.device_name)
    .bind(&command.install_id)
    .bind(&command.device_public_key)
    .bind(&command.proof_mode)
    .bind(&command.machine_profile_hash)
    .bind(&command.bind_ip)
    .bind(&command.bind_ip)
    .bind(&command.bind_region)
    .bind(&command.bind_region)
    .bind(0_i64)
    .bind(1_i64)
    .bind(command.now)
    .bind(device_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::DatabaseQueryFailed("更新客户端登录设备"))?;
    Ok(())
}

async fn revoke_client_device_card_sessions(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    app_id: u64,
    device_id: u64,
    card_id: Option<u64>,
    card_hash: &str,
) -> Result<u64, AppError> {
    let result = if let Some(card_id) = card_id {
        sqlx::query(
            "UPDATE `auth_sessions` SET `status` = 0 WHERE `app_id` = ? AND `device_id` = ? \
             AND `status` = 1 AND (`card_id` = ? OR `card_hash` = ?)",
        )
        .bind(app_id)
        .bind(device_id)
        .bind(card_id)
        .bind(card_hash)
        .execute(&mut **transaction)
        .await
    } else {
        sqlx::query(
            "UPDATE `auth_sessions` SET `status` = 0 WHERE `app_id` = ? AND `device_id` = ? \
             AND `status` = 1 AND `card_id` IS NULL AND `card_hash` = ?",
        )
        .bind(app_id)
        .bind(device_id)
        .bind(card_hash)
        .execute(&mut **transaction)
        .await
    }
    .map_err(|_| AppError::DatabaseQueryFailed("撤销旧客户端会话"))?;
    Ok(result.rows_affected())
}

async fn create_client_login_session(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    command: &ClientLoginCommand,
    card: &ClientLoginCard,
    device_id: Option<u64>,
    session_expires_at: NaiveDateTime,
) -> Result<u64, AppError> {
    let result = sqlx::query(
        "INSERT INTO `auth_sessions` \
         (`app_id`, `account_id`, `device_id`, `card_id`, `card_hash`, `card_fingerprint`, \
          `token_hash`, `request_counter`, `proof_mode`, `ticket_hash`, `ticket_expires_at`, \
          `expires_at`, `last_heartbeat_at`, `ip`, `status`) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(command.app_id)
    .bind(Option::<u64>::None)
    .bind(device_id)
    .bind(card.id)
    .bind(&card.card_hash)
    .bind(&card.card_fingerprint)
    .bind(&command.token_hash)
    .bind(0_i64)
    .bind(&command.proof_mode)
    .bind(&command.ticket_hash)
    .bind(command.ticket_expires_at)
    .bind(session_expires_at)
    .bind(command.now)
    .bind(&command.bind_ip)
    .bind(1_i64)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::DatabaseQueryFailed("创建客户端会话"))?;
    Ok(result.last_insert_id())
}

fn client_session_expires_at(
    command: &ClientLoginCommand,
    card: &ClientLoginCard,
) -> NaiveDateTime {
    let ttl_expires_at =
        command.now + chrono::Duration::seconds(command.heartbeat_interval.max(300));
    if ttl_expires_at < card.expires_at {
        ttl_expires_at
    } else {
        card.expires_at
    }
}

fn client_card_expires_at(
    card_type: &str,
    used_at: Option<NaiveDateTime>,
    duration_seconds: i64,
) -> NaiveDateTime {
    if matches!(card_type, "permanent" | "count") {
        return client_permanent_card_expires_at();
    }
    used_at.unwrap_or_else(|| chrono::Local::now().naive_local())
        + chrono::Duration::seconds(duration_seconds.max(1))
}

fn client_permanent_card_expires_at() -> NaiveDateTime {
    NaiveDateTime::parse_from_str("9999-12-31 23:59:59", "%Y-%m-%d %H:%M:%S")
        .expect("valid permanent card expiry")
}

fn normalized_client_card_type(value: &str) -> String {
    match value {
        "permanent" | "count" => value.to_string(),
        _ => "time".to_string(),
    }
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

fn is_client_count_card(card: &ClientLoginCard) -> bool {
    card.card_type == "count"
}

fn client_should_limit_card_devices(command: &ClientLoginCommand) -> bool {
    command.device_binding_enabled && !command.shared_cards_enabled
}

fn client_card_device_limit(command: &ClientLoginCommand, card: &ClientLoginCard) -> i64 {
    50_i64.max(card.max_devices).max(command.app_max_devices)
}

fn client_ip_binding_key(ip: &str) -> Result<String, AppError> {
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

async fn revoke_card_sessions_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    app_id: u64,
    card_id: u64,
    card_hash: &str,
) -> Result<u64, AppError> {
    let result = sqlx::query(
        "UPDATE `auth_sessions` SET `status` = 0 \
         WHERE `app_id` = ? AND `status` = 1 AND (`card_id` = ? OR `card_hash` = ?)",
    )
    .bind(app_id)
    .bind(card_id)
    .bind(card_hash)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::DatabaseQueryFailed("撤销卡密会话"))?;
    Ok(result.rows_affected())
}

async fn revoke_time_card_sessions_by_activated_range_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    app_id: u64,
    activated_start: NaiveDateTime,
    activated_end: NaiveDateTime,
) -> Result<u64, AppError> {
    let result = sqlx::query(
        "UPDATE `auth_sessions` s JOIN `auth_cards` c ON c.`app_id` = s.`app_id` \
         AND (s.`card_id` = c.`id` OR s.`card_hash` = c.`card_hash`) \
         SET s.`status` = 0 WHERE s.`status` = 1 AND c.`app_id` = ? \
         AND c.`used_at` IS NOT NULL AND c.`used_at` >= ? AND c.`used_at` <= ? \
         AND c.`card_type` = 'time'",
    )
    .bind(app_id)
    .bind(activated_start)
    .bind(activated_end)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::DatabaseQueryFailed("撤销激活范围时长卡会话"))?;
    Ok(result.rows_affected())
}

async fn revoke_device_sessions_by_ids_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    app_id: u64,
    device_ids: &[u64],
) -> Result<u64, AppError> {
    if device_ids.is_empty() {
        return Ok(0);
    }
    let mut builder =
        QueryBuilder::<MySql>::new("UPDATE `auth_sessions` SET `status` = 0 WHERE `app_id` = ");
    builder
        .push_bind(app_id)
        .push(" AND `status` = 1 AND `device_id` IN (");
    push_id_bindings(&mut builder, device_ids);
    builder.push(")");
    let result = builder
        .build()
        .execute(&mut **transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("撤销设备会话"))?;
    Ok(result.rows_affected())
}

async fn revoke_session_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    session_id: u64,
) -> Result<u64, AppError> {
    if session_id == 0 {
        return Ok(0);
    }
    let result = sqlx::query("UPDATE `auth_sessions` SET `status` = 0 WHERE `id` = ?")
        .bind(session_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("撤销会话"))?;
    Ok(result.rows_affected())
}

async fn update_messages_status_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    app_id: u64,
    message_ids: &[u64],
    update: &MessageStatusUpdate,
) -> Result<u64, AppError> {
    let mut builder = QueryBuilder::<MySql>::new("UPDATE `auth_messages` SET `status` = ");
    builder.push_bind(&update.status);
    if let Some(read_at) = update.read_at {
        builder.push(", `read_at` = ").push_bind(read_at);
    }
    if !update.handled_by.is_empty() {
        builder
            .push(", `handled_by` = ")
            .push_bind(&update.handled_by);
    }
    if let Some(handled_at) = update.handled_at {
        builder.push(", `handled_at` = ").push_bind(handled_at);
    }
    if let Some(archived_at) = update.archived_at {
        builder.push(", `archived_at` = ").push_bind(archived_at);
    }
    builder
        .push(" WHERE `app_id` = ")
        .push_bind(app_id)
        .push(" AND `id` IN (");
    push_id_bindings(&mut builder, message_ids);
    builder.push(")");
    let result = builder
        .build()
        .execute(&mut **transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("更新消息状态"))?;
    Ok(result.rows_affected())
}

async fn create_client_security_report_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    report: &ClientSecurityReportRecord,
) -> Result<u64, AppError> {
    let result = sqlx::query(
        "INSERT INTO `auth_security_reports` \
         (`app_id`, `session_id`, `device_id`, `card_id`, `card_hash`, `card_fingerprint`, \
          `install_id`, `event_id`, `event_type`, `risk_level`, `confidence`, `requested_action`, \
          `action`, `action_source`, `risk_score`, `action_reason`, `title`, `message`, \
          `evidence_json`, `attestation_json`, `sdk_version`, `detector_version`, `platform`, \
          `ip`, `occurred_at`) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(report.app_id)
    .bind(report.session_id)
    .bind(report.device_id)
    .bind(report.card_id)
    .bind(&report.card_hash)
    .bind(&report.card_fingerprint)
    .bind(&report.install_id)
    .bind(&report.event_id)
    .bind(&report.event_type)
    .bind(&report.risk_level)
    .bind(report.confidence)
    .bind(&report.requested_action)
    .bind(&report.action)
    .bind(&report.action_source)
    .bind(report.risk_score)
    .bind(&report.action_reason)
    .bind(&report.title)
    .bind(&report.message)
    .bind(&report.evidence_json)
    .bind(&report.attestation_json)
    .bind(&report.sdk_version)
    .bind(&report.detector_version)
    .bind(&report.platform)
    .bind(&report.ip)
    .bind(report.occurred_at)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::DatabaseQueryFailed("创建安全上报"))?;
    Ok(result.last_insert_id())
}

async fn create_client_security_message_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    report_id: u64,
    message: &ClientSecurityMessageRecord,
) -> Result<u64, AppError> {
    let result = sqlx::query(
        "INSERT INTO `auth_messages` \
         (`app_id`, `report_id`, `session_id`, `device_id`, `card_id`, `message_type`, \
          `severity`, `status`, `title`, `summary`, `action`, `action_source`, `risk_score`) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(message.app_id)
    .bind(report_id)
    .bind(message.session_id)
    .bind(message.device_id)
    .bind(message.card_id)
    .bind("security_report")
    .bind(&message.severity)
    .bind("unread")
    .bind(&message.title)
    .bind(&message.summary)
    .bind(&message.action)
    .bind(&message.action_source)
    .bind(message.risk_score)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::DatabaseQueryFailed("创建安全上报消息"))?;
    Ok(result.last_insert_id())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClientSecurityActionResult {
    session_revoked: bool,
    device_disabled: bool,
    card_disabled: bool,
    revoked_sessions: u64,
}

async fn apply_client_security_action_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    action: &ClientSecurityActionRecord,
    message_id: u64,
) -> Result<ClientSecurityActionResult, AppError> {
    let mut result = match action.action.as_str() {
        "kick_session" => {
            revoke_session_in_transaction(transaction, action.session_id).await?;
            ClientSecurityActionResult {
                session_revoked: true,
                device_disabled: false,
                card_disabled: false,
                revoked_sessions: 1,
            }
        }
        "disable_device" => {
            disable_client_security_device_in_transaction(transaction, action).await?
        }
        "disable_card" => disable_client_security_card_in_transaction(transaction, action).await?,
        _ => ClientSecurityActionResult {
            session_revoked: false,
            device_disabled: false,
            card_disabled: false,
            revoked_sessions: 0,
        },
    };
    create_message_action_in_transaction(
        transaction,
        &MessageActionRecord {
            app_id: action.app_id,
            message_id,
            action: &action.action,
            actor_type: "system",
            actor_name: "securityPolicy",
            result: if result.session_revoked {
                "enforced"
            } else {
                "recorded"
            },
            remark: &action.action_source,
            ip: &action.ip,
        },
    )
    .await?;
    write_audit_in_transaction(
        transaction,
        Some(action.app_id),
        &format!("security_{}", action.action),
        &format!("消息#{message_id} 客户端安全上报处置：{}", action.action),
        &action.ip,
    )
    .await?;
    if action.action == "manual_review" {
        result.session_revoked = false;
    }
    Ok(result)
}

async fn disable_client_security_device_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    action: &ClientSecurityActionRecord,
) -> Result<ClientSecurityActionResult, AppError> {
    let Some(device_id) = action.device_id else {
        revoke_session_in_transaction(transaction, action.session_id).await?;
        return Ok(ClientSecurityActionResult {
            session_revoked: true,
            device_disabled: false,
            card_disabled: false,
            revoked_sessions: 1,
        });
    };
    sqlx::query("UPDATE `auth_devices` SET `status` = 0 WHERE `id` = ?")
        .bind(device_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("禁用安全上报设备"))?;
    let revoked_sessions =
        revoke_device_sessions_by_ids_in_transaction(transaction, action.app_id, &[device_id])
            .await?;
    Ok(ClientSecurityActionResult {
        session_revoked: true,
        device_disabled: true,
        card_disabled: false,
        revoked_sessions,
    })
}

async fn disable_client_security_card_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    action: &ClientSecurityActionRecord,
) -> Result<ClientSecurityActionResult, AppError> {
    let Some(card_id) = action.card_id else {
        revoke_session_in_transaction(transaction, action.session_id).await?;
        return Ok(ClientSecurityActionResult {
            session_revoked: true,
            device_disabled: false,
            card_disabled: false,
            revoked_sessions: 1,
        });
    };
    sqlx::query("UPDATE `auth_cards` SET `status` = 2 WHERE `id` = ?")
        .bind(card_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("禁用安全上报卡密"))?;
    let revoked_sessions =
        revoke_card_sessions_in_transaction(transaction, action.app_id, card_id, &action.card_hash)
            .await?;
    Ok(ClientSecurityActionResult {
        session_revoked: true,
        device_disabled: false,
        card_disabled: true,
        revoked_sessions,
    })
}

async fn rotate_client_session_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    rotation: &ClientSessionRotation,
) -> Result<bool, AppError> {
    let result = sqlx::query(
        "UPDATE `auth_sessions` SET `token_hash` = ?, `request_counter` = ?, \
         `last_heartbeat_at` = ?, `expires_at` = ?, `ticket_hash` = ?, `ticket_expires_at` = ? \
         WHERE `id` = ? AND `token_hash` = ? AND `status` = 1 AND `request_counter` < ?",
    )
    .bind(&rotation.next_token_hash)
    .bind(rotation.request_counter)
    .bind(rotation.heartbeat_at)
    .bind(rotation.expires_at)
    .bind(&rotation.ticket_hash)
    .bind(rotation.ticket_expires_at)
    .bind(rotation.session_id)
    .bind(&rotation.current_token_hash)
    .bind(rotation.request_counter)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::DatabaseQueryFailed("更新客户端会话令牌"))?;
    Ok(result.rows_affected() == 1)
}

async fn touch_client_device_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    device_id: u64,
    seen_at: NaiveDateTime,
) -> Result<(), AppError> {
    sqlx::query("UPDATE `auth_devices` SET `last_seen_at` = ? WHERE `id` = ?")
        .bind(seen_at)
        .bind(device_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("更新客户端设备活跃时间"))?;
    Ok(())
}

struct MessageActionRecord<'a> {
    app_id: u64,
    message_id: u64,
    action: &'a str,
    actor_type: &'a str,
    actor_name: &'a str,
    result: &'a str,
    remark: &'a str,
    ip: &'a str,
}

async fn create_message_action_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    record: &MessageActionRecord<'_>,
) -> Result<u64, AppError> {
    let result = sqlx::query(
        "INSERT INTO `auth_message_actions` \
         (`app_id`, `message_id`, `action`, `actor_type`, `actor_name`, `result`, `remark`, `ip`) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(record.app_id)
    .bind(record.message_id)
    .bind(clip_text(record.action, 32))
    .bind(clip_text(record.actor_type, 16))
    .bind(clip_text(record.actor_name, 64))
    .bind(clip_text(record.result, 32))
    .bind(clip_text(record.remark, 255))
    .bind(clip_text(record.ip, 45))
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::DatabaseQueryFailed("写入消息动作"))?;
    Ok(result.last_insert_id())
}

async fn write_audit_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    app_id: Option<u64>,
    action: &str,
    message: &str,
    ip: &str,
) -> Result<u64, AppError> {
    let result = sqlx::query(
        "INSERT INTO `auth_audit_logs` (`app_id`, `account_id`, `action`, `message`, `ip`, `region`) \
         VALUES (?, NULL, ?, ?, ?, ?)",
    )
    .bind(app_id)
    .bind(clip_text(action, 40))
    .bind(clip_text(message, 255))
    .bind(clip_text(ip, 45))
    .bind(ip_region(ip))
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::DatabaseQueryFailed("写入审计日志"))?;
    Ok(result.last_insert_id())
}

async fn delete_message_actions_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    app_id: u64,
    message_ids: &[u64],
) -> Result<u64, AppError> {
    let mut builder =
        QueryBuilder::<MySql>::new("DELETE FROM `auth_message_actions` WHERE `app_id` = ");
    builder.push_bind(app_id).push(" AND `message_id` IN (");
    push_id_bindings(&mut builder, message_ids);
    builder.push(")");
    let result = builder
        .build()
        .execute(&mut **transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("删除消息动作"))?;
    Ok(result.rows_affected())
}

async fn delete_messages_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    app_id: u64,
    message_ids: &[u64],
) -> Result<u64, AppError> {
    let mut builder = QueryBuilder::<MySql>::new("DELETE FROM `auth_messages` WHERE `app_id` = ");
    builder.push_bind(app_id).push(" AND `id` IN (");
    push_id_bindings(&mut builder, message_ids);
    builder.push(")");
    let result = builder
        .build()
        .execute(&mut **transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("删除消息"))?;
    Ok(result.rows_affected())
}

async fn apply_message_action_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    app_id: u64,
    message: &MessageRow,
    action: &str,
) -> Result<MessageActionEffect, AppError> {
    match action {
        "kick_session" => kick_message_session_in_transaction(transaction, message).await,
        "disable_device" => {
            disable_message_device_in_transaction(transaction, app_id, message).await
        }
        "disable_card" => disable_message_card_in_transaction(transaction, app_id, message).await,
        _ => Ok(MessageActionEffect {
            result: "recorded".to_string(),
            revoked_sessions: 0,
            device_disabled: false,
            card_disabled: false,
        }),
    }
}

async fn kick_message_session_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    message: &MessageRow,
) -> Result<MessageActionEffect, AppError> {
    let Some(session_id) = message.session_id else {
        return Ok(target_missing_action_effect());
    };
    let revoked_sessions = revoke_session_in_transaction(transaction, session_id).await?;
    if revoked_sessions == 0 {
        return Ok(target_missing_action_effect());
    }
    Ok(MessageActionEffect {
        result: "enforced".to_string(),
        revoked_sessions,
        device_disabled: false,
        card_disabled: false,
    })
}

async fn disable_message_device_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    app_id: u64,
    message: &MessageRow,
) -> Result<MessageActionEffect, AppError> {
    let Some(device_id) = message.device_id else {
        return kick_message_session_in_transaction(transaction, message).await;
    };
    let result =
        sqlx::query("UPDATE `auth_devices` SET `status` = 0 WHERE `app_id` = ? AND `id` = ?")
            .bind(app_id)
            .bind(device_id)
            .execute(&mut **transaction)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("禁用消息关联设备"))?;
    if result.rows_affected() == 0 {
        return kick_message_session_in_transaction(transaction, message).await;
    }
    let revoked_sessions =
        revoke_device_sessions_by_ids_in_transaction(transaction, app_id, &[device_id]).await?;
    Ok(MessageActionEffect {
        result: "enforced".to_string(),
        revoked_sessions,
        device_disabled: true,
        card_disabled: false,
    })
}

async fn disable_message_card_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    app_id: u64,
    message: &MessageRow,
) -> Result<MessageActionEffect, AppError> {
    let Some(card_id) = message.card_id else {
        return kick_message_session_in_transaction(transaction, message).await;
    };
    let result =
        sqlx::query("UPDATE `auth_cards` SET `status` = 2 WHERE `app_id` = ? AND `id` = ?")
            .bind(app_id)
            .bind(card_id)
            .execute(&mut **transaction)
            .await
            .map_err(|_| AppError::DatabaseQueryFailed("禁用消息关联卡密"))?;
    if result.rows_affected() == 0 {
        return kick_message_session_in_transaction(transaction, message).await;
    }
    let card_hash =
        message_card_hash_in_transaction(transaction, card_id, &message.card_hash).await?;
    let revoked_sessions =
        revoke_card_sessions_in_transaction(transaction, app_id, card_id, &card_hash).await?;
    Ok(MessageActionEffect {
        result: "enforced".to_string(),
        revoked_sessions,
        device_disabled: false,
        card_disabled: true,
    })
}

async fn message_card_hash_in_transaction(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    card_id: u64,
    fallback: &str,
) -> Result<String, AppError> {
    if !fallback.trim().is_empty() {
        return Ok(fallback.to_string());
    }
    let row = sqlx::query("SELECT `card_hash` FROM `auth_cards` WHERE `id` = ?")
        .bind(card_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed("查询消息关联卡密哈希"))?;
    row.map(|row| row_get(&row, "card_hash", "读取消息关联卡密哈希"))
        .transpose()
        .map(|hash| hash.unwrap_or_default())
}

fn target_missing_action_effect() -> MessageActionEffect {
    MessageActionEffect {
        result: "target_missing".to_string(),
        revoked_sessions: 0,
        device_disabled: false,
        card_disabled: false,
    }
}

fn message_audit_labels(message_ids: &[u64]) -> String {
    message_ids
        .iter()
        .map(|message_id| format!("消息#{message_id}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn message_status_audit_message(message_ids: &[u64], status: &str, updated: u64) -> String {
    format!(
        "消息状态变更：{} => {}，{} 条",
        message_audit_labels(message_ids),
        status,
        updated
    )
}

async fn delete_rows_by_ids(
    pool: &MySqlPool,
    table_name: &'static str,
    id_column: &'static str,
    ids: &[u64],
    action: &'static str,
) -> Result<u64, AppError> {
    if ids.is_empty() {
        return Ok(0);
    }
    let mut builder = QueryBuilder::<MySql>::new("DELETE FROM `");
    builder
        .push(table_name)
        .push("` WHERE `")
        .push(id_column)
        .push("` IN (");
    push_id_bindings(&mut builder, ids);
    builder.push(")");
    let result = builder
        .build()
        .execute(pool)
        .await
        .map_err(|_| AppError::DatabaseQueryFailed(action))?;
    Ok(result.rows_affected())
}

fn unique_ids(mut ids: Vec<u64>) -> Vec<u64> {
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn object_or_empty(value: Option<Value>) -> Value {
    match value {
        Some(Value::Object(map)) => Value::Object(map),
        _ => serde_json::json!({}),
    }
}

fn clip_text(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

fn ip_region(ip: &str) -> &'static str {
    let ip = ip.trim();
    if ip.is_empty() || ip == "0.0.0.0" {
        return "未知";
    }
    let Ok(address) = ip.parse::<std::net::IpAddr>() else {
        return "内网或保留地址";
    };
    if address.is_loopback() {
        return "本机";
    }
    if is_private_or_reserved_ip(address) {
        return "内网或保留地址";
    }
    "公网"
}

fn is_private_or_reserved_ip(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(address) => {
            let octets = address.octets();
            address.is_unspecified()
                || address.is_private()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_multicast()
                || address.is_documentation()
                || octets[0] == 0
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 198 && (18..=19).contains(&octets[1]))
                || octets[0] >= 240
        }
        std::net::IpAddr::V6(address) => {
            let segments = address.segments();
            address.is_unspecified()
                || address.is_multicast()
                || ((segments[0] & 0xfe00) == 0xfc00)
                || ((segments[0] & 0xffc0) == 0xfe80)
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}

fn row_get<T>(
    row: &sqlx::mysql::MySqlRow,
    column: &'static str,
    operation: &'static str,
) -> Result<T, AppError>
where
    T: for<'value> sqlx::Decode<'value, sqlx::MySql> + sqlx::Type<sqlx::MySql>,
{
    row.try_get(column)
        .map_err(|_| AppError::DatabaseQueryFailed(operation))
}

fn is_duplicate_or_constraint_error(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Database(database_error) => database_error.code().as_deref() == Some("23000"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_status_audit_uses_updated_count_like_php() {
        assert_eq!(
            "消息状态变更：消息#7 消息#9 消息#11 => handled，1 条",
            message_status_audit_message(&[7, 9, 11], "handled", 1)
        );
    }

    #[test]
    fn cloud_storage_config_select_casts_mysql_unsigned_numbers() {
        for column in [
            "`status`",
            "`is_default`",
            "`max_file_size`",
            "`signed_url_ttl_seconds`",
        ] {
            assert!(
                CLOUD_STORAGE_CONFIG_SELECT_COLUMNS.contains(&format!("CAST({column} AS SIGNED)")),
                "missing signed cast for {column}"
            );
        }
    }

    #[test]
    fn admin_session_select_casts_mysql_unsigned_status() {
        assert!(
            ADMIN_SESSION_SELECT_BY_TOKEN_HASH.contains("CAST(`status` AS SIGNED) AS `status`"),
            "admin session status must be read with PHP-compatible signed numeric semantics"
        );
    }

    #[test]
    fn count_card_reset_counts_only_changed_rows_like_php() {
        assert!(
            RESET_COUNT_CARD_USES_CHANGED_FILTER.contains("`remaining_uses` <> `total_uses`"),
            "count card reset counters must ignore no-op rows like PHP mysqli affected rows"
        );
    }

    #[test]
    fn activated_range_updates_count_only_changed_rows() {
        assert_eq!(MIN_CARD_DURATION_SECONDS, 60);
        assert_eq!(MAX_CARD_DURATION_SECONDS, 315_360_000);
        assert!(
            CARD_STATUS_CHANGED_FILTER.contains("`status` <>"),
            "status range operations must ignore rows already in the target status"
        );
        assert!(
            ADD_TIME_CARD_DURATION_CHANGED_FILTER.contains("`duration_seconds` <"),
            "add duration range operations must ignore max-duration no-op rows"
        );
        assert!(
            REDUCE_TIME_CARD_DURATION_CHANGED_FILTER.contains("`duration_seconds` >"),
            "reduce duration range operations must ignore min-duration no-op rows"
        );
    }
}
