use std::collections::HashSet;

use bcrypt::{DEFAULT_COST, hash};
use chrono::{Duration, Local, NaiveDateTime};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::Sha256;

#[cfg(test)]
use crate::card_search::card_token_hashes;
use crate::{
    card_search::keyword_token_hashes,
    crypto,
    error::AppError,
    repository::{
        AccountRow, AdminCredentialsUpdate, AdminRow, AppApiUpdate, AppClientCryptoUpdate,
        AppDetailRow, AppRow, AppSettingsUpdate, AuditLogRow, AuthRepository, CardQuery, CardRow,
        CloudDownloadTokenInput, CloudFileRow, CloudStorageConfigRow, DeviceRow, NewApp, Overview,
        RemoteApiTokenDetailRow, RemoteConfigRow, RemoteConfigUpsert, RemoteVariableDetailRow,
        SecurityCleanup, SecurityPolicyInput, SecurityPolicyRow, SiteSettingsRow,
        SiteSettingsUpdate,
    },
    service::{
        admin_session::{AdminSessionContext, AdminUploadSessionContext},
        login::verify_php_password,
    },
};

mod cards;
mod cloud_storage;
mod messages;
mod remote_api;
mod sdk;
mod variables;

use self::cards::{
    MAX_CARD_EXPORT_ROWS, MAX_CARD_IMPORT_COUNT, build_new_cards, card_create_response,
    card_export_response, card_hash, card_import_response, card_matches_export_filter, card_prefix,
    card_rule, card_structure, create_card_keys, export_card_ids, export_card_query,
    exportable_card_keys, parse_card_import, selected_export_ids,
};
pub use self::cloud_storage::{
    CloudUploadForm, download_token_hash, local_object_path, temporary_download_url,
};
use self::cloud_storage::{
    assert_upload_session, cloud_config_get_view, cloud_config_payload, cloud_config_provider,
    cloud_file_filters, cloud_file_view, cloud_storage_summary_view, config_view,
    create_upload_ticket_payload, default_local_config, delete_cloud_object, download_token_view,
    enabled_flag, require_enabled_default_config, require_pending_upload_ticket,
    run_cloud_storage_config_test, store_cloud_base64_upload, store_cloud_upload,
    upload_ticket_hash, upload_ticket_response, upload_ticket_token,
};
use self::messages::{
    action_effect_view, activity_cleanup_view, admin_action, message_detail_view, message_filters,
    message_id, message_ids, message_view, security_action, status_update,
};
use self::remote_api::{
    assert_remote_api_logs_clear_confirmed, new_remote_api_token, remote_api_created_token_view,
    remote_api_log_filters, remote_api_log_ids, remote_api_log_view, remote_api_token_detail_view,
    remote_api_token_filters, remote_api_token_id, remote_api_token_status, remote_api_token_view,
};
use self::sdk::{SdkPackageContext, build_sdk_package};
use self::variables::{
    converted_remote_variable_input, remote_variable_app_ids, remote_variable_filters,
    remote_variable_id, remote_variable_ids, remote_variable_name, remote_variable_names,
    remote_variable_payload, remote_variable_scope, remote_variable_status, remote_variable_view,
};

type HmacSha256 = Hmac<Sha256>;

const CLIENT_AUTH_MODE: &str = "local_key_v1";
const DEFAULT_CLIENT_CRYPTO_ALG: &str = "rsa_oaep_aes_256_gcm";
const DEFAULT_MAX_DEVICES: i64 = 50;
const DEFAULT_SESSION_TTL: i64 = 86_400;
const MIN_CARD_DURATION_SECONDS: i64 = 60;
const MAX_CARD_DURATION_SECONDS: i64 = 315_360_000;
const MAX_APP_CODE_ATTEMPTS: usize = 8;
const FLAG_ENABLED: i64 = 1;
const FLAG_DISABLED: i64 = 0;
const PERMANENT_CARD_EXPIRES_AT: &str = "9999-12-31 23:59:59";
const SECURITY_POLICY_MODES: &[&str] = &["honor_client", "bounded_client", "server_score"];

#[derive(Clone)]
pub struct AdminService {
    repository: AuthRepository,
    system_key: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct SiteSettings {
    hostname: String,
    site_subtitle: String,
    siteurl: String,
    logo_url: String,
    announcement: String,
    contact: String,
    footer_text: String,
    custom_json: Value,
}

struct CardActivatedRange {
    start: NaiveDateTime,
    end: NaiveDateTime,
}

struct SecurityPolicyFields<'a> {
    enabled: i64,
    mode: &'a str,
    min_confidence_for_client_action: i64,
    max_client_action: &'a str,
    kick_score: i64,
    disable_device_score: i64,
    disable_card_score: i64,
    allowed_client_actions: &'a str,
    client_disable_device_min_score: i64,
    client_disable_card_min_score: i64,
    report_rate_limit_per_minute: i64,
    report_retention_days: i64,
    message_retention_days: i64,
    server_critical_action: &'a str,
    server_high_action: &'a str,
    server_medium_action: &'a str,
    server_low_action: &'a str,
    trusted_event_types_json: &'a str,
    updated_by: &'a str,
    updated_at: String,
}

impl AdminService {
    pub fn new(repository: AuthRepository, system_key: String) -> Self {
        Self {
            repository,
            system_key,
        }
    }

    pub async fn dispatch(
        &self,
        route: &str,
        context: &AdminSessionContext,
    ) -> Result<Value, AppError> {
        match route {
            "/admin/overview" => self.overview(&context.payload).await,
            "/admin/apps/create" => self.create_app(&context.payload).await,
            "/admin/apps/list" => self.list_apps(&context.payload).await,
            "/admin/apps/update" => self.update_app(&context.payload).await,
            "/admin/apps/api/update" => self.update_app_api(&context.payload).await,
            "/admin/apps/generate-keypair" => self.generate_client_key_pair(&context.payload).await,
            "/admin/apps/sdk" => self.app_sdk(&context.payload).await,
            "/admin/apps/integration" => self.app_integration(&context.payload).await,
            "/admin/apps/delete" => self.delete_apps(&context.payload).await,
            "/admin/apps/batch-status" => self.batch_app_status(&context.payload).await,
            "/admin/apps/status" => self.set_app_status(&context.payload).await,
            "/admin/audits/list" => self.list_audit_logs(&context.payload).await,
            "/admin/messages/list" => self.list_messages(&context.payload).await,
            "/admin/messages/detail" => self.message_detail(&context.payload).await,
            "/admin/messages/read" => self.update_messages_status(context, "read", "read").await,
            "/admin/messages/handling" => {
                self.update_messages_status(context, "handling", "start_handling")
                    .await
            }
            "/admin/messages/handle" => {
                self.update_messages_status(context, "handled", "handle")
                    .await
            }
            "/admin/messages/archive" => {
                self.update_messages_status(context, "archived", "archive")
                    .await
            }
            "/admin/messages/delete" => self.delete_messages(context).await,
            "/admin/messages/action" => self.act_message(context).await,
            "/admin/messages/clear-app-activity" => {
                self.clear_app_activity_data(&context.payload).await
            }
            "/admin/config/get" => self.get_config(&context.payload).await,
            "/admin/config/set" => self.set_config(&context.payload).await,
            "/admin/config/variables/set" => self.set_legacy_variables().await,
            "/admin/variables/list" => self.list_variables(&context.payload).await,
            "/admin/variables/create" => self.create_variable(&context.payload).await,
            "/admin/variables/update" => self.update_variable(&context.payload).await,
            "/admin/variables/status" => self.set_variable_status(&context.payload).await,
            "/admin/variables/delete" => self.delete_variable(&context.payload).await,
            "/admin/variables/batch-status" => self.batch_variable_status(&context.payload).await,
            "/admin/variables/batch-delete" => self.batch_delete_variables(&context.payload).await,
            "/admin/variables/convert" => self.convert_variable(&context.payload).await,
            "/admin/variables/apps/set" => self.set_variable_apps(&context.payload).await,
            "/admin/remote-api/tokens/list" => self.list_remote_api_tokens(&context.payload).await,
            "/admin/remote-api/tokens/create" => {
                self.create_remote_api_token(&context.payload, context)
                    .await
            }
            "/admin/remote-api/tokens/secret" => {
                self.remote_api_token_secret(&context.payload).await
            }
            "/admin/remote-api/tokens/status" => {
                self.set_remote_api_token_status(&context.payload).await
            }
            "/admin/remote-api/tokens/delete" => {
                self.delete_remote_api_token(&context.payload).await
            }
            "/admin/remote-api/logs/list" => self.list_remote_api_logs(&context.payload).await,
            "/admin/remote-api/logs/delete" => self.delete_remote_api_logs(&context.payload).await,
            "/admin/remote-api/logs/clear" => self.clear_remote_api_logs(&context.payload).await,
            "/admin/cloud-storage/summary" => self.cloud_storage_summary().await,
            "/admin/cloud-storage/files/list" => self.list_cloud_files(&context.payload).await,
            "/admin/cloud-storage/files/detail" => self.cloud_file_detail(&context.payload).await,
            "/admin/cloud-storage/files/delete" => self.delete_cloud_file(&context.payload).await,
            "/admin/cloud-storage/upload-ticket/create" => {
                self.create_cloud_upload_ticket(&context.payload, context)
                    .await
            }
            "/admin/cloud-storage/config/get" => self.get_cloud_storage_config().await,
            "/admin/cloud-storage/config/save" => {
                self.save_cloud_storage_config(&context.payload).await
            }
            "/admin/cloud-storage/config/test" => {
                self.test_cloud_storage_config(&context.payload).await
            }
            "/admin/cloud-storage/download-token/get" => self.get_cloud_download_token().await,
            "/admin/cloud-storage/download-token/refresh" => {
                self.refresh_cloud_download_token().await
            }
            "/admin/cloud-storage/download-token/status" => {
                self.set_cloud_download_token_status(&context.payload).await
            }
            "/admin/cards/create" => self.create_cards(&context.payload).await,
            "/admin/cards/import" => self.import_cards(&context.payload).await,
            "/admin/cards/export" => self.export_cards(&context.payload).await,
            "/admin/cards/list" => self.list_cards(&context.payload).await,
            "/admin/cards/status" => self.set_card_status(&context.payload).await,
            "/admin/cards/revoke" => self.revoke_card(&context.payload).await,
            "/admin/cards/delete" => self.delete_cards(&context.payload).await,
            "/admin/cards/batch-status" => self.batch_card_status(&context.payload).await,
            "/admin/cards/adjust-time" => self.adjust_card_duration(&context.payload).await,
            "/admin/cards/batch-adjust-time" => {
                self.batch_adjust_card_duration(&context.payload).await
            }
            "/admin/cards/range-operation" => {
                self.operate_cards_by_activated_range(&context.payload)
                    .await
            }
            "/admin/cards/reset-uses" => self.reset_card_uses(&context.payload).await,
            "/admin/cards/batch-reset-uses" => self.batch_reset_card_uses(&context.payload).await,
            "/admin/cards/devices" => self.list_card_devices(&context.payload).await,
            "/admin/cards/devices/unbind" => self.unbind_card_device(&context.payload).await,
            "/admin/cards/devices/unbind-all" => self.unbind_card_devices(&context.payload).await,
            "/admin/cards/devices/batch-status" => {
                self.batch_card_devices_status(&context.payload).await
            }
            "/admin/cards/devices/batch-unbind" => {
                self.batch_unbind_card_devices(&context.payload).await
            }
            "/admin/accounts/list" => self.list_accounts(&context.payload).await,
            "/admin/accounts/status" => self.set_account_status(&context.payload).await,
            "/admin/accounts/extend" => self.extend_account(&context.payload).await,
            "/admin/devices/list" => self.list_devices(&context.payload).await,
            "/admin/devices/status" => self.set_device_status(&context.payload).await,
            "/admin/security/policy/get" => self.get_security_policy(&context.payload).await,
            "/admin/security/policy/set" => self.set_security_policy(context).await,
            "/admin/maintenance/cleanup-nonces" => self.cleanup_nonces().await,
            "/admin/profile/get" => self.get_admin_profile(context).await,
            "/admin/profile/clear-remember" => self.clear_remembered_admin_login(context).await,
            "/admin/profile/update" => self.update_admin_profile(context).await,
            "/admin/site/get" => self.get_site_settings().await,
            "/admin/site/update" => self.update_site_settings(context).await,
            _ => Err(AppError::InvalidRoute),
        }
    }

    pub async fn dispatch_remote_special(
        &self,
        route: &str,
        context: &AdminSessionContext,
    ) -> Result<Option<Value>, AppError> {
        let data = match route {
            "/remote/apps/api/get" => self.remote_app_api(&context.payload).await?,
            "/remote/variables/upsert" => {
                self.upsert_remote_variable_by_name(&context.payload)
                    .await?
            }
            "/remote/variables/status" => {
                self.set_remote_variable_status_by_names(&context.payload)
                    .await?
            }
            "/remote/variables/delete" => {
                self.delete_remote_variables_by_names(&context.payload)
                    .await?
            }
            "/remote/variables/convert" => {
                self.convert_remote_variable_by_name(&context.payload)
                    .await?
            }
            "/remote/variables/apps/set" => {
                self.set_remote_variable_apps_by_name(&context.payload)
                    .await?
            }
            "/remote/cloud-storage/files/upload" => {
                self.upload_cloud_file_base64(&context.payload).await?
            }
            _ => return Ok(None),
        };
        Ok(Some(data))
    }

    async fn get_admin_profile(&self, context: &AdminSessionContext) -> Result<Value, AppError> {
        let username = context.admin_username.trim();
        if username.is_empty() {
            return Err(AppError::AdminSessionInvalid);
        }
        let admin = self
            .repository
            .find_admin_by_username(username)
            .await?
            .ok_or(AppError::AdminNotFound)?;
        Ok(json!({
            "profile": admin_profile_view(&admin, &context.session_expires_at)
        }))
    }

    async fn clear_remembered_admin_login(
        &self,
        context: &AdminSessionContext,
    ) -> Result<Value, AppError> {
        let username = current_admin_username(context)?;
        self.repository
            .clear_admin_remember_login(&username)
            .await?;
        let admin = self
            .repository
            .find_admin_by_username(&username)
            .await?
            .ok_or(AppError::AdminNotFound)?;
        Ok(json!({
            "cleared": true,
            "profile": admin_profile_view(&admin, &context.session_expires_at)
        }))
    }

    async fn update_admin_profile(&self, context: &AdminSessionContext) -> Result<Value, AppError> {
        let admin = self.load_current_admin(context).await?;
        assert_current_admin_password(
            &admin,
            &payload_raw_string(&context.payload, "current_password"),
        )?;
        let current_username = admin.username.clone();
        let next_username = admin_username(&payload_string_or(
            &context.payload,
            "username",
            &current_username,
        ))?;
        let password_change = admin_password_change(&context.payload)?;
        if next_username == current_username && password_change.is_none() {
            return Err(AppError::InvalidInput("没有可保存的账号改动"));
        }
        self.assert_admin_username_available(&current_username, &next_username)
            .await?;
        let update = AdminCredentialsUpdate {
            username: next_username.clone(),
            password: password_change.unwrap_or(admin.password),
        };
        self.repository
            .update_admin_credentials_and_revoke_sessions(&current_username, &update)
            .await?;
        Ok(json!({
            "updated": true,
            "username": next_username,
            "relogin_required": true,
        }))
    }

    async fn get_site_settings(&self) -> Result<Value, AppError> {
        let settings = self
            .repository
            .get_site_settings()
            .await?
            .map(normalize_site_settings)
            .unwrap_or_else(default_site_settings);
        Ok(json!({ "settings": settings }))
    }

    async fn update_site_settings(&self, context: &AdminSessionContext) -> Result<Value, AppError> {
        let settings = site_settings_update(&context.payload)?;
        if settings.hostname.is_empty() {
            return Err(AppError::InvalidHostname);
        }
        self.repository.save_site_settings(&settings).await?;
        self.repository
            .write_audit(
                None,
                None,
                "site_settings_update",
                &format!("更新站点配置：{}", settings.hostname),
                &context.ip,
            )
            .await?;
        Ok(json!({
            "saved": true,
            "settings": site_settings_view(&settings)
        }))
    }

    async fn create_app(&self, payload: &Value) -> Result<Value, AppError> {
        let app_code = self.app_code(payload).await?;
        if self.repository.find_app_by_code(&app_code).await?.is_some() {
            return Err(AppError::InvalidInput("应用编号已存在"));
        }
        let app = self.new_app(payload, app_code)?;
        let app_id = self.repository.create_app(&app).await?;
        Ok(created_app_view(app_id, &app))
    }

    async fn overview(&self, payload: &Value) -> Result<Value, AppError> {
        let app_code = payload_string(payload, "app_code");
        let app_id = if app_code.is_empty() {
            None
        } else {
            Some(
                self.repository
                    .find_app_id_by_code(&app_code)
                    .await?
                    .ok_or(AppError::InvalidRoute)?,
            )
        };
        Ok(overview_view(
            self.repository.admin_overview(app_id).await?,
            &app_code,
        ))
    }

    async fn list_apps(&self, payload: &Value) -> Result<Value, AppError> {
        let page = int_range(payload.get("page"), 1, 1_000_000, 1);
        let limit = int_range(payload.get("limit"), 1, 100, 20);
        let offset = (page - 1) * limit;
        let apps = self.repository.list_apps(limit, offset).await?;
        let views = apps
            .into_iter()
            .map(|app| self.app_view(app))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(json!({ "apps": views }))
    }

    async fn update_app(&self, payload: &Value) -> Result<Value, AppError> {
        let app_id = positive_id(payload.get("app_id"))?;
        let current_app = self.load_app_by_id(app_id).await?;
        let update = app_settings_update(payload, &current_app)?;
        self.repository.update_app(app_id, &update).await?;
        Ok(json!({ "updated": true }))
    }

    async fn update_app_api(&self, payload: &Value) -> Result<Value, AppError> {
        let app_id = positive_id(payload.get("app_id"))?;
        let current_app = self.load_app_by_id(app_id).await?;
        let update = app_api_update(payload, &current_app)?;
        self.repository
            .update_app_api_config(app_id, &update)
            .await?;
        Ok(json!({ "updated": true }))
    }

    async fn generate_client_key_pair(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(payload, "app_code"))
            .await?;
        let client_crypto_alg = normalize_client_crypto_alg(&payload_string_or(
            payload,
            "client_crypto_alg",
            &app.client_crypto_alg,
        ))?;
        let key_pair = crypto::generate_client_rsa_key_pair(&self.system_key)?;
        let update = AppClientCryptoUpdate {
            client_crypto_alg: client_crypto_alg.clone(),
            client_public_key: key_pair.public_key,
            client_private_key_cipher: key_pair.private_key_cipher,
        };
        self.repository
            .update_app_client_crypto(app.id, &update)
            .await?;
        Ok(json!({
            "app_code": app.app_code,
            "client_crypto_alg": client_crypto_alg,
            "client_public_key": update.client_public_key,
        }))
    }

    async fn app_integration(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(payload, "app_code"))
            .await?;
        let remote_config = self.repository.find_remote_config(app.id).await?;
        Ok(json!({
            "api_url": self.sdk_api_url(payload).await?,
            "app": app_integration_view(&app, remote_config.as_ref(), &self.system_key)?,
            "sdk_types": sdk_types(),
            "client_routes": client_route_docs(),
            "error_codes": client_error_codes(),
        }))
    }

    async fn app_sdk(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(payload, "app_code"))
            .await?;
        if app.client_public_key.trim().is_empty() {
            return Err(AppError::AppKeyPairMissing);
        }
        let remote_config = self.repository.find_remote_config(app.id).await?;
        let context = SdkPackageContext {
            app_name: app.name.clone(),
            api_url: self.sdk_api_url(payload).await?,
            app_code: app.app_code.clone(),
            api_token: resolved_api_token_parts(&app.app_code, &app.api_token, &self.system_key)?,
            api_success_code: api_success_code(app.api_success_code),
            api_routes: api_routes_from_text(&app.api_config_json),
            app_version: remote_config
                .as_ref()
                .map(|config| config.version.clone())
                .unwrap_or_default(),
            client_auth_mode: CLIENT_AUTH_MODE.to_string(),
            client_crypto_alg: normalize_client_crypto_alg(&app.client_crypto_alg)?,
            client_public_key: app.client_public_key.clone(),
            sdk_type: payload_string_or(payload, "sdk_type", "cpp"),
        };
        build_sdk_package(&context)
    }

    async fn remote_app_api(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self.load_app_from_remote_payload(payload).await?;
        Ok(json!({
            "api": {
                "app_id": app.id.to_string(),
                "app_code": app.app_code,
                "api_token": resolved_api_token_parts(&app.app_code, &app.api_token, &self.system_key)?,
                "login_ip_binding_enabled": app.login_ip_binding_enabled,
                "web_card_query_enabled": app.web_card_query_enabled,
                "unbind_interval_seconds": app.unbind_interval_seconds,
                "unbind_deduct_seconds": app.unbind_deduct_seconds,
                "unbind_deduct_uses": app.unbind_deduct_uses,
                "api_success_code": api_success_code(app.api_success_code),
                "api_routes": api_routes_from_text(&app.api_config_json),
            }
        }))
    }

    async fn delete_apps(&self, payload: &Value) -> Result<Value, AppError> {
        let app_ids = ids(payload.get("app_ids"))?;
        self.ensure_apps_exist(&app_ids).await?;
        let deleted = self.repository.delete_apps(&app_ids).await?;
        Ok(json!({ "deleted": deleted }))
    }

    async fn batch_app_status(&self, payload: &Value) -> Result<Value, AppError> {
        let app_ids = ids(payload.get("app_ids"))?;
        self.ensure_apps_exist(&app_ids).await?;
        let status = status(payload.get("status"))?;
        let updated = self.repository.update_apps_status(&app_ids, status).await?;
        Ok(json!({ "updated": updated }))
    }

    async fn set_app_status(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(payload, "app_code"))
            .await?;
        self.repository
            .update_app_status(app.id, status(payload.get("status"))?)
            .await?;
        Ok(json!({ "updated": true }))
    }

    async fn list_audit_logs(&self, payload: &Value) -> Result<Value, AppError> {
        let app_code = payload_string(payload, "app_code");
        let app_id = self
            .repository
            .find_app_id_by_code(&app_code)
            .await?
            .ok_or(AppError::InvalidRoute)?;
        let page = int_range(payload.get("page"), 1, 1_000_000, 1);
        let limit = int_range(payload.get("limit"), 1, 100, 20);
        let offset = (page - 1) * limit;
        let logs = self
            .repository
            .list_audit_logs(app_id, limit, offset)
            .await?
            .into_iter()
            .map(audit_log_view)
            .collect::<Vec<_>>();
        Ok(json!({ "logs": logs }))
    }

    async fn list_messages(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(payload, "app_code"))
            .await?;
        let filters = message_filters(payload)?;
        let messages = self
            .repository
            .list_messages(app.id, &filters)
            .await?
            .into_iter()
            .map(|message| message_view(&message))
            .collect::<Vec<_>>();
        Ok(json!({ "messages": messages }))
    }

    async fn message_detail(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(payload, "app_code"))
            .await?;
        let message = self
            .repository
            .find_message_detail(app.id, message_id(payload.get("message_id"))?)
            .await?
            .ok_or(AppError::MessageNotFound)?;
        let actions = self
            .repository
            .list_message_actions(app.id, message.id)
            .await?;
        let audits = self
            .repository
            .list_message_audit_logs(app.id, message.id, 50)
            .await?;
        Ok(json!({
            "message": message_detail_view(&message, &actions, &audits)
        }))
    }

    async fn update_messages_status(
        &self,
        context: &AdminSessionContext,
        status: &str,
        action: &str,
    ) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(&context.payload, "app_code"))
            .await?;
        let message_ids = message_ids(&context.payload)?;
        let actor_name = current_admin_username(context)?;
        let update = status_update(&context.payload, status, action, &actor_name, &context.ip)?;
        let updated = self
            .repository
            .update_messages_status(app.id, &message_ids, &update)
            .await?;
        Ok(json!({ "updated": updated }))
    }

    async fn delete_messages(&self, context: &AdminSessionContext) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(&context.payload, "app_code"))
            .await?;
        let message_ids = message_ids(&context.payload)?;
        let deleted = self
            .repository
            .delete_messages(app.id, &message_ids, &context.ip)
            .await?;
        Ok(json!({ "deleted": deleted }))
    }

    async fn clear_app_activity_data(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(payload, "app_code"))
            .await?;
        let cleanup = self.repository.clear_app_activity_data(app.id).await?;
        Ok(activity_cleanup_view(cleanup, &app.app_code))
    }

    async fn act_message(&self, context: &AdminSessionContext) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(&context.payload, "app_code"))
            .await?;
        let message = self
            .repository
            .find_message_detail(app.id, message_id(context.payload.get("message_id"))?)
            .await?
            .ok_or(AppError::MessageNotFound)?;
        let actor_name = current_admin_username(context)?;
        let action = admin_action(&context.payload, &actor_name, &context.ip)?;
        let effect = self
            .repository
            .act_message(app.id, &message, &action)
            .await?;
        Ok(action_effect_view(effect))
    }

    async fn get_config(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(payload, "app_code"))
            .await?;
        let config = self.repository.find_remote_config(app.id).await?;
        Ok(json!({ "config": remote_config_view(config.as_ref()) }))
    }

    async fn set_config(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(payload, "app_code"))
            .await?;
        let current = self.repository.find_remote_config(app.id).await?;
        let config = remote_config_upsert(app.id, current.as_ref(), payload)?;
        self.repository.upsert_remote_config(&config).await?;
        Ok(json!({ "saved": true }))
    }

    async fn set_legacy_variables(&self) -> Result<Value, AppError> {
        Err(AppError::RemoteVariablesMoved)
    }

    async fn list_variables(&self, payload: &Value) -> Result<Value, AppError> {
        let filters = remote_variable_filters(payload)?;
        let variables = self
            .repository
            .list_remote_variables(&filters)
            .await?
            .into_iter()
            .map(remote_variable_view)
            .collect::<Vec<_>>();
        Ok(json!({ "variables": variables }))
    }

    async fn create_variable(&self, payload: &Value) -> Result<Value, AppError> {
        let input = remote_variable_payload(payload, &self.system_key)?;
        self.ensure_variable_apps_exist(&input.app_ids).await?;
        let variable_id = self
            .repository
            .create_remote_variable(&input.variable, &input.app_ids)
            .await?;
        Ok(json!({
            "saved": true,
            "variable_id": variable_id,
        }))
    }

    async fn update_variable(&self, payload: &Value) -> Result<Value, AppError> {
        let variable_id = remote_variable_id(payload.get("variable_id"))?;
        self.load_remote_variable(variable_id).await?;
        let input = remote_variable_payload(payload, &self.system_key)?;
        self.ensure_variable_apps_exist(&input.app_ids).await?;
        self.repository
            .update_remote_variable(variable_id, &input.variable, &input.app_ids)
            .await?;
        Ok(json!({
            "saved": true,
            "variable_id": variable_id,
        }))
    }

    async fn set_variable_status(&self, payload: &Value) -> Result<Value, AppError> {
        let variable_id = remote_variable_id(payload.get("variable_id"))?;
        self.load_remote_variable(variable_id).await?;
        self.repository
            .update_remote_variable_status(
                variable_id,
                remote_variable_status(payload.get("status")),
            )
            .await?;
        Ok(json!({ "saved": true }))
    }

    async fn delete_variable(&self, payload: &Value) -> Result<Value, AppError> {
        let variable_id = remote_variable_id(payload.get("variable_id"))?;
        self.load_remote_variable(variable_id).await?;
        self.repository.delete_remote_variable(variable_id).await?;
        Ok(json!({ "deleted": true }))
    }

    async fn batch_variable_status(&self, payload: &Value) -> Result<Value, AppError> {
        let variable_ids = remote_variable_ids(payload.get("variable_ids"))?;
        let updated = self
            .repository
            .update_remote_variables_status(
                &variable_ids,
                remote_variable_status(payload.get("status")),
            )
            .await?;
        Ok(json!({ "updated": updated }))
    }

    async fn batch_delete_variables(&self, payload: &Value) -> Result<Value, AppError> {
        let variable_ids = remote_variable_ids(payload.get("variable_ids"))?;
        let deleted = self
            .repository
            .delete_remote_variables(&variable_ids)
            .await?;
        Ok(json!({ "deleted": deleted }))
    }

    async fn convert_variable(&self, payload: &Value) -> Result<Value, AppError> {
        let variable_id = remote_variable_id(payload.get("variable_id"))?;
        let variable = self.load_remote_variable(variable_id).await?;
        let scope = remote_variable_scope(&payload_string(payload, "scope"))?;
        let app_ids = if scope == "private" {
            remote_variable_app_ids(payload.get("app_ids"))?
        } else {
            Vec::new()
        };
        self.ensure_variable_apps_exist(&app_ids).await?;
        let input = converted_remote_variable_input(&variable, scope);
        self.repository
            .update_remote_variable(variable_id, &input, &app_ids)
            .await?;
        Ok(json!({ "saved": true }))
    }

    async fn set_variable_apps(&self, payload: &Value) -> Result<Value, AppError> {
        let variable_id = remote_variable_id(payload.get("variable_id"))?;
        let variable = self.load_remote_variable(variable_id).await?;
        if variable.scope != "private" {
            return Err(AppError::InvalidVariableScope);
        }
        let app_ids = remote_variable_app_ids(payload.get("app_ids"))?;
        self.ensure_variable_apps_exist(&app_ids).await?;
        self.repository
            .replace_remote_variable_apps(variable_id, &app_ids)
            .await?;
        Ok(json!({ "saved": true }))
    }

    async fn upsert_remote_variable_by_name(&self, payload: &Value) -> Result<Value, AppError> {
        let input = remote_variable_payload(payload, &self.system_key)?;
        self.ensure_variable_apps_exist(&input.app_ids).await?;
        let existing = self
            .repository
            .find_remote_variable_by_name(&input.variable.name)
            .await?;
        let (variable_id, created) = match existing {
            Some(variable) => {
                self.repository
                    .update_remote_variable(variable.id, &input.variable, &input.app_ids)
                    .await?;
                (variable.id, false)
            }
            None => (
                self.repository
                    .create_remote_variable(&input.variable, &input.app_ids)
                    .await?,
                true,
            ),
        };
        Ok(json!({
            "saved": true,
            "variable_id": variable_id,
            "created": created,
        }))
    }

    async fn set_remote_variable_status_by_names(
        &self,
        payload: &Value,
    ) -> Result<Value, AppError> {
        let variables = self.load_remote_variables_by_names(payload).await?;
        let variable_ids = variables
            .iter()
            .map(|variable| variable.id)
            .collect::<Vec<_>>();
        let updated = self
            .repository
            .update_remote_variables_status(
                &variable_ids,
                remote_variable_status(payload.get("status")),
            )
            .await?;
        Ok(json!({ "updated": updated }))
    }

    async fn delete_remote_variables_by_names(&self, payload: &Value) -> Result<Value, AppError> {
        let variables = self.load_remote_variables_by_names(payload).await?;
        let variable_ids = variables
            .iter()
            .map(|variable| variable.id)
            .collect::<Vec<_>>();
        Ok(json!({
            "deleted": self.repository.delete_remote_variables(&variable_ids).await?
        }))
    }

    async fn convert_remote_variable_by_name(&self, payload: &Value) -> Result<Value, AppError> {
        let variable = self.load_remote_variable_by_payload_name(payload).await?;
        let scope = remote_variable_scope(&payload_string(payload, "scope"))?;
        let app_ids = if scope == "private" {
            remote_variable_app_ids(payload.get("app_ids"))?
        } else {
            Vec::new()
        };
        self.ensure_variable_apps_exist(&app_ids).await?;
        let input = converted_remote_variable_input(&variable, scope);
        self.repository
            .update_remote_variable(variable.id, &input, &app_ids)
            .await?;
        Ok(json!({ "saved": true }))
    }

    async fn set_remote_variable_apps_by_name(&self, payload: &Value) -> Result<Value, AppError> {
        let variable = self.load_remote_variable_by_payload_name(payload).await?;
        if variable.scope != "private" {
            return Err(AppError::InvalidVariableScope);
        }
        let app_ids = remote_variable_app_ids(payload.get("app_ids"))?;
        self.ensure_variable_apps_exist(&app_ids).await?;
        self.repository
            .replace_remote_variable_apps(variable.id, &app_ids)
            .await?;
        Ok(json!({ "saved": true }))
    }

    async fn list_remote_api_tokens(&self, payload: &Value) -> Result<Value, AppError> {
        let filters = remote_api_token_filters(payload)?;
        let tokens = self
            .repository
            .list_remote_api_tokens(&filters)
            .await?
            .into_iter()
            .map(|token| remote_api_token_view(&token))
            .collect::<Vec<_>>();
        Ok(json!({ "tokens": tokens }))
    }

    async fn create_remote_api_token(
        &self,
        payload: &Value,
        context: &AdminSessionContext,
    ) -> Result<Value, AppError> {
        let secret = crypto::token(32);
        let access_key = self.unique_remote_api_access_key().await?;
        let secret_cipher = crypto::encrypt_protected_text(&secret, &self.system_key)?;
        let token = new_remote_api_token(
            payload,
            access_key,
            secret_cipher,
            current_admin_username(context)?,
        )?;
        let token_id = self.repository.create_remote_api_token(&token).await?;
        Ok(json!({
            "created": true,
            "token": remote_api_created_token_view(token_id, &token),
            "secret": secret,
        }))
    }

    async fn remote_api_token_secret(&self, payload: &Value) -> Result<Value, AppError> {
        let token = self
            .load_remote_api_token(remote_api_token_id(payload.get("token_id"))?)
            .await?;
        let secret = crypto::decrypt_protected_text(&token.secret_cipher, &self.system_key)?;
        Ok(json!({
            "token": remote_api_token_detail_view(&token),
            "secret": secret,
        }))
    }

    async fn set_remote_api_token_status(&self, payload: &Value) -> Result<Value, AppError> {
        let token_id = remote_api_token_id(payload.get("token_id"))?;
        self.load_remote_api_token(token_id).await?;
        self.repository
            .update_remote_api_token_status(
                token_id,
                remote_api_token_status(payload.get("status"))?,
            )
            .await?;
        Ok(json!({ "updated": true }))
    }

    async fn delete_remote_api_token(&self, payload: &Value) -> Result<Value, AppError> {
        let token_id = remote_api_token_id(payload.get("token_id"))?;
        self.load_remote_api_token(token_id).await?;
        self.repository.delete_remote_api_token(token_id).await?;
        Ok(json!({ "deleted": true }))
    }

    async fn list_remote_api_logs(&self, payload: &Value) -> Result<Value, AppError> {
        let filters = remote_api_log_filters(payload)?;
        let logs = self
            .repository
            .list_remote_api_logs(&filters)
            .await?
            .into_iter()
            .map(|log| remote_api_log_view(&log))
            .collect::<Vec<_>>();
        Ok(json!({ "logs": logs }))
    }

    async fn delete_remote_api_logs(&self, payload: &Value) -> Result<Value, AppError> {
        let log_ids = remote_api_log_ids(payload)?;
        let deleted = self.repository.delete_remote_api_logs(&log_ids).await?;
        Ok(json!({ "deleted": deleted }))
    }

    async fn clear_remote_api_logs(&self, payload: &Value) -> Result<Value, AppError> {
        assert_remote_api_logs_clear_confirmed(payload)?;
        Ok(json!({ "deleted": self.repository.clear_remote_api_logs().await? }))
    }

    async fn cloud_storage_summary(&self) -> Result<Value, AppError> {
        self.ensure_cloud_local_config().await?;
        cloud_storage_summary_view(
            self.repository.cloud_storage_summary().await?,
            &self.system_key,
        )
    }

    async fn list_cloud_files(&self, payload: &Value) -> Result<Value, AppError> {
        let filters = cloud_file_filters(payload)?;
        let files = self
            .repository
            .list_cloud_files(&filters)
            .await?
            .into_iter()
            .map(|file| cloud_file_view(&file))
            .collect::<Vec<_>>();
        Ok(json!({ "files": files }))
    }

    async fn cloud_file_detail(&self, payload: &Value) -> Result<Value, AppError> {
        let file = self
            .repository
            .find_cloud_file_by_id(positive_id(payload.get("file_id"))?)
            .await?
            .ok_or(AppError::CloudFileNotFound)?;
        Ok(json!({ "file": cloud_file_view(&file) }))
    }

    async fn delete_cloud_file(&self, payload: &Value) -> Result<Value, AppError> {
        let file_id = positive_id(payload.get("file_id"))?;
        let file = self
            .repository
            .find_cloud_file_by_id(file_id)
            .await?
            .ok_or(AppError::CloudFileNotFound)?;
        if file.status != "active" {
            return Ok(json!({ "deleted": true }));
        }
        let config = self.cloud_config_for_file(&file).await?;
        delete_cloud_object(&config, &file.object_key, &self.system_key).await?;
        self.repository.mark_cloud_file_deleted(file.id).await?;
        Ok(json!({ "deleted": true }))
    }

    async fn create_cloud_upload_ticket(
        &self,
        payload: &Value,
        context: &AdminSessionContext,
    ) -> Result<Value, AppError> {
        self.ensure_cloud_local_config().await?;
        let config = require_enabled_default_config(
            self.repository.find_default_cloud_storage_config().await?,
        )?;
        let ticket =
            create_upload_ticket_payload(payload, &config, context.session_id, &self.system_key)?;
        self.repository
            .create_cloud_upload_ticket(&ticket.ticket)
            .await?;
        Ok(upload_ticket_response(&ticket, &config.provider))
    }

    pub async fn upload_cloud_file(
        &self,
        context: &AdminUploadSessionContext,
        upload: CloudUploadForm,
    ) -> Result<Value, AppError> {
        let ticket_token = upload_ticket_token(&upload.ticket)?;
        let ticket_hash = upload_ticket_hash(&ticket_token, &self.system_key)?;
        let ticket = require_pending_upload_ticket(
            self.repository
                .find_cloud_upload_ticket_by_hash(&ticket_hash)
                .await?,
        )?;
        assert_upload_session(&ticket, context.session_id)?;
        let config = self
            .repository
            .find_cloud_storage_config_by_provider(&ticket.provider)
            .await?
            .ok_or(AppError::CloudStorageConfigMissing)?;
        if !self
            .repository
            .mark_cloud_upload_ticket_used(ticket.id, Local::now().naive_local())
            .await?
        {
            return Err(AppError::CloudUploadTicketInvalid);
        }
        let file_input = store_cloud_upload(&ticket, &config, upload, &self.system_key).await?;
        let file_id = self.repository.create_cloud_file(&file_input).await?;
        let file = self
            .repository
            .find_cloud_file_by_id(file_id)
            .await?
            .ok_or(AppError::CloudFileNotFound)?;
        Ok(json!({ "file": cloud_file_view(&file) }))
    }

    async fn upload_cloud_file_base64(&self, payload: &Value) -> Result<Value, AppError> {
        self.ensure_cloud_local_config().await?;
        let config = require_enabled_default_config(
            self.repository.find_default_cloud_storage_config().await?,
        )?;
        let file_input = store_cloud_base64_upload(payload, &config, &self.system_key).await?;
        let file_id = self.repository.create_cloud_file(&file_input).await?;
        let file = self
            .repository
            .find_cloud_file_by_id(file_id)
            .await?
            .ok_or(AppError::CloudFileNotFound)?;
        Ok(json!({ "file": cloud_file_view(&file) }))
    }

    async fn get_cloud_storage_config(&self) -> Result<Value, AppError> {
        self.ensure_cloud_local_config().await?;
        let configs = self.repository.list_cloud_storage_configs().await?;
        let default_config = self.repository.find_default_cloud_storage_config().await?;
        Ok(cloud_config_get_view(&configs, default_config.as_ref()))
    }

    async fn save_cloud_storage_config(&self, payload: &Value) -> Result<Value, AppError> {
        let provider = cloud_config_provider(payload)?;
        let existing = self
            .repository
            .find_cloud_storage_config_by_provider(&provider)
            .await?;
        let payload = cloud_config_payload(payload, existing.as_ref(), &self.system_key, true)?;
        let config_id = self
            .repository
            .upsert_cloud_storage_config(&payload.config)
            .await?;
        if payload.set_default {
            self.repository
                .set_default_cloud_storage_config(config_id)
                .await?;
        }
        let config = self
            .repository
            .find_cloud_storage_config_by_id(config_id)
            .await?
            .ok_or(AppError::CloudStorageConfigMissing)?;
        Ok(json!({
            "saved": true,
            "config": config_view(Some(&config)),
        }))
    }

    async fn test_cloud_storage_config(&self, payload: &Value) -> Result<Value, AppError> {
        let provider = cloud_config_provider(payload)?;
        let existing = self
            .repository
            .find_cloud_storage_config_by_provider(&provider)
            .await?;
        let payload = cloud_config_payload(payload, existing.as_ref(), &self.system_key, false)?;
        let result = run_cloud_storage_config_test(&payload.config, &self.system_key).await?;
        if let Some(stored) = existing {
            self.repository
                .update_cloud_storage_test_result(
                    stored.id,
                    result["status"].as_str().unwrap_or("success"),
                    result["message"].as_str().unwrap_or("配置格式有效"),
                    Some(Local::now().naive_local()),
                )
                .await?;
        }
        Ok(result)
    }

    async fn get_cloud_download_token(&self) -> Result<Value, AppError> {
        Ok(json!({
            "download_token": download_token_view(
                self.repository.find_cloud_download_token().await?.as_ref(),
                &self.system_key,
            )?
        }))
    }

    async fn refresh_cloud_download_token(&self) -> Result<Value, AppError> {
        let token = crypto::token(32);
        self.repository
            .upsert_cloud_download_token(&CloudDownloadTokenInput {
                token_hash: download_token_hash(&token, &self.system_key)?,
                token_cipher: crypto::encrypt_protected_text(&token, &self.system_key)?,
                status: FLAG_ENABLED,
            })
            .await?;
        self.get_cloud_download_token().await
    }

    async fn set_cloud_download_token_status(&self, payload: &Value) -> Result<Value, AppError> {
        let status = enabled_flag(payload.get("status"));
        let token = self.repository.find_cloud_download_token().await?;
        if status == FLAG_ENABLED
            && token
                .as_ref()
                .is_none_or(|token| token.token_hash.trim().is_empty())
        {
            return Err(AppError::CloudDownloadTokenMissing);
        }
        self.repository
            .update_cloud_download_token_status(status)
            .await?;
        self.get_cloud_download_token().await
    }

    async fn create_cards(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(payload, "app_code"))
            .await?;
        let rule = card_rule(payload, &app)?;
        let count = payload_int_range(payload.get("count"), 1, MAX_CARD_IMPORT_COUNT as i64, 1)?;
        let prefix = card_prefix(&payload_string(payload, "prefix"))?;
        let structure = card_structure(&payload_string_or(payload, "card_structure", "hex"))?;
        let card_length = payload_int_range(payload.get("card_length"), 8, 64, 24)?;
        let card_keys = create_card_keys(&prefix, &structure, card_length, count as usize)?;
        let cards = build_new_cards(
            &app,
            &card_keys,
            &rule,
            &structure,
            &prefix,
            &self.system_key,
        )?;
        self.repository.create_cards(&cards).await?;
        Ok(card_create_response(&card_keys, &rule))
    }

    async fn import_cards(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(payload, "app_code"))
            .await?;
        let rule = card_rule(payload, &app)?;
        let card_import = parse_card_import(payload.get("custom_cards"))?;
        if card_import.cards.is_empty() {
            return Err(AppError::InvalidInput("请填写要导入的卡密"));
        }
        self.ensure_import_cards_are_new(&app, &card_import.cards)
            .await?;
        let cards = build_new_cards(
            &app,
            &card_import.cards,
            &rule,
            "custom",
            "",
            &self.system_key,
        )?;
        self.repository.create_cards(&cards).await?;
        Ok(card_import_response(&card_import, &rule))
    }

    async fn export_cards(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(payload, "app_code"))
            .await?;
        let keyword = safe_text(&payload_string(payload, "keyword"), 120)?;
        let status = card_status_filter(&payload_string(payload, "status"))?;
        let duration_category =
            card_duration_category(&payload_string(payload, "duration_category"))?;
        let card_ids = export_card_ids(payload)?;
        let cards = self
            .card_rows_for_export(&app, &status, &duration_category, &keyword, &card_ids)
            .await?;
        let selected_ids = selected_export_ids(&card_ids);
        let views =
            self.export_card_views(cards, &status, &duration_category, &keyword, &selected_ids)?;
        let card_keys = exportable_card_keys(&views)?;
        if card_keys.is_empty() {
            return Err(AppError::InvalidInput("没有可导出的完整卡密"));
        }
        Ok(card_export_response(&app.app_code, &card_keys, views.len()))
    }

    async fn list_cards(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(payload, "app_code"))
            .await?;
        let page = payload_int_range(payload.get("page"), 1, 1_000_000, 1)?;
        let limit = payload_int_range(payload.get("limit"), 1, 100, 20)?;
        let mut query = card_query(payload, &app, page, limit, &self.system_key)?;
        let total = self.repository.count_cards(app.id, &query).await?;
        let total_pages = ((total + limit - 1) / limit).max(1);
        if total == 0 {
            query.offset = 0;
        } else if query.offset >= total {
            query.offset = (total_pages - 1) * limit;
        }
        let cards = self
            .repository
            .list_cards(app.id, app.heartbeat_enabled == FLAG_ENABLED, &query)
            .await?
            .into_iter()
            .map(|card| self.card_view(card))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(json!({
            "cards": cards,
            "total": total,
            "page": query.offset / limit + 1,
            "limit": limit,
            "total_pages": total_pages,
        }))
    }

    async fn set_card_status(&self, payload: &Value) -> Result<Value, AppError> {
        let card = self.load_card(positive_id(payload.get("card_id"))?).await?;
        let status = card_status_value(payload.get("status"))?;
        let next_status = if status == FLAG_DISABLED {
            enabled_card_status(&card)
        } else {
            2
        };
        self.repository
            .update_card_status(card.id, next_status)
            .await?;
        Ok(json!({ "updated": true }))
    }

    async fn revoke_card(&self, payload: &Value) -> Result<Value, AppError> {
        self.repository
            .update_card_status(positive_id(payload.get("card_id"))?, 2)
            .await?;
        Ok(json!({ "revoked": true }))
    }

    async fn delete_cards(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(payload, "app_code"))
            .await?;
        let deleted = self
            .repository
            .delete_cards(app.id, &ids(payload.get("card_ids"))?)
            .await?;
        Ok(json!({ "deleted": deleted }))
    }

    async fn batch_card_status(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(payload, "app_code"))
            .await?;
        let card_ids = ids(payload.get("card_ids"))?;
        let status = card_status_value(payload.get("status"))?;
        if status == 2 {
            let updated = self
                .repository
                .update_cards_status(app.id, &card_ids, 2)
                .await?;
            return Ok(json!({ "updated": updated }));
        }
        let mut updated = 0_u64;
        for card_id in card_ids {
            let card = self.load_card_in_app(&app, card_id).await?;
            self.repository
                .update_card_status(card.id, enabled_card_status(&card))
                .await?;
            updated += 1;
        }
        Ok(json!({ "updated": updated }))
    }

    async fn adjust_card_duration(&self, payload: &Value) -> Result<Value, AppError> {
        let card = self.load_card(positive_id(payload.get("card_id"))?).await?;
        assert_time_card(&card)?;
        let duration_seconds = required_int_range(
            payload.get("duration_seconds"),
            MIN_CARD_DURATION_SECONDS,
            MAX_CARD_DURATION_SECONDS,
        )?;
        let direction = card_duration_direction(&payload_string_or(payload, "direction", "add"))?;
        if direction == "reset" {
            let revoked_sessions = self
                .repository
                .reset_time_card_duration(&card, duration_seconds)
                .await?;
            return Ok(json!({
                "duration_seconds": duration_seconds,
                "expires_at": "",
                "revoked_sessions": revoked_sessions,
            }));
        }
        let next_duration =
            adjusted_card_duration(card.duration_seconds, duration_seconds, &direction);
        self.repository
            .update_card_duration(card.id, next_duration)
            .await?;
        Ok(json!({
            "duration_seconds": next_duration,
            "expires_at": card_expiry_after_duration(&card, next_duration),
        }))
    }

    async fn batch_adjust_card_duration(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(payload, "app_code"))
            .await?;
        let card_ids = ids(payload.get("card_ids"))?;
        let duration_seconds = required_int_range(
            payload.get("duration_seconds"),
            MIN_CARD_DURATION_SECONDS,
            MAX_CARD_DURATION_SECONDS,
        )?;
        let direction =
            batch_card_duration_direction(&payload_string_or(payload, "direction", "add"))?;
        let mut card_durations = Vec::new();
        for card_id in card_ids {
            let card = self.load_card_in_app(&app, card_id).await?;
            if is_time_card(&card)? {
                let next_duration =
                    adjusted_card_duration(card.duration_seconds, duration_seconds, &direction);
                card_durations.push((card.id, next_duration));
            }
        }
        let updated = self
            .repository
            .update_card_durations(&card_durations)
            .await?;
        Ok(json!({ "updated": updated }))
    }

    async fn operate_cards_by_activated_range(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(payload, "app_code"))
            .await?;
        let range = card_activated_range(payload)?;
        let operation = card_range_operation(&payload_string(payload, "operation"))?;
        if is_card_range_duration_operation(&operation) {
            return self
                .operate_time_cards_by_activated_range(app.id, &range, &operation, payload)
                .await;
        }
        self.operate_general_cards_by_activated_range(app.id, &range, &operation)
            .await
    }

    async fn reset_card_uses(&self, payload: &Value) -> Result<Value, AppError> {
        let card = self.load_card(positive_id(payload.get("card_id"))?).await?;
        if normalize_card_type(&card.card_type)? != "count" {
            return Err(AppError::InvalidInput("卡密类型必须为次数卡"));
        }
        self.repository.reset_count_card_uses(card.id).await?;
        Ok(card_reset_uses_response(card.total_uses))
    }

    async fn batch_reset_card_uses(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(payload, "app_code"))
            .await?;
        let updated = self
            .repository
            .reset_count_cards_uses(app.id, &ids(payload.get("card_ids"))?)
            .await?;
        Ok(json!({ "updated": updated }))
    }

    async fn list_card_devices(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(payload, "app_code"))
            .await?;
        let card = self
            .load_card_in_app(&app, positive_id(payload.get("card_id"))?)
            .await?;
        if normalize_card_type(&card.card_type)? == "count" {
            return Ok(json!({ "devices": [] }));
        }
        let devices = self
            .repository
            .list_card_devices(app.id, card.id)
            .await?
            .into_iter()
            .map(device_view)
            .collect::<Vec<_>>();
        Ok(json!({ "devices": devices }))
    }

    async fn list_accounts(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(payload, "app_code"))
            .await?;
        let (limit, offset) = pagination(payload)?;
        let accounts = self
            .repository
            .list_accounts(app.id, limit, offset)
            .await?
            .into_iter()
            .map(account_view)
            .collect::<Vec<_>>();
        Ok(json!({ "accounts": accounts }))
    }

    async fn set_account_status(&self, payload: &Value) -> Result<Value, AppError> {
        self.repository
            .update_account_status(
                positive_id(payload.get("account_id"))?,
                status(payload.get("status"))?,
            )
            .await?;
        Ok(json!({ "updated": true }))
    }

    async fn extend_account(&self, payload: &Value) -> Result<Value, AppError> {
        let account_id = positive_id(payload.get("account_id"))?;
        let account = self
            .repository
            .find_account_by_id(account_id)
            .await?
            .ok_or(AppError::AccountNotFound)?;
        let duration_seconds = payload_int_range(
            payload.get("duration_seconds"),
            MIN_CARD_DURATION_SECONDS,
            MAX_CARD_DURATION_SECONDS,
            86_400,
        )?;
        let now = Local::now().naive_local();
        let base_time = if account.expires_at > now {
            account.expires_at
        } else {
            now
        };
        let expires_at = base_time + Duration::seconds(duration_seconds);
        self.repository
            .update_account_expiry(account_id, expires_at)
            .await?;
        Ok(json!({ "expires_at": expires_at.format("%Y-%m-%d %H:%M:%S").to_string() }))
    }

    async fn list_devices(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(payload, "app_code"))
            .await?;
        let (limit, offset) = pagination(payload)?;
        let account_id = optional_non_negative_id(payload.get("account_id"))?;
        let devices = self
            .repository
            .list_devices(app.id, account_id, limit, offset)
            .await?
            .into_iter()
            .map(device_view)
            .collect::<Vec<_>>();
        Ok(json!({ "devices": devices }))
    }

    async fn get_security_policy(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(payload, "app_code"))
            .await?;
        let policy = self.repository.find_security_policy(app.id).await?;
        Ok(json!({ "policy": security_policy_view(policy.as_ref())? }))
    }

    async fn set_security_policy(&self, context: &AdminSessionContext) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(&context.payload, "app_code"))
            .await?;
        let policy = security_policy_payload(&context.payload, app.id, &admin_actor_name(context))?;
        self.repository.upsert_security_policy(&policy).await?;
        self.repository
            .write_audit(
                Some(app.id),
                None,
                "security_policy_update",
                &format!("更新安全上报策略：{}", policy.mode),
                &context.ip,
            )
            .await?;
        Ok(json!({
            "saved": true,
            "policy": security_policy_input_view(&policy)?
        }))
    }

    async fn unbind_card_device(&self, payload: &Value) -> Result<Value, AppError> {
        self.repository
            .delete_device(positive_id(payload.get("device_id"))?)
            .await?;
        Ok(json!({ "unbound": true }))
    }

    async fn unbind_card_devices(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(payload, "app_code"))
            .await?;
        let card_id = positive_id(payload.get("card_id"))?;
        let unbound = self.repository.delete_card_devices(app.id, card_id).await?;
        Ok(json!({ "unbound": unbound }))
    }

    async fn batch_card_devices_status(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(payload, "app_code"))
            .await?;
        let status = status(payload.get("status"))?;
        let mut affected_cards = 0_u64;
        let mut device_ids = Vec::new();
        for card_id in ids(payload.get("card_ids"))? {
            let devices = self.manageable_card_devices(&app, card_id).await?;
            if devices.is_empty() {
                continue;
            }
            affected_cards += 1;
            device_ids.extend(devices.into_iter().map(|device| device.id));
        }
        let device_ids = unique_device_ids(device_ids);
        let revoked_sessions = self
            .repository
            .update_app_devices_status(app.id, &device_ids, status)
            .await?;
        Ok(json!({
            "updated_devices": device_ids.len(),
            "affected_cards": affected_cards,
            "revoked_sessions": revoked_sessions,
        }))
    }

    async fn batch_unbind_card_devices(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(payload, "app_code"))
            .await?;
        let mut affected_cards = 0_u64;
        let mut device_ids = Vec::new();
        for card_id in ids(payload.get("card_ids"))? {
            let devices = self.manageable_card_devices(&app, card_id).await?;
            if devices.is_empty() {
                continue;
            }
            affected_cards += 1;
            device_ids.extend(devices.into_iter().map(|device| device.id));
        }
        let unbound_devices = self
            .repository
            .delete_app_devices(app.id, &unique_device_ids(device_ids))
            .await?;
        Ok(json!({
            "unbound_devices": unbound_devices,
            "affected_cards": affected_cards,
        }))
    }

    async fn set_device_status(&self, payload: &Value) -> Result<Value, AppError> {
        let app = self
            .load_app_by_code(&payload_string(payload, "app_code"))
            .await?;
        let device_id = positive_id(payload.get("device_id"))?;
        let device = self
            .repository
            .find_device_by_id(device_id)
            .await?
            .ok_or(AppError::DeviceNotFound)?;
        if device.app_id != app.id {
            return Err(AppError::DeviceNotFound);
        }
        let status = status(payload.get("status"))?;
        self.repository
            .update_device_status(device_id, status)
            .await?;
        let revoked_sessions = if status == FLAG_DISABLED {
            self.repository
                .revoke_device_sessions(app.id, device_id)
                .await?
        } else {
            0
        };
        Ok(json!({
            "updated": true,
            "revoked_sessions": revoked_sessions,
        }))
    }

    async fn cleanup_nonces(&self) -> Result<Value, AppError> {
        let now = Local::now().naive_local();
        let security_data = self.repository.cleanup_security_data(now, 1000).await?;
        Ok(json!({
            "deleted_nonces": self.repository.delete_expired_nonces(now).await?,
            "deleted_sessions": self.repository.delete_expired_sessions(now).await?,
            "deleted_login_challenges": self.repository.delete_expired_login_challenges(now).await?,
            "deleted_admin_nonces": self.repository.delete_expired_admin_nonces(now).await?,
            "deleted_admin_sessions": self.repository.delete_expired_admin_sessions(now).await?,
            "deleted_remote_api_nonces": self.repository.delete_expired_remote_api_nonces(now).await?,
            "deleted_cloud_upload_tickets": self.repository.delete_expired_cloud_upload_tickets(now).await?,
            "security_data": security_cleanup_view(security_data),
        }))
    }

    fn app_view(&self, app: AppRow) -> Result<Value, AppError> {
        Ok(json!({
            "id": app.id,
            "app_code": app.app_code,
            "api_token": resolved_api_token(&app, &self.system_key)?,
            "name": app.name,
            "status": app.status,
            "max_devices": app.max_devices,
            "heartbeat_interval": app.heartbeat_interval,
            "heartbeat_enabled": app.heartbeat_enabled,
            "verification_enabled": app.verification_enabled,
            "device_binding_enabled": app.device_binding_enabled,
            "shared_cards_enabled": app.shared_cards_enabled,
            "login_ip_binding_enabled": app.login_ip_binding_enabled,
            "web_card_query_enabled": app.web_card_query_enabled,
            "unbind_interval_seconds": app.unbind_interval_seconds,
            "unbind_deduct_seconds": app.unbind_deduct_seconds,
            "unbind_deduct_uses": app.unbind_deduct_uses,
            "api_success_code": api_success_code(app.api_success_code),
            "api_routes": api_routes_from_text(&app.api_config_json),
            "latest_version": app.latest_version,
            "client_auth_mode": CLIENT_AUTH_MODE,
            "client_crypto_alg": app.client_crypto_alg,
            "remark": app.remark,
            "created_at": format_datetime(app.created_at),
            "updated_at": format_datetime(app.updated_at),
            "cards_total": app.cards_total,
            "devices_total": app.devices_total,
            "sessions_active": app.sessions_active,
        }))
    }

    fn card_view(&self, card: CardRow) -> Result<Value, AppError> {
        card_view(card, &self.system_key)
    }

    async fn app_code(&self, payload: &Value) -> Result<String, AppError> {
        let app_code = payload_string(payload, "app_code");
        if app_code.is_empty() {
            return self.generate_app_code().await;
        }
        validate_app_code(&app_code)
    }

    fn new_app(&self, payload: &Value, app_code: String) -> Result<NewApp, AppError> {
        let key_pair = crypto::generate_client_rsa_key_pair(&self.system_key)?;
        Ok(NewApp {
            app_code,
            api_token: crypto::token(32),
            name: safe_text(&payload_string(payload, "name"), 80)?,
            status: FLAG_ENABLED,
            max_devices: DEFAULT_MAX_DEVICES,
            heartbeat_interval: session_ttl(payload)?,
            heartbeat_enabled: binary_flag(payload, "heartbeat_enabled", FLAG_ENABLED)?,
            verification_enabled: binary_flag(payload, "verification_enabled", FLAG_ENABLED)?,
            device_binding_enabled: binary_flag(payload, "device_binding_enabled", FLAG_ENABLED)?,
            shared_cards_enabled: binary_flag(payload, "shared_cards_enabled", FLAG_DISABLED)?,
            login_ip_binding_enabled: FLAG_DISABLED,
            web_card_query_enabled: FLAG_DISABLED,
            unbind_interval_seconds: 0,
            unbind_deduct_seconds: 0,
            unbind_deduct_uses: 0,
            api_success_code: 0,
            api_config_json: serde_json::to_string(&api_route_defaults())
                .map_err(|_| AppError::InvalidApiRoutes)?,
            latest_version: safe_text(&payload_string(payload, "latest_version"), 40)?,
            client_auth_mode: CLIENT_AUTH_MODE.to_string(),
            client_crypto_alg: normalize_client_crypto_alg(&optional_payload_string(
                payload,
                "client_crypto_alg",
            ))?,
            client_public_key: key_pair.public_key,
            client_private_key_cipher: key_pair.private_key_cipher,
            remark: safe_text(&payload_string(payload, "remark"), 255)?,
        })
    }

    async fn generate_app_code(&self) -> Result<String, AppError> {
        for _ in 0..MAX_APP_CODE_ATTEMPTS {
            let app_code = format!("ACE{}", random_upper_hex(5));
            if self.repository.find_app_by_code(&app_code).await?.is_none() {
                return Ok(app_code);
            }
        }
        Err(AppError::AppCodeExhausted)
    }

    async fn load_current_admin(
        &self,
        context: &AdminSessionContext,
    ) -> Result<AdminRow, AppError> {
        let username = current_admin_username(context)?;
        self.repository
            .find_admin_by_username(&username)
            .await?
            .ok_or(AppError::AdminNotFound)
    }

    async fn assert_admin_username_available(
        &self,
        current_username: &str,
        next_username: &str,
    ) -> Result<(), AppError> {
        if current_username == next_username {
            return Ok(());
        }
        if self
            .repository
            .find_admin_by_username(next_username)
            .await?
            .is_some()
        {
            return Err(AppError::InvalidInput("该管理员账号已存在"));
        }
        Ok(())
    }

    async fn sdk_api_url(&self, payload: &Value) -> Result<String, AppError> {
        let api_url = safe_text(&payload_string(payload, "api_url"), 500)?;
        if !api_url.is_empty() {
            return validate_api_url(&api_url);
        }
        let Some(settings) = self.repository.get_site_settings().await? else {
            return Err(AppError::InvalidApiUrl);
        };
        let site_url = settings.siteurl.trim();
        if site_url.is_empty() {
            return Err(AppError::InvalidApiUrl);
        }
        validate_api_url(&format!(
            "{}/api/v1/index.php",
            site_url.trim_end_matches('/')
        ))
    }

    async fn load_app_by_id(&self, app_id: u64) -> Result<AppDetailRow, AppError> {
        self.repository
            .find_app_by_id(app_id)
            .await?
            .ok_or(AppError::AppNotFound)
    }

    async fn load_app_by_code(&self, app_code: &str) -> Result<AppDetailRow, AppError> {
        let app_code = validate_app_code(app_code)?;
        self.repository
            .find_app_by_code(&app_code)
            .await?
            .ok_or(AppError::AppNotFound)
    }

    async fn load_app_from_remote_payload(
        &self,
        payload: &Value,
    ) -> Result<AppDetailRow, AppError> {
        let app_code = payload_string(payload, "app_code");
        if !app_code.is_empty() {
            return self.load_app_by_code(&app_code).await;
        }
        self.load_app_by_id(positive_id(payload.get("app_id"))?)
            .await
    }

    async fn ensure_apps_exist(&self, app_ids: &[u64]) -> Result<(), AppError> {
        for app_id in app_ids {
            self.load_app_by_id(*app_id).await?;
        }
        Ok(())
    }

    async fn load_card(&self, card_id: u64) -> Result<CardRow, AppError> {
        self.repository
            .find_card_by_id(card_id)
            .await?
            .ok_or(AppError::CardNotFound)
    }

    async fn load_card_in_app(
        &self,
        app: &AppDetailRow,
        card_id: u64,
    ) -> Result<CardRow, AppError> {
        let card = self.load_card(card_id).await?;
        if card.app_id != app.id {
            return Err(AppError::CardNotFound);
        }
        Ok(card)
    }

    async fn load_remote_variable(
        &self,
        variable_id: u64,
    ) -> Result<RemoteVariableDetailRow, AppError> {
        self.repository
            .find_remote_variable_by_id(variable_id)
            .await?
            .ok_or(AppError::VariableNotFound)
    }

    async fn load_remote_variable_by_name(
        &self,
        name: &str,
    ) -> Result<RemoteVariableDetailRow, AppError> {
        let name = remote_variable_name(name)?;
        self.repository
            .find_remote_variable_by_name(&name)
            .await?
            .ok_or(AppError::VariableNotFound)
    }

    async fn load_remote_variables_by_names(
        &self,
        payload: &Value,
    ) -> Result<Vec<RemoteVariableDetailRow>, AppError> {
        let mut variables = Vec::new();
        for name in remote_variable_names(payload)? {
            variables.push(self.load_remote_variable_by_name(&name).await?);
        }
        Ok(variables)
    }

    async fn load_remote_variable_by_payload_name(
        &self,
        payload: &Value,
    ) -> Result<RemoteVariableDetailRow, AppError> {
        let name = remote_variable_names(payload)?
            .into_iter()
            .next()
            .ok_or(AppError::InvalidVariable)?;
        self.load_remote_variable_by_name(&name).await
    }

    async fn load_remote_api_token(
        &self,
        token_id: u64,
    ) -> Result<RemoteApiTokenDetailRow, AppError> {
        self.repository
            .find_remote_api_token_by_id(token_id)
            .await?
            .ok_or(AppError::RemoteApiTokenInvalid)
    }

    async fn unique_remote_api_access_key(&self) -> Result<String, AppError> {
        for _ in 0..MAX_APP_CODE_ATTEMPTS {
            let access_key = crypto::token(24);
            if self
                .repository
                .find_remote_api_token_by_access_key(&access_key)
                .await?
                .is_none()
            {
                return Ok(access_key);
            }
        }
        Err(AppError::RemoteApiAccessKeyExhausted)
    }

    async fn ensure_cloud_local_config(&self) -> Result<(), AppError> {
        let local = match self
            .repository
            .find_cloud_storage_config_by_provider("local")
            .await?
        {
            Some(local) => local,
            None => {
                let config_id = self
                    .repository
                    .upsert_cloud_storage_config(&default_local_config())
                    .await?;
                self.repository
                    .find_cloud_storage_config_by_id(config_id)
                    .await?
                    .ok_or(AppError::CloudStorageConfigMissing)?
            }
        };
        if self
            .repository
            .find_default_cloud_storage_config()
            .await?
            .is_none()
        {
            self.repository
                .set_default_cloud_storage_config(local.id)
                .await?;
        }
        Ok(())
    }

    async fn cloud_config_for_file(
        &self,
        file: &CloudFileRow,
    ) -> Result<CloudStorageConfigRow, AppError> {
        if let Some(config_id) = file.config_id {
            if let Some(config) = self
                .repository
                .find_cloud_storage_config_by_id(config_id)
                .await?
            {
                return Ok(config);
            }
        }
        self.repository
            .find_cloud_storage_config_by_provider(&file.provider)
            .await?
            .ok_or(AppError::CloudFileStorageConfigMissing)
    }

    async fn ensure_variable_apps_exist(&self, app_ids: &[u64]) -> Result<(), AppError> {
        if app_ids.is_empty() {
            return Ok(());
        }
        let count = self.repository.count_apps_by_ids(app_ids).await?;
        if count == app_ids.len() as i64 {
            return Ok(());
        }
        Err(AppError::InvalidVariableApps)
    }

    async fn operate_time_cards_by_activated_range(
        &self,
        app_id: u64,
        range: &CardActivatedRange,
        operation: &str,
        payload: &Value,
    ) -> Result<Value, AppError> {
        let duration_seconds = required_int_range(
            payload.get("duration_seconds"),
            MIN_CARD_DURATION_SECONDS,
            MAX_CARD_DURATION_SECONDS,
        )?;
        let matched = self
            .repository
            .count_cards_by_activated_range(app_id, range.start, range.end, "time")
            .await?;
        let affected = if operation == "reset_duration" {
            self.repository
                .reset_time_cards_duration_by_activated_range(
                    app_id,
                    range.start,
                    range.end,
                    duration_seconds,
                )
                .await?
        } else {
            let direction = if operation == "reduce_duration" {
                "reduce"
            } else {
                "add"
            };
            self.repository
                .adjust_time_cards_duration_by_activated_range(
                    app_id,
                    range.start,
                    range.end,
                    duration_seconds,
                    direction,
                )
                .await?
        };
        Ok(card_range_result(operation, matched, affected))
    }

    async fn operate_general_cards_by_activated_range(
        &self,
        app_id: u64,
        range: &CardActivatedRange,
        operation: &str,
    ) -> Result<Value, AppError> {
        let card_type = if operation == "reset_uses" {
            "count"
        } else {
            ""
        };
        let matched = self
            .repository
            .count_cards_by_activated_range(app_id, range.start, range.end, card_type)
            .await?;
        let affected = match operation {
            "enable" => {
                self.repository
                    .update_cards_status_by_activated_range(app_id, range.start, range.end, 1)
                    .await?
            }
            "disable" => {
                self.repository
                    .update_cards_status_by_activated_range(app_id, range.start, range.end, 2)
                    .await?
            }
            "reset_uses" => {
                self.repository
                    .reset_count_cards_uses_by_activated_range(app_id, range.start, range.end)
                    .await?
            }
            "delete" => {
                self.repository
                    .delete_cards_by_activated_range(app_id, range.start, range.end)
                    .await?
            }
            _ => return Err(AppError::InvalidInput("激活日期范围操作不支持")),
        };
        Ok(card_range_result(operation, matched, affected))
    }

    async fn manageable_card_devices(
        &self,
        app: &AppDetailRow,
        card_id: u64,
    ) -> Result<Vec<DeviceRow>, AppError> {
        let card = self.load_card_in_app(app, card_id).await?;
        if normalize_card_type(&card.card_type)? == "count" {
            return Ok(Vec::new());
        }
        self.repository.list_card_devices(app.id, card.id).await
    }

    async fn ensure_import_cards_are_new(
        &self,
        app: &AppDetailRow,
        card_keys: &[String],
    ) -> Result<(), AppError> {
        for card_key in card_keys {
            let card_hash = card_hash(app, card_key);
            if self
                .repository
                .find_card_by_hash(app.id, &card_hash)
                .await?
                .is_some()
            {
                return Err(AppError::InvalidInput("导入卡密已存在"));
            }
        }
        Ok(())
    }

    async fn card_rows_for_export(
        &self,
        app: &AppDetailRow,
        status: &str,
        duration_category: &str,
        keyword: &str,
        card_ids: &[u64],
    ) -> Result<Vec<CardRow>, AppError> {
        if card_ids.len() > MAX_CARD_EXPORT_ROWS {
            return Err(AppError::InvalidInput(
                "卡密数量超过导出上限，请缩小筛选范围",
            ));
        }
        if !card_ids.is_empty() {
            return self
                .repository
                .list_cards_by_ids_for_export(app.id, card_ids)
                .await;
        }
        let query = export_card_query(app, status, duration_category, keyword, &self.system_key)?;
        let cards = self
            .repository
            .list_cards_for_export(app.id, &query)
            .await?;
        if cards.len() > MAX_CARD_EXPORT_ROWS {
            return Err(AppError::InvalidInput(
                "卡密数量超过导出上限，请缩小筛选范围",
            ));
        }
        Ok(cards)
    }

    fn export_card_views(
        &self,
        cards: Vec<CardRow>,
        status: &str,
        duration_category: &str,
        keyword: &str,
        selected_ids: &HashSet<u64>,
    ) -> Result<Vec<Value>, AppError> {
        let mut views = Vec::new();
        for card in cards {
            let view = self.card_view(card)?;
            if card_matches_export_filter(&view, status, duration_category, keyword, selected_ids)?
            {
                views.push(view);
            }
        }
        Ok(views)
    }
}

fn random_upper_hex(byte_count: usize) -> String {
    let mut bytes = vec![0_u8; byte_count];
    OsRng.fill_bytes(&mut bytes);
    hex::encode_upper(bytes)
}

fn created_app_view(app_id: u64, app: &NewApp) -> Value {
    json!({
        "app_id": app_id,
        "app_code": app.app_code,
        "client_auth_mode": CLIENT_AUTH_MODE,
        "client_crypto_alg": app.client_crypto_alg,
        "client_public_key": app.client_public_key,
    })
}

fn app_settings_update(
    payload: &Value,
    current_app: &AppDetailRow,
) -> Result<AppSettingsUpdate, AppError> {
    Ok(AppSettingsUpdate {
        name: safe_text(&payload_string(payload, "name"), 80)?,
        max_devices: DEFAULT_MAX_DEVICES,
        heartbeat_interval: session_ttl(payload)?,
        heartbeat_enabled: binary_flag(
            payload,
            "heartbeat_enabled",
            current_app.heartbeat_enabled,
        )?,
        verification_enabled: binary_flag(
            payload,
            "verification_enabled",
            current_app.verification_enabled,
        )?,
        device_binding_enabled: binary_flag(
            payload,
            "device_binding_enabled",
            current_app.device_binding_enabled,
        )?,
        shared_cards_enabled: binary_flag(
            payload,
            "shared_cards_enabled",
            current_app.shared_cards_enabled,
        )?,
        login_ip_binding_enabled: binary_flag(
            payload,
            "login_ip_binding_enabled",
            current_app.login_ip_binding_enabled,
        )?,
        latest_version: safe_text(
            &payload_string_or(payload, "latest_version", &current_app.latest_version),
            40,
        )?,
        client_auth_mode: CLIENT_AUTH_MODE.to_string(),
        client_crypto_alg: normalize_client_crypto_alg(&payload_string_or(
            payload,
            "client_crypto_alg",
            &current_app.client_crypto_alg,
        ))?,
        remark: safe_text(&payload_string(payload, "remark"), 255)?,
    })
}

fn app_api_update(payload: &Value, current_app: &AppDetailRow) -> Result<AppApiUpdate, AppError> {
    let api_routes = if let Some(value) = payload.get("api_routes") {
        normalize_api_routes_for_write(value.clone())?
    } else {
        api_routes_from_text(&current_app.api_config_json)
    };
    Ok(AppApiUpdate {
        api_token: api_token_from_payload(payload, current_app)?,
        login_ip_binding_enabled: binary_flag(
            payload,
            "login_ip_binding_enabled",
            current_app.login_ip_binding_enabled,
        )?,
        web_card_query_enabled: binary_flag(
            payload,
            "web_card_query_enabled",
            current_app.web_card_query_enabled,
        )?,
        unbind_interval_seconds: payload_int_range(
            payload.get("unbind_interval_seconds"),
            0,
            MAX_CARD_DURATION_SECONDS,
            current_app.unbind_interval_seconds,
        )?,
        unbind_deduct_seconds: payload_int_range(
            payload.get("unbind_deduct_seconds"),
            0,
            MAX_CARD_DURATION_SECONDS,
            current_app.unbind_deduct_seconds,
        )?,
        unbind_deduct_uses: payload_int_range(
            payload.get("unbind_deduct_uses"),
            0,
            1_000_000,
            current_app.unbind_deduct_uses,
        )?,
        api_success_code: payload_int_range(
            payload.get("api_success_code"),
            0,
            999_999,
            current_app.api_success_code,
        )?,
        api_config_json: serde_json::to_string(&api_routes)
            .map_err(|_| AppError::InvalidApiRoutes)?,
    })
}

fn card_query(
    payload: &Value,
    app: &AppDetailRow,
    page: i64,
    limit: i64,
    system_key: &str,
) -> Result<CardQuery, AppError> {
    let keyword = safe_text(&payload_string(payload, "keyword"), 120)?;
    let card_hash = if keyword.is_empty() {
        String::new()
    } else {
        card_hash(app, &keyword)
    };
    Ok(CardQuery {
        status: card_status_filter(&payload_string(payload, "status"))?,
        duration_category: card_duration_category(&payload_string(payload, "duration_category"))?,
        search_token_hashes: keyword_token_hashes(&keyword, system_key)?,
        keyword,
        card_hash,
        limit,
        offset: (page - 1) * limit,
    })
}

fn card_view(card: CardRow, system_key: &str) -> Result<Value, AppError> {
    let card_type = normalize_card_type(&card.card_type)?;
    let expires_at = card_expires_at(&card_type, &card);
    let remaining_seconds = expires_at.map(|expires_at| {
        (expires_at - Local::now().naive_local())
            .num_seconds()
            .max(0)
    });
    let card_key = crypto::decrypt_protected_text(&card.card_cipher, system_key).ok();
    let card_fingerprint = visible_card_fingerprint(&card);
    Ok(json!({
        "id": card.id,
        "app_id": card.app_id,
        "card_fingerprint": card_fingerprint,
        "card_key": card_key.clone().unwrap_or_default(),
        "card_recoverable": card_key.is_some(),
        "card_type": card_type,
        "duration_seconds": card.duration_seconds,
        "total_uses": card.total_uses,
        "remaining_uses": card.remaining_uses,
        "max_devices": card_max_devices(&card_type, &card),
        "card_structure": card.card_structure,
        "prefix": card.prefix,
        "unbind_limit": card.unbind_limit,
        "unbind_count": card.unbind_count,
        "last_unbound_at": format_datetime(card.last_unbound_at),
        "status": card.status,
        "used_account_id": card.used_account_id,
        "used_at": format_datetime(card.used_at),
        "created_at": card.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
        "online_count": card.online_count,
        "device_count": if card_type == "count" { 0 } else { card.device_count },
        "login_ips": ip_list(&card.login_ips),
        "expires_at": card_expires_text(&card_type, expires_at),
        "remaining_seconds": remaining_seconds,
        "remaining_text": card_remaining_text(&card_type, &card, remaining_seconds),
        "duration_category": card_duration_category_from_card(&card_type, &card),
        "duration_text": card_duration_text(&card_type, &card),
    }))
}

fn device_view(device: DeviceRow) -> Value {
    json!({
        "id": device.id,
        "app_id": device.app_id,
        "account_id": device.account_id,
        "card_id": device.card_id,
        "card_fingerprint": device.card_fingerprint,
        "device_hash": device.device_hash,
        "device_fingerprint": fingerprint(&device.device_hash),
        "install_id": device.install_id,
        "machine_profile_hash": device.machine_profile_hash,
        "bind_ip": device.bind_ip,
        "bind_region": device.bind_region,
        "device_name": device.device_name,
        "status": device.status,
        "first_seen_at": device.first_seen_at.format("%Y-%m-%d %H:%M:%S").to_string(),
        "last_seen_at": device.last_seen_at.format("%Y-%m-%d %H:%M:%S").to_string(),
    })
}

fn account_view(account: AccountRow) -> Value {
    json!({
        "id": account.id,
        "app_id": account.app_id,
        "username": account.username,
        "status": account.status,
        "expires_at": account.expires_at.format("%Y-%m-%d %H:%M:%S").to_string(),
        "max_devices": account.max_devices,
        "created_at": format_datetime(account.created_at),
        "updated_at": format_datetime(account.updated_at),
    })
}

fn security_policy_payload(
    payload: &Value,
    app_id: u64,
    admin_username: &str,
) -> Result<SecurityPolicyInput, AppError> {
    let allowed_client_actions = allowed_client_actions_from_value(
        payload.get("allowed_client_actions"),
        &[
            "record_only",
            "kick_session",
            "disable_device",
            "disable_card",
        ],
    )?;
    Ok(SecurityPolicyInput {
        app_id,
        enabled: binary_flag(payload, "enabled", FLAG_ENABLED)?,
        mode: security_policy_mode(&payload_string_or(payload, "mode", "honor_client"))?,
        min_confidence_for_client_action: payload_int_range(
            payload.get("min_confidence_for_client_action"),
            0,
            100,
            0,
        )?,
        max_client_action: security_action(&payload_string_or(
            payload,
            "max_client_action",
            "disable_card",
        ))?,
        kick_score: payload_int_range(payload.get("kick_score"), 0, 255, 80)?,
        disable_device_score: payload_int_range(payload.get("disable_device_score"), 0, 255, 95)?,
        disable_card_score: payload_int_range(payload.get("disable_card_score"), 0, 255, 120)?,
        allowed_client_actions: allowed_client_actions.join(","),
        client_disable_device_min_score: payload_int_range(
            payload.get("client_disable_device_min_score"),
            0,
            255,
            80,
        )?,
        client_disable_card_min_score: payload_int_range(
            payload.get("client_disable_card_min_score"),
            0,
            255,
            95,
        )?,
        report_rate_limit_per_minute: payload_int_range(
            payload.get("report_rate_limit_per_minute"),
            1,
            1000,
            20,
        )?,
        report_retention_days: payload_int_range(
            payload.get("report_retention_days"),
            1,
            3650,
            90,
        )?,
        message_retention_days: payload_int_range(
            payload.get("message_retention_days"),
            1,
            3650,
            180,
        )?,
        server_critical_action: security_action(&payload_string_or(
            payload,
            "server_critical_action",
            "disable_card",
        ))?,
        server_high_action: security_action(&payload_string_or(
            payload,
            "server_high_action",
            "disable_device",
        ))?,
        server_medium_action: security_action(&payload_string_or(
            payload,
            "server_medium_action",
            "manual_review",
        ))?,
        server_low_action: security_action(&payload_string_or(
            payload,
            "server_low_action",
            "record_only",
        ))?,
        trusted_event_types_json: trusted_event_types_payload(payload.get("trusted_event_types"))?,
        updated_by: admin_username.trim().to_string(),
    })
}

fn security_policy_view(policy: Option<&SecurityPolicyRow>) -> Result<Value, AppError> {
    let fields = SecurityPolicyFields {
        enabled: policy.map(|row| row.enabled).unwrap_or(FLAG_ENABLED),
        mode: policy
            .map(|row| row.mode.as_str())
            .unwrap_or("honor_client"),
        min_confidence_for_client_action: policy
            .map(|row| row.min_confidence_for_client_action)
            .unwrap_or(0),
        max_client_action: policy
            .map(|row| row.max_client_action.as_str())
            .unwrap_or("disable_card"),
        kick_score: policy.map(|row| row.kick_score).unwrap_or(80),
        disable_device_score: policy.map(|row| row.disable_device_score).unwrap_or(95),
        disable_card_score: policy.map(|row| row.disable_card_score).unwrap_or(120),
        allowed_client_actions: policy
            .map(|row| row.allowed_client_actions.as_str())
            .unwrap_or("record_only,kick_session,disable_device,disable_card"),
        client_disable_device_min_score: policy
            .map(|row| row.client_disable_device_min_score)
            .unwrap_or(80),
        client_disable_card_min_score: policy
            .map(|row| row.client_disable_card_min_score)
            .unwrap_or(95),
        report_rate_limit_per_minute: policy
            .map(|row| row.report_rate_limit_per_minute)
            .unwrap_or(20),
        report_retention_days: policy.map(|row| row.report_retention_days).unwrap_or(90),
        message_retention_days: policy.map(|row| row.message_retention_days).unwrap_or(180),
        server_critical_action: policy
            .map(|row| row.server_critical_action.as_str())
            .unwrap_or("disable_card"),
        server_high_action: policy
            .map(|row| row.server_high_action.as_str())
            .unwrap_or("disable_device"),
        server_medium_action: policy
            .map(|row| row.server_medium_action.as_str())
            .unwrap_or("manual_review"),
        server_low_action: policy
            .map(|row| row.server_low_action.as_str())
            .unwrap_or("record_only"),
        trusted_event_types_json: policy
            .map(|row| row.trusted_event_types_json.as_str())
            .unwrap_or("[]"),
        updated_by: policy.map(|row| row.updated_by.as_str()).unwrap_or(""),
        updated_at: policy
            .map(|row| format_datetime(row.updated_at))
            .unwrap_or_default(),
    };
    security_policy_fields_view(&fields)
}

fn security_policy_input_view(policy: &SecurityPolicyInput) -> Result<Value, AppError> {
    security_policy_fields_view(&SecurityPolicyFields {
        enabled: policy.enabled,
        mode: &policy.mode,
        min_confidence_for_client_action: policy.min_confidence_for_client_action,
        max_client_action: &policy.max_client_action,
        kick_score: policy.kick_score,
        disable_device_score: policy.disable_device_score,
        disable_card_score: policy.disable_card_score,
        allowed_client_actions: &policy.allowed_client_actions,
        client_disable_device_min_score: policy.client_disable_device_min_score,
        client_disable_card_min_score: policy.client_disable_card_min_score,
        report_rate_limit_per_minute: policy.report_rate_limit_per_minute,
        report_retention_days: policy.report_retention_days,
        message_retention_days: policy.message_retention_days,
        server_critical_action: &policy.server_critical_action,
        server_high_action: &policy.server_high_action,
        server_medium_action: &policy.server_medium_action,
        server_low_action: &policy.server_low_action,
        trusted_event_types_json: &policy.trusted_event_types_json,
        updated_by: &policy.updated_by,
        updated_at: String::new(),
    })
}

fn security_policy_fields_view(policy: &SecurityPolicyFields<'_>) -> Result<Value, AppError> {
    Ok(json!({
        "enabled": policy.enabled,
        "mode": security_policy_mode(policy.mode)?,
        "min_confidence_for_client_action": policy.min_confidence_for_client_action,
        "max_client_action": security_action(policy.max_client_action)?,
        "kick_score": policy.kick_score,
        "disable_device_score": policy.disable_device_score,
        "disable_card_score": policy.disable_card_score,
        "allowed_client_actions": allowed_client_actions(policy.allowed_client_actions)?,
        "client_disable_device_min_score": policy.client_disable_device_min_score,
        "client_disable_card_min_score": policy.client_disable_card_min_score,
        "report_rate_limit_per_minute": policy.report_rate_limit_per_minute,
        "report_retention_days": policy.report_retention_days,
        "message_retention_days": policy.message_retention_days,
        "server_critical_action": security_action(policy.server_critical_action)?,
        "server_high_action": security_action(policy.server_high_action)?,
        "server_medium_action": security_action(policy.server_medium_action)?,
        "server_low_action": security_action(policy.server_low_action)?,
        "trusted_event_types": trusted_event_types(policy.trusted_event_types_json),
        "updated_by": policy.updated_by,
        "updated_at": policy.updated_at,
    }))
}

fn security_cleanup_view(cleanup: SecurityCleanup) -> Value {
    json!({
        "deleted_security_reports": cleanup.deleted_security_reports,
        "deleted_messages": cleanup.deleted_messages,
        "deleted_message_actions": cleanup.deleted_message_actions,
    })
}

fn assert_time_card(card: &CardRow) -> Result<(), AppError> {
    if is_time_card(card)? {
        return Ok(());
    }
    Err(AppError::InvalidInput("只有时长卡可以调整时长"))
}

fn is_time_card(card: &CardRow) -> Result<bool, AppError> {
    Ok(normalize_card_type(&card.card_type)? == "time")
}

fn card_duration_direction(value: &str) -> Result<String, AppError> {
    let direction = value.trim().to_ascii_lowercase();
    if matches!(direction.as_str(), "add" | "reduce" | "reset") {
        return Ok(direction);
    }
    Err(AppError::InvalidInput("卡密时长调整方向错误"))
}

fn batch_card_duration_direction(value: &str) -> Result<String, AppError> {
    let direction = value.trim().to_ascii_lowercase();
    if matches!(direction.as_str(), "add" | "reduce") {
        return Ok(direction);
    }
    Err(AppError::InvalidInput("批量调整方向错误"))
}

fn adjusted_card_duration(current_seconds: i64, delta_seconds: i64, direction: &str) -> i64 {
    if direction == "reduce" {
        return (current_seconds - delta_seconds).max(MIN_CARD_DURATION_SECONDS);
    }
    (current_seconds + delta_seconds).min(MAX_CARD_DURATION_SECONDS)
}

fn card_expiry_after_duration(card: &CardRow, duration_seconds: i64) -> String {
    card.used_at
        .map(|used_at| {
            (used_at + Duration::seconds(duration_seconds))
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        })
        .unwrap_or_default()
}

fn card_range_operation(value: &str) -> Result<String, AppError> {
    let operation = value.trim().to_ascii_lowercase();
    if matches!(
        operation.as_str(),
        "reset_duration"
            | "add_duration"
            | "reduce_duration"
            | "enable"
            | "disable"
            | "reset_uses"
            | "delete"
    ) {
        return Ok(operation);
    }
    Err(AppError::InvalidInput("激活日期范围操作不支持"))
}

fn is_card_range_duration_operation(operation: &str) -> bool {
    matches!(
        operation,
        "reset_duration" | "add_duration" | "reduce_duration"
    )
}

fn card_activated_range(payload: &Value) -> Result<CardActivatedRange, AppError> {
    let start = card_activated_boundary(&payload_string(payload, "activated_start"), false)?;
    let end = card_activated_boundary(&payload_string(payload, "activated_end"), true)?;
    if start <= end {
        return Ok(CardActivatedRange { start, end });
    }
    Err(AppError::InvalidInput("激活日期范围错误"))
}

fn card_activated_boundary(value: &str, end_of_day: bool) -> Result<NaiveDateTime, AppError> {
    let text = value.trim();
    let normalized = if is_date_text(text) {
        format!(
            "{text} {}",
            if end_of_day { "23:59:59" } else { "00:00:00" }
        )
    } else {
        let datetime = text.replace('T', " ");
        if is_datetime_minute_text(&datetime) {
            format!("{datetime}:00")
        } else {
            datetime
        }
    };
    NaiveDateTime::parse_from_str(&normalized, "%Y-%m-%d %H:%M:%S")
        .map_err(|_| AppError::InvalidInput("激活日期范围错误"))
}

fn is_date_text(value: &str) -> bool {
    value.len() == 10
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
}

fn is_datetime_minute_text(value: &str) -> bool {
    value.len() == 16
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value.as_bytes()[10] == b' '
        && value.as_bytes()[13] == b':'
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7 | 10 | 13) || byte.is_ascii_digit())
}

fn card_range_result(operation: &str, matched: i64, affected: u64) -> Value {
    json!({
        "operation": operation,
        "matched": matched,
        "affected": affected,
    })
}

fn unique_device_ids(mut device_ids: Vec<u64>) -> Vec<u64> {
    device_ids.sort_unstable();
    device_ids.dedup();
    device_ids
}

fn card_status_value(value: Option<&Value>) -> Result<i64, AppError> {
    required_int_range(value, 0, 2)
}

fn card_status_filter(value: &str) -> Result<String, AppError> {
    let status = value.trim().to_ascii_lowercase();
    if status.is_empty() || matches!(status.as_str(), "0" | "1" | "2" | "active" | "expired") {
        return Ok(status);
    }
    Err(AppError::InvalidInput("卡密状态筛选格式错误"))
}

fn card_duration_category(value: &str) -> Result<String, AppError> {
    let category = value.trim().to_ascii_lowercase();
    if category.is_empty()
        || matches!(
            category.as_str(),
            "day" | "week" | "month" | "season" | "year" | "custom"
        )
    {
        return Ok(category);
    }
    Err(AppError::InvalidInput("卡密时长分类不支持"))
}

fn normalize_card_type(value: &str) -> Result<String, AppError> {
    let card_type = value.trim().to_ascii_lowercase();
    match card_type.as_str() {
        "time" | "permanent" | "count" => Ok(card_type),
        _ => Err(AppError::InvalidInput("卡密类型不支持")),
    }
}

fn enabled_card_status(card: &CardRow) -> i64 {
    if card.used_at.is_some() { 1 } else { 0 }
}

fn card_expires_at(card_type: &str, card: &CardRow) -> Option<NaiveDateTime> {
    if matches!(card_type, "permanent" | "count") {
        return NaiveDateTime::parse_from_str(PERMANENT_CARD_EXPIRES_AT, "%Y-%m-%d %H:%M:%S").ok();
    }
    card.used_at
        .map(|used_at| used_at + Duration::seconds(card.duration_seconds))
}

fn card_expires_text(card_type: &str, expires_at: Option<NaiveDateTime>) -> String {
    if matches!(card_type, "permanent" | "count") {
        return PERMANENT_CARD_EXPIRES_AT.to_string();
    }
    expires_at
        .map(|value| value.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_default()
}

fn card_remaining_text(card_type: &str, card: &CardRow, remaining_seconds: Option<i64>) -> String {
    match card_type {
        "permanent" => "永久".to_string(),
        "count" => format!("剩余 {} 次", card.remaining_uses),
        _ => remaining_seconds
            .map(remaining_text)
            .unwrap_or_else(|| "未激活".to_string()),
    }
}

fn card_duration_category_from_card(card_type: &str, card: &CardRow) -> String {
    if card_type != "time" {
        return String::new();
    }
    match card.duration_seconds {
        86_400 => "day",
        604_800 => "week",
        2_592_000 => "month",
        7_776_000 => "season",
        31_536_000 => "year",
        _ => "custom",
    }
    .to_string()
}

fn card_duration_text(card_type: &str, card: &CardRow) -> String {
    match card_type {
        "permanent" => "永久".to_string(),
        "count" => format!("{}次", card.total_uses),
        _ => duration_text(card.duration_seconds),
    }
}

fn duration_text(seconds: i64) -> String {
    if seconds <= 0 {
        return "未设置".to_string();
    }
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    if days > 0 && hours == 0 && minutes == 0 {
        return format!("{days}天");
    }
    if days > 0 {
        return format!("{days}天{hours}小时");
    }
    if hours > 0 {
        return if minutes > 0 {
            format!("{hours}小时{minutes}分钟")
        } else {
            format!("{hours}小时")
        };
    }
    format!("{}分钟", minutes.max(1))
}

fn remaining_text(seconds: i64) -> String {
    let seconds = seconds.max(0);
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    if days > 0 {
        return format!("{days}天{hours}小时");
    }
    format!("{hours}小时")
}

fn card_max_devices(card_type: &str, card: &CardRow) -> i64 {
    if card_type == "count" {
        0
    } else {
        card.max_devices.max(DEFAULT_MAX_DEVICES)
    }
}

fn card_reset_uses_response(total_uses: i64) -> Value {
    json!({
        "updated": true,
        "remaining_uses": total_uses,
    })
}

fn visible_card_fingerprint(card: &CardRow) -> String {
    let fingerprint = card.card_fingerprint.trim();
    if fingerprint.is_empty() {
        return self::fingerprint(&card.card_hash);
    }
    fingerprint.to_string()
}

fn fingerprint(value: &str) -> String {
    let value = value.trim();
    if value.len() <= 14 {
        return value.to_string();
    }
    format!("{}...{}", &value[..8], &value[value.len() - 6..])
}

fn security_policy_mode(value: &str) -> Result<String, AppError> {
    let mode = value.trim().to_ascii_lowercase();
    if SECURITY_POLICY_MODES.contains(&mode.as_str()) {
        return Ok(mode);
    }
    Err(AppError::InvalidSecurityPolicyMode)
}

fn admin_actor_name(context: &AdminSessionContext) -> String {
    let username = context.admin_username.trim();
    if username.is_empty() {
        return "admin".to_string();
    }
    username.to_string()
}

fn allowed_client_actions(value: &str) -> Result<Vec<String>, AppError> {
    let mut actions = vec!["record_only".to_string()];
    for raw_action in value.split(',') {
        let action = raw_action.trim();
        if action.is_empty() {
            continue;
        }
        let action = security_action(action)?;
        if !actions.iter().any(|existing| existing == &action) {
            actions.push(action);
        }
    }
    Ok(actions)
}

fn allowed_client_actions_from_value(
    value: Option<&Value>,
    default_actions: &[&str],
) -> Result<Vec<String>, AppError> {
    let mut actions = vec!["record_only".to_string()];
    let raw_actions = match value {
        Some(Value::Array(values)) => values.iter().map(php_scalar_string).collect::<Vec<_>>(),
        Some(value) => php_scalar_string(value)
            .split(',')
            .map(str::to_string)
            .collect::<Vec<_>>(),
        None => default_actions
            .iter()
            .map(|action| (*action).to_string())
            .collect::<Vec<_>>(),
    };
    for raw_action in raw_actions {
        let action = raw_action.trim();
        if action.is_empty() {
            continue;
        }
        let action = security_action(action)?;
        if !actions.iter().any(|existing| existing == &action) {
            actions.push(action);
        }
    }
    Ok(actions)
}

fn trusted_event_types(json_text: &str) -> Value {
    let text = json_text.trim();
    let json_text = if text.is_empty() { "[]" } else { text };
    match serde_json::from_str::<Value>(json_text) {
        Ok(Value::Array(values)) => Value::Array(values),
        _ => json!([]),
    }
}

fn trusted_event_types_payload(value: Option<&Value>) -> Result<String, AppError> {
    let Some(value) = value else {
        return Ok("[]".to_string());
    };
    let Value::Array(values) = value else {
        return Err(AppError::InvalidSecurityPolicy("可信事件类型必须是列表"));
    };
    let mut seen = HashSet::new();
    let mut event_types = Vec::new();
    for value in values {
        let event_type = php_scalar_string(value);
        if seen.insert(event_type.clone()) {
            assert_trusted_event_type(&event_type)?;
            event_types.push(event_type);
        }
    }
    serde_json::to_string(&event_types)
        .map_err(|_| AppError::InvalidSecurityPolicy("JSON 编码失败"))
}

fn assert_trusted_event_type(event_type: &str) -> Result<(), AppError> {
    if (3..=40).contains(&event_type.len())
        && event_type
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Ok(());
    }
    Err(AppError::InvalidSecurityPolicy("可信事件类型格式错误"))
}

fn php_scalar_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(true) => "1".to_string(),
        Value::Bool(false) => String::new(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => text.to_string(),
        Value::Array(_) | Value::Object(_) => "Array".to_string(),
    }
}

fn ip_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn validate_app_code(value: &str) -> Result<String, AppError> {
    let app_code = value.trim();
    if (3..=32).contains(&app_code.len())
        && app_code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Ok(app_code.to_string());
    }
    Err(AppError::InvalidInput("应用编号格式错误"))
}

fn current_admin_username(context: &AdminSessionContext) -> Result<String, AppError> {
    let username = context.admin_username.trim();
    if username.is_empty() {
        return Err(AppError::AdminSessionInvalid);
    }
    Ok(username.to_string())
}

fn admin_username(value: &str) -> Result<String, AppError> {
    let username = value.trim();
    if (3..=32).contains(&username.len())
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'@' | b'-'))
    {
        return Ok(username.to_string());
    }
    Err(AppError::InvalidInput(
        "管理员账号只能使用 3 到 32 位字母、数字、下划线、点、@ 或短横线",
    ))
}

fn assert_current_admin_password(admin: &AdminRow, current_password: &str) -> Result<(), AppError> {
    if !current_password.is_empty() && verify_php_password(current_password, &admin.password) {
        return Ok(());
    }
    Err(AppError::InvalidCurrentPassword)
}

fn admin_password_change(payload: &Value) -> Result<Option<String>, AppError> {
    let new_password = payload_raw_string(payload, "new_password");
    let confirm_password = payload_raw_string(payload, "confirm_password");
    if new_password.is_empty() && confirm_password.is_empty() {
        return Ok(None);
    }
    if new_password != confirm_password {
        return Err(AppError::InvalidInput("两次输入的新密码不一致"));
    }
    if !(8..=72).contains(&new_password.len()) {
        return Err(AppError::InvalidInput(
            "新密码长度必须在 8 到 72 个字符之间",
        ));
    }
    hash(new_password, DEFAULT_COST)
        .map(Some)
        .map_err(|_| AppError::CryptoError("管理员密码加密失败"))
}

fn site_settings_update(payload: &Value) -> Result<SiteSettingsUpdate, AppError> {
    Ok(SiteSettingsUpdate {
        hostname: clip(&payload_string(payload, "hostname"), 80),
        site_subtitle: clip(&payload_string(payload, "site_subtitle"), 120),
        siteurl: clip(&payload_string(payload, "siteurl"), 255),
        logo_url: clip(&payload_string(payload, "logo_url"), 500),
        announcement: payload_string(payload, "announcement"),
        contact: clip(&payload_string(payload, "contact"), 255),
        footer_text: clip(&payload_string(payload, "footer_text"), 255),
        custom_json: site_custom_json(payload.get("custom_json"))?,
    })
}

fn site_custom_json(value: Option<&Value>) -> Result<Value, AppError> {
    match value {
        Some(Value::String(text)) if !text.trim().is_empty() => {
            let decoded: Value =
                serde_json::from_str(text).map_err(|_| AppError::InvalidCustomJson)?;
            if matches!(decoded, Value::Object(_) | Value::Array(_)) {
                return Ok(object_or_empty(decoded));
            }
            Err(AppError::InvalidCustomJson)
        }
        Some(value) => Ok(object_or_empty(value.clone())),
        None => Ok(json!({})),
    }
}

fn site_settings_view(settings: &SiteSettingsUpdate) -> Value {
    json!({
        "hostname": settings.hostname,
        "site_subtitle": settings.site_subtitle,
        "siteurl": settings.siteurl,
        "logo_url": settings.logo_url,
        "announcement": settings.announcement,
        "contact": settings.contact,
        "footer_text": settings.footer_text,
        "custom_json": settings.custom_json,
    })
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

fn session_ttl(payload: &Value) -> Result<i64, AppError> {
    let value = payload
        .get("session_ttl_seconds")
        .or_else(|| payload.get("heartbeat_interval"));
    payload_int_range(value, 300, MAX_CARD_DURATION_SECONDS, DEFAULT_SESSION_TTL)
}

fn binary_flag(payload: &Value, key: &str, default: i64) -> Result<i64, AppError> {
    payload_int_range(payload.get(key), FLAG_DISABLED, FLAG_ENABLED, default)
}

fn status(value: Option<&Value>) -> Result<i64, AppError> {
    required_int_range(value, FLAG_DISABLED, FLAG_ENABLED)
}

fn positive_id(value: Option<&Value>) -> Result<u64, AppError> {
    Ok(required_int_range(value, 1, i64::MAX)? as u64)
}

fn optional_non_negative_id(value: Option<&Value>) -> Result<u64, AppError> {
    match value {
        Some(value) => Ok(required_int_range(Some(value), 0, i64::MAX)? as u64),
        None => Ok(0),
    }
}

fn pagination(payload: &Value) -> Result<(i64, i64), AppError> {
    let page = payload_int_range(payload.get("page"), 1, 1_000_000, 1)?;
    let limit = payload_int_range(payload.get("limit"), 1, 100, 20)?;
    Ok((limit, (page - 1) * limit))
}

fn ids(value: Option<&Value>) -> Result<Vec<u64>, AppError> {
    let Some(Value::Array(values)) = value else {
        return Err(AppError::InvalidIds);
    };
    let mut seen = HashSet::new();
    let mut ids = Vec::new();
    for value in values {
        let id = positive_id(Some(value))?;
        if seen.insert(id) {
            ids.push(id);
        }
    }
    if ids.is_empty() {
        return Err(AppError::EmptyIds);
    }
    Ok(ids)
}

fn required_int_range(value: Option<&Value>, min: i64, max: i64) -> Result<i64, AppError> {
    let Some(value) = value else {
        return Err(AppError::InvalidNumber);
    };
    int_from_value(value)
        .filter(|number| (*number >= min) && (*number <= max))
        .ok_or(AppError::InvalidNumber)
}

fn payload_int_range(
    value: Option<&Value>,
    min: i64,
    max: i64,
    default: i64,
) -> Result<i64, AppError> {
    let Some(value) = value else {
        return Ok(default);
    };
    int_from_value(value)
        .filter(|number| (*number >= min) && (*number <= max))
        .ok_or(AppError::InvalidNumber)
}

fn int_from_value(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => int_from_json_number(number),
        Value::String(text) => int_from_php_filter_text(text),
        Value::Bool(true) => Some(1),
        Value::Bool(false) | Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn int_from_json_number(number: &serde_json::Number) -> Option<i64> {
    number
        .as_i64()
        .or_else(|| number.as_u64().and_then(|value| i64::try_from(value).ok()))
        .or_else(|| {
            number.as_f64().and_then(|value| {
                if value.is_finite()
                    && value.fract() == 0.0
                    && value >= i64::MIN as f64
                    && value <= i64::MAX as f64
                {
                    Some(value as i64)
                } else {
                    None
                }
            })
        })
}

fn int_from_php_filter_text(value: &str) -> Option<i64> {
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

fn api_token_from_payload(payload: &Value, current_app: &AppDetailRow) -> Result<String, AppError> {
    let token = payload
        .get("api_token")
        .and_then(Value::as_str)
        .unwrap_or(&current_app.api_token)
        .trim();
    if token.is_empty() {
        return Ok(crypto::token(32));
    }
    validate_api_token(token)
}

fn validate_api_token(value: &str) -> Result<String, AppError> {
    let token = value.trim();
    if (16..=64).contains(&token.len())
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Ok(token.to_string());
    }
    Err(AppError::InvalidApiToken)
}

fn normalize_client_crypto_alg(value: &str) -> Result<String, AppError> {
    let algorithm = value.trim().to_ascii_lowercase();
    if algorithm.is_empty() {
        return Ok(DEFAULT_CLIENT_CRYPTO_ALG.to_string());
    }
    match algorithm.as_str() {
        "rsa_oaep_aes_256_gcm" | "rsa_oaep_aes_128_gcm" | "rsa_pkcs1_aes_256_gcm" => Ok(algorithm),
        _ => Err(AppError::UnsupportedClientCrypto),
    }
}

fn audit_log_view(row: AuditLogRow) -> Value {
    json!({
        "id": row.id,
        "app_id": row.app_id,
        "account_id": row.account_id,
        "action": row.action,
        "message": row.message,
        "ip": row.ip,
        "region": row.region,
        "created_at": row.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
    })
}

fn overview_view(overview: Overview, app_code: &str) -> Value {
    json!({
        "apps_total": overview.apps_total,
        "cards_total": overview.cards_total,
        "devices_total": overview.devices_total,
        "sessions_active": overview.sessions_active,
        "card_status": {
            "inactive": overview.card_status.inactive,
            "active": overview.card_status.active,
            "expired": overview.card_status.expired,
            "disabled": overview.card_status.disabled,
        },
        "device_status": {
            "enabled": overview.device_status.enabled,
            "disabled": overview.device_status.disabled,
        },
        "single_code_ratio": {
            "total": overview.single_code_ratio.total,
            "single_code": overview.single_code_ratio.single_code,
            "multi_device": overview.single_code_ratio.multi_device,
            "single_percent": overview.single_code_ratio.single_percent_basis_points as f64 / 100.0,
        },
        "login_ip_stats": {
            "distinct_count": overview.login_ip_stats.distinct_count,
        },
        "app_code": app_code,
    })
}

fn admin_profile_view(admin: &AdminRow, session_expires_at: &str) -> Value {
    let remember_active = remember_login_active(admin);
    json!({
        "username": admin.username,
        "remember_login_active": remember_active,
        "remember_login_expires_at": if remember_active { format_datetime(admin.remember_login_expires_at) } else { String::new() },
        "session_expires_at": session_expires_at,
        "created_at": format_datetime(admin.created_at),
        "updated_at": format_datetime(admin.updated_at),
    })
}

fn remember_login_active(admin: &AdminRow) -> bool {
    !admin.remember_login_token_hash.trim().is_empty()
        && admin
            .remember_login_expires_at
            .is_some_and(|expires_at| expires_at > Local::now().naive_local())
}

fn normalize_site_settings(row: SiteSettingsRow) -> SiteSettings {
    SiteSettings {
        hostname: clip(&row.hostname, 80),
        site_subtitle: clip(&row.site_subtitle, 120),
        siteurl: clip(&row.siteurl, 255),
        logo_url: clip(&row.logo_url, 500),
        announcement: row.announcement,
        contact: clip(&row.contact, 255),
        footer_text: clip(&row.footer_text, 255),
        custom_json: object_or_empty(row.custom_json),
    }
}

fn remote_config_view(config: Option<&RemoteConfigRow>) -> Value {
    json!({
        "notice": config.map(|row| row.notice.as_str()).unwrap_or(""),
        "version": config.map(|row| row.version.as_str()).unwrap_or(""),
        "force_update": config.map(|row| row.force_update).unwrap_or(0),
        "download_url": config.map(|row| row.download_url.as_str()).unwrap_or(""),
    })
}

fn remote_config_upsert(
    app_id: u64,
    current: Option<&RemoteConfigRow>,
    payload: &Value,
) -> Result<RemoteConfigUpsert, AppError> {
    Ok(RemoteConfigUpsert {
        app_id,
        notice: safe_text_block(&payload_string(payload, "notice"), 2000)?,
        config_json: "{}".to_string(),
        variables_json: preserved_json_text(current.map(|row| row.variables_json.as_str())),
        version: safe_text(&payload_string(payload, "version"), 40)?,
        force_update: force_update_flag(payload.get("force_update")),
        download_url: safe_text(&payload_string(payload, "download_url"), 255)?,
        status: FLAG_ENABLED,
    })
}

fn preserved_json_text(value: Option<&str>) -> String {
    let text = value.unwrap_or("").trim();
    if text.is_empty() {
        "{}".to_string()
    } else {
        text.to_string()
    }
}

fn force_update_flag(value: Option<&Value>) -> i64 {
    match value {
        None | Some(Value::Null) => FLAG_DISABLED,
        Some(Value::Bool(enabled)) => i64::from(*enabled),
        Some(Value::Number(number)) => {
            if number.as_i64().unwrap_or(0) == 0 {
                FLAG_DISABLED
            } else {
                FLAG_ENABLED
            }
        }
        Some(Value::String(text)) => {
            if text.is_empty() || text == "0" {
                FLAG_DISABLED
            } else {
                FLAG_ENABLED
            }
        }
        Some(Value::Array(values)) => {
            if values.is_empty() {
                FLAG_DISABLED
            } else {
                FLAG_ENABLED
            }
        }
        Some(Value::Object(map)) => {
            if map.is_empty() {
                FLAG_DISABLED
            } else {
                FLAG_ENABLED
            }
        }
    }
}

fn app_integration_view(
    app: &AppDetailRow,
    remote_config: Option<&RemoteConfigRow>,
    system_key: &str,
) -> Result<Value, AppError> {
    Ok(json!({
        "app_code": app.app_code,
        "api_token": resolved_api_token_parts(&app.app_code, &app.api_token, system_key)?,
        "api_success_code": api_success_code(app.api_success_code),
        "api_routes": api_routes_from_text(&app.api_config_json),
        "name": app.name,
        "client_auth_mode": CLIENT_AUTH_MODE,
        "client_crypto_alg": normalize_client_crypto_alg(&app.client_crypto_alg)?,
        "client_public_key": app.client_public_key,
        "app_version": remote_config.map(|row| row.version.as_str()).unwrap_or(""),
        "heartbeat_interval": app.heartbeat_interval,
        "heartbeat_enabled": app.heartbeat_enabled,
        "verification_enabled": app.verification_enabled,
        "device_binding_enabled": app.device_binding_enabled,
        "shared_cards_enabled": app.shared_cards_enabled,
        "login_ip_binding_enabled": app.login_ip_binding_enabled,
        "web_card_query_enabled": app.web_card_query_enabled,
        "unbind_interval_seconds": app.unbind_interval_seconds,
        "unbind_deduct_seconds": app.unbind_deduct_seconds,
        "unbind_deduct_uses": app.unbind_deduct_uses,
    }))
}

fn validate_api_url(value: &str) -> Result<String, AppError> {
    let api_url = value.trim();
    if api_url.len() > 500 || !api_url.is_ascii() {
        return Err(AppError::InvalidApiUrl);
    }
    let Some(authority_start) = api_url
        .strip_prefix("http://")
        .or_else(|| api_url.strip_prefix("https://"))
    else {
        return Err(AppError::InvalidApiUrl);
    };
    if authority_start.is_empty() || authority_start.starts_with('/') {
        return Err(AppError::InvalidApiUrl);
    }
    let parsed = reqwest::Url::parse(api_url).map_err(|_| AppError::InvalidApiUrl)?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(AppError::InvalidApiUrl);
    }
    if api_url
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(AppError::InvalidApiUrl);
    }
    parsed
        .path_segments()
        .ok_or(AppError::InvalidApiUrl)
        .map(|_| ())?;
    Ok(api_url.to_string())
}

fn sdk_types() -> Value {
    json!([
        {"value": "android", "label": "Android SDK"},
        {"value": "windows", "label": "Windows SDK"},
        {"value": "macos", "label": "macOS SDK"},
        {"value": "linux", "label": "Linux SDK"},
        {"value": "python", "label": "Python SDK"},
    ])
}

fn client_route_docs() -> Value {
    json!([
        {"route": "/login/challenge", "method": "POST", "name": "登录挑战", "auth": "应用参数"},
        {"route": "/login", "method": "POST", "name": "卡密登录", "auth": "设备签名或临时票据"},
        {"route": "/heartbeat", "method": "POST", "name": "心跳续期", "auth": "轮换 token + 设备证明"},
        {"route": "/config", "method": "POST", "name": "远程配置", "auth": "轮换 token + 设备证明"},
        {"route": "/notice", "method": "POST", "name": "应用公告", "auth": "应用参数"},
        {"route": "/variable", "method": "POST", "name": "按变量名读取远程变量", "auth": "轮换 token + 设备证明"},
        {"route": "/cloud/download-ticket", "method": "POST", "name": "获取云存储下载票据", "auth": "轮换 token + 设备证明"},
        {"route": "/security/report", "method": "POST", "name": "客户端安全上报", "auth": "轮换 token + 设备证明"},
        {"route": "/logout", "method": "POST", "name": "退出登录", "auth": "当前 token + 设备证明"},
        {"route": "/unbind", "method": "POST", "name": "解绑设备", "auth": "卡密 + 设备签名"},
        {"route": "/card/query", "method": "POST", "name": "网页卡密查询", "auth": "独立开关"},
    ])
}

fn client_error_codes() -> Value {
    json!([
        {"code": "APP_DISABLED", "message": "应用已停用"},
        {"code": "CARD_INVALID", "message": "卡密不存在或不可用"},
        {"code": "CARD_EXPIRED", "message": "卡密已过期"},
        {"code": "CARD_IN_USE", "message": "单人卡密已在其他设备使用中"},
        {"code": "IP_REGION_UNAVAILABLE", "message": "服务端 IP 地区库不可用"},
        {"code": "CLIENT_VERSION_OUTDATED", "message": "强制更新开启后客户端版本不匹配"},
        {"code": "DEVICE_DISABLED", "message": "设备已被禁用"},
        {"code": "DEVICE_LIMIT", "message": "卡密绑定设备数量已达上限"},
        {"code": "SESSION_INVALID", "message": "会话无效、过期、计数器错误或 token 已轮换"},
        {"code": "REPLAY_REQUEST", "message": "请求 nonce 已使用"},
        {"code": "BAD_DEVICE_SIGNATURE", "message": "设备签名校验失败"},
        {"code": "DEVICE_PUBLIC_KEY_INVALID", "message": "设备公钥格式错误或无法验签"},
        {"code": "DEVICE_KEY_CHANGED", "message": "设备公钥与首次绑定不一致"},
        {"code": "DEVICE_KEY_MODE_INVALID", "message": "设备证明模式不支持或与挑战不一致"},
        {"code": "DEVICE_KEY_MODE_DOWNGRADE", "message": "已绑定本地密钥的设备不能降级为临时票据模式"},
        {"code": "SESSION_TICKET_MISSING", "message": "临时票据缺失"},
        {"code": "SESSION_TICKET_INVALID", "message": "临时票据无效"},
        {"code": "SESSION_TICKET_EXPIRED", "message": "临时票据已过期"},
        {"code": "SECURITY_REPORT_INVALID", "message": "安全上报格式错误"},
        {"code": "SECURITY_ACTION_INVALID", "message": "安全上报处置动作不支持"},
        {"code": "CLOUD_FILE_NOT_FOUND", "message": "云存储文件不存在或已删除"},
        {"code": "CLOUD_DOWNLOAD_TICKET_INVALID", "message": "云存储下载票据无效或已过期"},
    ])
}

fn default_site_settings() -> SiteSettings {
    SiteSettings {
        hostname: "授权管理系统".to_string(),
        site_subtitle: "授权管理平台".to_string(),
        siteurl: String::new(),
        logo_url: String::new(),
        announcement: String::new(),
        contact: String::new(),
        footer_text: String::new(),
        custom_json: json!({}),
    }
}

fn resolved_api_token(app: &AppRow, system_key: &str) -> Result<String, AppError> {
    resolved_api_token_parts(&app.app_code, &app.api_token, system_key)
}

fn resolved_api_token_parts(
    app_code: &str,
    api_token: &str,
    system_key: &str,
) -> Result<String, AppError> {
    let token = api_token.trim();
    if !token.is_empty() {
        return Ok(token.to_string());
    }
    let mut mac = <HmacSha256 as Mac>::new_from_slice(system_key.as_bytes())
        .map_err(|_| AppError::CryptoError("应用 Token 密钥错误"))?;
    mac.update(app_code.as_bytes());
    Ok(crypto::encode_base64_url(&mac.finalize().into_bytes())[..43].to_string())
}

fn api_success_code(value: i64) -> i64 {
    if value > 999_999 { 0 } else { value }
}

fn api_routes_from_text(value: &str) -> Value {
    let decoded = serde_json::from_str::<Value>(value).unwrap_or_else(|_| api_route_defaults());
    normalize_api_routes_for_read(decoded)
}

fn normalize_api_routes_for_read(value: Value) -> Value {
    let input = value.as_array().cloned().unwrap_or_default();
    let mut rows = Vec::new();
    for (route, name, default_call_id) in api_route_definitions() {
        let existing = route_row(&input, route);
        let call_id = existing
            .and_then(|row| row.get("call_id"))
            .map(api_route_scalar_text)
            .filter(|text| valid_call_id(text))
            .unwrap_or_else(|| default_call_id.to_string());
        let enabled = existing
            .and_then(|row| row.get("enabled"))
            .map(|value| if php_int_from_value(value) == 0 { 0 } else { 1 })
            .unwrap_or(1);
        rows.push(json!({
            "route": route,
            "name": name,
            "call_id": call_id,
            "enabled": enabled,
        }));
    }
    Value::Array(rows)
}

fn normalize_api_routes_for_write(value: Value) -> Result<Value, AppError> {
    let Some(input) = value.as_array() else {
        return Err(AppError::InvalidApiRoutes);
    };
    if input.iter().any(|row| !row.is_object()) {
        return Err(AppError::InvalidApiRoutes);
    }
    let mut rows = Vec::new();
    let mut used_call_ids = HashSet::new();
    for (route, name, default_call_id) in api_route_definitions() {
        let existing = route_row(input, route);
        let call_id_input = existing
            .and_then(|row| row.get("call_id"))
            .map(api_route_scalar_text)
            .unwrap_or_default();
        let call_id_input = call_id_input.trim();
        let call_id = validate_call_id(if call_id_input.is_empty() {
            default_call_id
        } else {
            call_id_input
        })?;
        if !used_call_ids.insert(call_id.clone()) {
            return Err(AppError::DuplicateApiCallId);
        }
        let enabled = existing
            .and_then(|row| row.get("enabled"))
            .map(|value| if php_int_from_value(value) == 0 { 0 } else { 1 })
            .unwrap_or(1);
        rows.push(json!({
            "route": route,
            "name": name,
            "call_id": call_id,
            "enabled": enabled,
        }));
    }
    Ok(Value::Array(rows))
}

fn route_row<'a>(input: &'a [Value], route: &str) -> Option<&'a Value> {
    input.iter().rev().find(|row| {
        row.get("route")
            .map(api_route_scalar_text)
            .is_some_and(|value| value == route)
    })
}

fn api_route_defaults() -> Value {
    normalize_api_routes_for_read(Value::Array(Vec::new()))
}

fn api_route_definitions() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("/login/challenge", "登录挑战", "login_challenge"),
        ("/login", "卡密登录", "login"),
        ("/heartbeat", "心跳验证", "heartbeat"),
        ("/config", "应用配置", "config"),
        ("/variable", "远程变量", "variable"),
        (
            "/cloud/download-ticket",
            "云存储下载票据",
            "cloud_download_ticket",
        ),
        ("/security/report", "安全上报", "security_report"),
        ("/notice", "应用公告", "notice"),
        ("/unbind", "解绑设备", "unbind"),
        ("/logout", "退出登录", "logout"),
    ]
}

fn valid_call_id(value: &str) -> bool {
    let length = value.len();
    (2..=80).contains(&length)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
}

fn validate_call_id(value: &str) -> Result<String, AppError> {
    if valid_call_id(value) {
        return Ok(value.trim().to_string());
    }
    Err(AppError::InvalidApiCallId)
}

fn api_route_scalar_text(value: &Value) -> String {
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
        Value::Null => String::new(),
        Value::Array(_) | Value::Object(_) => "Array".to_string(),
    }
}

fn php_int_from_value(value: &Value) -> i64 {
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
    payload
        .get(key)
        .map(php_scalar_string)
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn payload_raw_string(payload: &Value, key: &str) -> String {
    payload.get(key).map(php_scalar_string).unwrap_or_default()
}

fn optional_payload_string(payload: &Value, key: &str) -> String {
    payload
        .get(key)
        .map(php_scalar_string)
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn payload_string_or(payload: &Value, key: &str, default: &str) -> String {
    match payload.get(key) {
        Some(Value::Null) | None => default.trim().to_string(),
        Some(value) => php_scalar_string(value).trim().to_string(),
    }
}

fn int_range(value: Option<&Value>, min: i64, max: i64, default: i64) -> i64 {
    let Some(value) = value else {
        return default;
    };
    let number = value
        .as_i64()
        .or_else(|| value.as_str().and_then(|text| text.parse::<i64>().ok()))
        .unwrap_or(default);
    number.clamp(min, max)
}

fn object_or_empty(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(map),
        _ => json!({}),
    }
}

fn format_datetime(value: Option<chrono::NaiveDateTime>) -> String {
    value
        .map(|datetime| datetime.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_default()
}

fn clip(value: &str, max_chars: usize) -> String {
    value.trim().chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clips_site_settings_like_php_normalizer() {
        let row = SiteSettingsRow {
            hostname: format!("  {}  ", "站".repeat(90)),
            site_subtitle: "授权管理平台".to_string(),
            siteurl: String::new(),
            logo_url: String::new(),
            announcement: "公告".to_string(),
            contact: "联系".to_string(),
            footer_text: "页脚".to_string(),
            custom_json: json!([]),
        };

        let settings = normalize_site_settings(row);

        assert_eq!(80, settings.hostname.chars().count());
        assert_eq!(json!({}), settings.custom_json);
    }

    #[test]
    fn builds_remote_config_upsert_like_php_service() {
        let current = RemoteConfigRow {
            app_id: 3,
            notice: "old".to_string(),
            config_json: " {\"legacy\":true} ".to_string(),
            variables_json: String::new(),
            version: "1.0.0".to_string(),
            force_update: 0,
            download_url: String::new(),
            status: 1,
        };
        let payload = json!({
            "notice": "第一行\n第二行",
            "version": "2.0.0",
            "force_update": "1",
            "download_url": "https://example.com/app.zip"
        });

        let config = remote_config_upsert(3, Some(&current), &payload).expect("remote config");

        assert_eq!("第一行\n第二行", config.notice);
        assert_eq!("{}", config.config_json);
        assert_eq!("{}", config.variables_json);
        assert_eq!("2.0.0", config.version);
        assert_eq!(1, config.force_update);
        assert_eq!("https://example.com/app.zip", config.download_url);
        assert_eq!(1, config.status);
    }

    #[test]
    fn maps_force_update_with_php_empty_semantics() {
        assert_eq!(0, force_update_flag(None));
        assert_eq!(0, force_update_flag(Some(&json!(false))));
        assert_eq!(0, force_update_flag(Some(&json!(0))));
        assert_eq!(0, force_update_flag(Some(&json!("0"))));
        assert_eq!(1, force_update_flag(Some(&json!(true))));
        assert_eq!(1, force_update_flag(Some(&json!("false"))));
    }

    #[test]
    fn normalizes_site_settings_update_payload() {
        let payload = json!({
            "hostname": format!("  {}  ", "站".repeat(90)),
            "site_subtitle": "授权管理平台",
            "siteurl": " https://example.com ",
            "logo_url": "",
            "announcement": "公告\n第二行",
            "contact": "客服",
            "footer_text": "页脚",
            "custom_json": {"web": {"login_title": "ACE"}}
        });

        let settings = site_settings_update(&payload).expect("site settings");

        assert_eq!(80, settings.hostname.chars().count());
        assert_eq!("https://example.com", settings.siteurl);
        assert_eq!("公告\n第二行", settings.announcement);
        assert_eq!(json!({"web": {"login_title": "ACE"}}), settings.custom_json);
        assert!(matches!(
            site_settings_update(&json!({"custom_json": "1"})),
            Err(AppError::InvalidCustomJson)
        ));
    }

    #[test]
    fn casts_admin_payload_strings_like_php() {
        let payload = json!({
            "number": 123,
            "true_value": true,
            "false_value": false,
            "array_value": ["x"],
            "object_value": {"x": 1},
            "null_value": null,
            "raw_value": "  keep  "
        });

        assert_eq!("123", payload_string(&payload, "number"));
        assert_eq!("1", payload_string(&payload, "true_value"));
        assert_eq!("", payload_string(&payload, "false_value"));
        assert_eq!("Array", payload_string(&payload, "array_value"));
        assert_eq!("Array", payload_string(&payload, "object_value"));
        assert_eq!("", payload_string(&payload, "null_value"));
        assert_eq!(
            "fallback",
            payload_string_or(&payload, "missing", " fallback ")
        );
        assert_eq!(
            "fallback",
            payload_string_or(&payload, "null_value", " fallback ")
        );
        assert_eq!("", payload_string_or(&payload, "false_value", " fallback "));
        assert_eq!("  keep  ", payload_raw_string(&payload, "raw_value"));
        assert_eq!("Array", payload_raw_string(&payload, "array_value"));
        assert_eq!("Array", optional_payload_string(&payload, "object_value"));
    }

    #[test]
    fn validates_admin_profile_payload_without_trimming_passwords() {
        assert_eq!(
            "admin.name",
            admin_username(" admin.name ").expect("username")
        );
        assert!(matches!(
            admin_username("bad/name"),
            Err(AppError::InvalidInput(_))
        ));
        assert!(matches!(
            admin_password_change(&json!({
                "new_password": "password-one",
                "confirm_password": "password-two"
            })),
            Err(AppError::InvalidInput(_))
        ));
        assert!(
            admin_password_change(&json!({}))
                .expect("empty password change")
                .is_none()
        );
        assert_eq!(
            "  password  ",
            payload_raw_string(
                &json!({"current_password": "  password  "}),
                "current_password"
            )
        );
    }

    #[test]
    fn builds_app_integration_payload_for_frontend_docs() {
        let mut app = app_detail_fixture();
        app.client_public_key =
            "-----BEGIN PUBLIC KEY-----\nKEY\n-----END PUBLIC KEY-----\n".to_string();
        let remote_config = RemoteConfigRow {
            app_id: app.id,
            notice: String::new(),
            config_json: "{}".to_string(),
            variables_json: "{}".to_string(),
            version: "2.3.4".to_string(),
            force_update: 0,
            download_url: String::new(),
            status: 1,
        };

        let view =
            app_integration_view(&app, Some(&remote_config), "system-key").expect("integration");

        assert_eq!("ACE_TEST", view["app_code"]);
        assert_eq!("ABCDEFGHIJKLMNOP", view["api_token"]);
        assert_eq!("2.3.4", view["app_version"]);
        assert_eq!("local_key_v1", view["client_auth_mode"]);
        assert_eq!("/login/challenge", view["api_routes"][0]["route"]);
        assert_eq!("login_challenge", view["api_routes"][0]["call_id"]);
    }

    #[test]
    fn validates_sdk_api_url_shape() {
        assert_eq!(
            "https://example.com/api/v1/index.php",
            validate_api_url(" https://example.com/api/v1/index.php ").expect("api url")
        );
        assert!(matches!(
            validate_api_url("ftp://example.com/api"),
            Err(AppError::InvalidApiUrl)
        ));
        assert!(matches!(
            validate_api_url("https:///api"),
            Err(AppError::InvalidApiUrl)
        ));
        assert!(matches!(
            validate_api_url("http://例子.测试/api"),
            Err(AppError::InvalidApiUrl)
        ));
    }

    #[test]
    fn parses_admin_integer_inputs_like_php_filter_validate_int() {
        for (value, expected) in [
            (json!("81"), 81),
            (json!(" 81 "), 81),
            (json!("+81"), 81),
            (json!("-0"), 0),
            (json!(true), 1),
            (json!(1.0), 1),
        ] {
            assert_eq!(Some(expected), int_from_value(&value));
        }
        for value in [
            json!("081"),
            json!("00"),
            json!("1.0"),
            json!(false),
            json!(""),
            json!(null),
            json!([]),
            json!({ "value": 1 }),
            json!(1.5),
        ] {
            assert_eq!(None, int_from_value(&value));
        }
    }

    #[test]
    fn renders_default_security_policy_like_php_service() {
        let policy = security_policy_view(None).expect("default policy");

        assert_eq!(
            json!({
                "enabled": 1,
                "mode": "honor_client",
                "min_confidence_for_client_action": 0,
                "max_client_action": "disable_card",
                "kick_score": 80,
                "disable_device_score": 95,
                "disable_card_score": 120,
                "allowed_client_actions": ["record_only", "kick_session", "disable_device", "disable_card"],
                "client_disable_device_min_score": 80,
                "client_disable_card_min_score": 95,
                "report_rate_limit_per_minute": 20,
                "report_retention_days": 90,
                "message_retention_days": 180,
                "server_critical_action": "disable_card",
                "server_high_action": "disable_device",
                "server_medium_action": "manual_review",
                "server_low_action": "record_only",
                "trusted_event_types": [],
                "updated_by": "",
                "updated_at": "",
            }),
            policy
        );
    }

    #[test]
    fn parses_security_policy_client_actions_like_php_service() {
        assert_eq!(
            vec![
                "record_only".to_string(),
                "kick_session".to_string(),
                "disable_device".to_string(),
            ],
            allowed_client_actions("kick_session,record_only,disable_device,kick_session")
                .expect("actions")
        );
        assert!(matches!(
            allowed_client_actions("bad_action"),
            Err(AppError::InvalidSecurityAction)
        ));
    }

    #[test]
    fn builds_security_policy_payload_like_php_service() {
        let payload = json!({
            "enabled": 0,
            "mode": "bounded_client",
            "allowed_client_actions": ["kick_session", "record_only", "disable_device", "kick_session"],
            "trusted_event_types": ["hook_detected", "debugger_attached", "hook_detected"],
            "server_medium_action": "manual_review",
        });

        let policy = security_policy_payload(&payload, 7, "alice").expect("policy payload");
        let view = security_policy_input_view(&policy).expect("policy view");

        assert_eq!(7, policy.app_id);
        assert_eq!(0, policy.enabled);
        assert_eq!("bounded_client", policy.mode);
        assert_eq!(
            "record_only,kick_session,disable_device",
            policy.allowed_client_actions
        );
        assert_eq!(
            "[\"hook_detected\",\"debugger_attached\"]",
            policy.trusted_event_types_json
        );
        assert_eq!("alice", policy.updated_by);
        assert_eq!(
            json!(["record_only", "kick_session", "disable_device"]),
            view["allowed_client_actions"]
        );
        assert_eq!(
            json!(["hook_detected", "debugger_attached"]),
            view["trusted_event_types"]
        );
        assert_eq!("", view["updated_at"]);
    }

    #[test]
    fn rejects_invalid_security_policy_trusted_event_types_like_php_service() {
        assert!(matches!(
            trusted_event_types_payload(Some(&json!("hook_detected"))),
            Err(AppError::InvalidSecurityPolicy("可信事件类型必须是列表"))
        ));
        assert!(matches!(
            trusted_event_types_payload(Some(&json!(["HookDetected"]))),
            Err(AppError::InvalidSecurityPolicy("可信事件类型格式错误"))
        ));
    }

    #[test]
    fn validates_app_code_like_php_validator() {
        assert_eq!(
            "ACE_01-test",
            validate_app_code("ACE_01-test").expect("app code should be valid")
        );
        assert!(matches!(
            validate_app_code("ACE/01"),
            Err(AppError::InvalidInput(_))
        ));
    }

    #[test]
    fn rejects_duplicate_api_call_ids() {
        let routes = json!([
            {"route": "/login", "call_id": "same_call", "enabled": 1},
            {"route": "/heartbeat", "call_id": "same_call", "enabled": 1}
        ]);

        assert!(matches!(
            normalize_api_routes_for_write(routes),
            Err(AppError::DuplicateApiCallId)
        ));
    }

    #[test]
    fn normalizes_api_routes_with_php_scalar_casts() {
        let routes = json!([
            {"route": "/login", "call_id": 12345, "enabled": "0"},
            {"route": "/heartbeat", "call_id": "beat", "enabled": "1abc"},
            {"route": true, "call_id": "ignored", "enabled": 0}
        ]);

        let normalized = normalize_api_routes_for_write(routes).expect("routes");

        assert_eq!("12345", normalized[1]["call_id"]);
        assert_eq!(0, normalized[1]["enabled"]);
        assert_eq!("beat", normalized[2]["call_id"]);
        assert_eq!(1, normalized[2]["enabled"]);
        assert_eq!("login_challenge", normalized[0]["call_id"]);
    }

    #[test]
    fn rejects_invalid_api_call_id_with_php_error_code() {
        let routes = json!([
            {"route": "/login", "call_id": "x", "enabled": 1}
        ]);

        assert!(matches!(
            normalize_api_routes_for_write(routes),
            Err(AppError::InvalidApiCallId)
        ));
    }

    #[test]
    fn builds_app_api_update_from_payload() {
        let current_app = app_detail_fixture();
        let payload = json!({
            "api_token": "ABCDEFGHIJKLMNOP",
            "login_ip_binding_enabled": 1,
            "web_card_query_enabled": 1,
            "unbind_interval_seconds": 60,
            "unbind_deduct_seconds": 120,
            "unbind_deduct_uses": 2,
            "api_success_code": 200,
            "api_routes": [
                {"route": "/login", "call_id": "card_login", "enabled": 1},
                {"route": "/heartbeat", "call_id": "beat", "enabled": 0}
            ]
        });

        let update = app_api_update(&payload, &current_app).expect("api update should build");
        let routes: Value =
            serde_json::from_str(&update.api_config_json).expect("routes should be json");

        assert_eq!("ABCDEFGHIJKLMNOP", update.api_token);
        assert_eq!(1, update.login_ip_binding_enabled);
        assert_eq!(200, update.api_success_code);
        assert_eq!("card_login", routes[1]["call_id"]);
        assert_eq!(0, routes[2]["enabled"]);
    }

    #[test]
    fn validates_card_filters() {
        assert_eq!("active", card_status_filter("active").expect("status"));
        assert_eq!("expired", card_status_filter("expired").expect("status"));
        assert!(matches!(
            card_status_filter("deleted"),
            Err(AppError::InvalidInput(_))
        ));
        assert_eq!(
            "season",
            card_duration_category("season").expect("duration category")
        );
        assert!(matches!(
            card_duration_category("forever"),
            Err(AppError::InvalidInput(_))
        ));
    }

    #[test]
    fn renders_card_remaining_text_like_php() {
        assert_eq!("0小时", remaining_text(0));
        assert_eq!("0小时", remaining_text(3_599));
        assert_eq!("1小时", remaining_text(3_600));
        assert_eq!("17小时", remaining_text(61_202));
        assert_eq!("1天1小时", remaining_text(90_000));
    }

    #[test]
    fn parses_activated_range_boundaries_like_php() {
        let range = card_activated_range(&json!({
            "activated_start": "2026-06-01",
            "activated_end": "2026-06-11T12:30"
        }))
        .expect("range should parse");

        assert_eq!(
            "2026-06-01 00:00:00",
            range.start.format("%Y-%m-%d %H:%M:%S").to_string()
        );
        assert_eq!(
            "2026-06-11 12:30:00",
            range.end.format("%Y-%m-%d %H:%M:%S").to_string()
        );
        assert!(matches!(
            card_activated_range(&json!({
                "activated_start": "2026-06-12",
                "activated_end": "2026-06-11"
            })),
            Err(AppError::InvalidInput(_))
        ));
    }

    #[test]
    fn validates_card_range_operation_names() {
        assert_eq!(
            "reset_duration",
            card_range_operation("reset_duration").expect("operation")
        );
        assert!(is_card_range_duration_operation("add_duration"));
        assert!(matches!(
            card_range_operation("unknown"),
            Err(AppError::InvalidInput(_))
        ));
    }

    #[test]
    fn clamps_card_duration_adjustments() {
        assert_eq!(60, adjusted_card_duration(120, 300, "reduce"));
        assert_eq!(
            MAX_CARD_DURATION_SECONDS,
            adjusted_card_duration(MAX_CARD_DURATION_SECONDS - 10, 300, "add")
        );

        let mut card = count_card_fixture(String::new());
        card.card_type = "time".to_string();
        card.used_at = Some(
            NaiveDateTime::parse_from_str("2026-06-01 08:00:00", "%Y-%m-%d %H:%M:%S")
                .expect("used_at"),
        );
        assert_eq!(
            "2026-06-02 08:00:00",
            card_expiry_after_duration(&card, 86_400)
        );
    }

    #[test]
    fn parses_custom_card_import_like_php_parser() {
        let payload = json!(["ABCDEF12", "ABCDEF12,abc_def-90；ZZZZZZZZ"]);

        let card_import = parse_card_import(Some(&payload)).expect("import should parse");

        assert_eq!(4, card_import.input_count);
        assert_eq!(1, card_import.duplicate_count);
        assert_eq!(
            vec![
                "ABCDEF12".to_string(),
                "abc_def-90".to_string(),
                "ZZZZZZZZ".to_string()
            ],
            card_import.cards
        );
    }

    #[test]
    fn builds_card_search_hashes_with_php_compatible_hmac() {
        let system_key = "test-system-key";

        assert_eq!(
            vec!["a3d7e98942f342f3a827b2bb452bdb442e93110c2b6e2a12cf0031a3d59f42c2"],
            keyword_token_hashes("abc", system_key).expect("keyword token")
        );
        assert_eq!(
            vec![
                "78c43cd22f08cd19312f754f563a4f54071af6ea110c4cb5dd63c3f173f25732",
                "7f09f58b91d8fefaeea81937e79e17ee0bffcdac03201a4ae370ebef38312047",
                "a3d7e98942f342f3a827b2bb452bdb442e93110c2b6e2a12cf0031a3d59f42c2"
            ],
            card_token_hashes("AB-CD", system_key).expect("card tokens")
        );
        assert_eq!(
            vec![
                "76a26bb38904a9b32163d77908a31d56a7b02ec9a413823371cf72a900a0bf0f",
                "bd6c29f83143df202a3b16b331fddb9a820fa6a247b9be704282b15d369cb8a0"
            ],
            keyword_token_hashes("ABCDEFGHIJKLMNOPQ", system_key).expect("long keyword")
        );
    }

    #[test]
    fn rejects_multiline_card_keys_for_line_export() {
        let cards = vec![json!({
            "card_recoverable": true,
            "card_key": "BAD\nCARD"
        })];

        assert!(matches!(
            exportable_card_keys(&cards),
            Err(AppError::InvalidInput(_))
        ));
    }

    #[test]
    fn renders_count_card_view() {
        let system_key = "test-system-key";
        let card_key = "COUNT-CARD-001";
        let row = count_card_fixture(
            crypto::encrypt_protected_text(card_key, system_key).expect("card should encrypt"),
        );

        let view = card_view(row, system_key).expect("card view should render");

        assert_eq!(card_key, view["card_key"]);
        assert_eq!(true, view["card_recoverable"]);
        assert_eq!("count", view["card_type"]);
        assert_eq!("剩余 3 次", view["remaining_text"]);
        assert_eq!("", view["duration_category"]);
        assert_eq!("10次", view["duration_text"]);
        assert_eq!(0, view["max_devices"]);
        assert_eq!(0, view["device_count"]);
    }

    #[test]
    fn renders_single_count_card_reset_response_like_php() {
        let response = card_reset_uses_response(7);
        assert_eq!(true, response["updated"]);
        assert_eq!(7, response["remaining_uses"]);
    }

    fn app_detail_fixture() -> AppDetailRow {
        AppDetailRow {
            id: 1,
            app_code: "ACE_TEST".to_string(),
            api_token: "ABCDEFGHIJKLMNOP".to_string(),
            name: "测试应用".to_string(),
            status: 1,
            max_devices: 50,
            heartbeat_interval: 86_400,
            heartbeat_enabled: 1,
            verification_enabled: 1,
            device_binding_enabled: 1,
            shared_cards_enabled: 0,
            login_ip_binding_enabled: 0,
            web_card_query_enabled: 0,
            unbind_interval_seconds: 0,
            unbind_deduct_seconds: 0,
            unbind_deduct_uses: 0,
            api_success_code: 0,
            api_config_json: serde_json::to_string(&api_route_defaults())
                .expect("defaults should encode"),
            latest_version: String::new(),
            client_auth_mode: CLIENT_AUTH_MODE.to_string(),
            client_crypto_alg: DEFAULT_CLIENT_CRYPTO_ALG.to_string(),
            client_public_key: String::new(),
            client_private_key_cipher: String::new(),
            remark: String::new(),
            created_at: None,
            updated_at: None,
        }
    }

    fn count_card_fixture(card_cipher: String) -> CardRow {
        CardRow {
            id: 9,
            app_id: 1,
            card_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            card_cipher,
            card_fingerprint: "COUNT...001".to_string(),
            card_type: "count".to_string(),
            duration_seconds: 0,
            total_uses: 10,
            remaining_uses: 3,
            max_devices: 50,
            card_structure: "alnum".to_string(),
            prefix: "COUNT".to_string(),
            unbind_limit: 0,
            unbind_count: 0,
            last_unbound_at: None,
            status: 1,
            used_account_id: None,
            used_at: None,
            created_at: NaiveDateTime::parse_from_str("2026-01-01 00:00:00", "%Y-%m-%d %H:%M:%S")
                .expect("created_at"),
            online_count: 2,
            login_ips: "127.0.0.1,10.0.0.1".to_string(),
            device_count: 5,
        }
    }
}
