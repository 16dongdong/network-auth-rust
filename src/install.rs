use std::{
    fs,
    ops::Range,
    path::{Path, PathBuf},
};

use bcrypt::hash as bcrypt_hash;
use chrono::Local;
use rand::RngCore;
use sqlx::{
    MySql, MySqlPool, QueryBuilder, Row,
    mysql::{MySqlConnectOptions, MySqlPoolOptions},
};
use thiserror::Error;

use crate::{card_search, config::DatabaseConfig, crypto};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdStrategy {
    AutoIncrement,
    UuidShortDefault,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaMigrationPlan {
    statements: Vec<String>,
    id_strategy: IdStrategy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaMigrationResult {
    pub schema_statements: usize,
    pub runtime_patches: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallDatabaseConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub database_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallAdminAccount {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallSystemPaths {
    pub config_file: PathBuf,
    pub schema_file: PathBuf,
    pub lock_file: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallSystemResult {
    pub config_file: String,
    pub statement_count: usize,
    pub admin_username: Option<String>,
    pub admin_token: Option<String>,
    pub id_strategy: IdStrategy,
}

#[derive(Debug, Error)]
pub enum InstallError {
    #[error("schema 文件读取失败: {0}")]
    SchemaReadFailed(String),
    #[error("schema 文件没有可执行 SQL")]
    SchemaEmpty,
    #[error("schema 执行失败: {0}")]
    SchemaExecuteFailed(String),
    #[error("schema 检查失败: {0}")]
    SchemaInspectFailed(String),
    #[error("schema 结构异常: {0}")]
    SchemaInvariantFailed(String),
    #[error("{0}")]
    InvalidInput(String),
    #[error("数据库连接失败：{0}")]
    DatabaseConnectFailed(String),
    #[error("配置文件读取失败: {0}")]
    ConfigReadFailed(String),
    #[error("配置文件写入失败: {0}")]
    ConfigWriteFailed(String),
    #[error("管理员账号创建失败: {0}")]
    AdminCreateFailed(String),
}

#[derive(Debug, Clone, Copy)]
struct ColumnPatch {
    table: &'static str,
    column: &'static str,
    sql: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct NullableColumnPatch {
    table: &'static str,
    column: &'static str,
    foreign_key: &'static str,
    modify_sql: &'static str,
    restore_sql: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct IndexPatch {
    table: &'static str,
    index: &'static str,
    sql: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct DropColumnPatch {
    table: &'static str,
    column: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StrategyProbe {
    ids_valid: bool,
    column_valid: bool,
    engine_valid: bool,
}

impl StrategyProbe {
    fn supported(self) -> bool {
        self.ids_valid && self.column_valid && self.engine_valid
    }

    fn summary(self) -> String {
        format!(
            "ids_valid={}, column_valid={}, engine_valid={}",
            self.ids_valid, self.column_valid, self.engine_valid
        )
    }
}

struct CardSearchBackfillRow {
    card_id: u64,
    app_id: u64,
    card_cipher: String,
}

const CARD_SEARCH_BACKFILL_BATCH_SIZE: i64 = 500;

const COLUMN_PATCHES: &[ColumnPatch] = &[
    ColumnPatch {
        table: "sub_admin",
        column: "remember_login_token_hash",
        sql: "ALTER TABLE `sub_admin` ADD COLUMN `remember_login_token_hash` char(64) NOT NULL DEFAULT '' AFTER `cookies`",
    },
    ColumnPatch {
        table: "sub_admin",
        column: "remember_login_expires_at",
        sql: "ALTER TABLE `sub_admin` ADD COLUMN `remember_login_expires_at` datetime DEFAULT NULL AFTER `remember_login_token_hash`",
    },
    ColumnPatch {
        table: "auth_apps",
        column: "api_token",
        sql: "ALTER TABLE `auth_apps` ADD COLUMN `api_token` varchar(64) NOT NULL DEFAULT '' COMMENT '客户端请求Token' AFTER `app_code`",
    },
    ColumnPatch {
        table: "auth_apps",
        column: "login_ip_binding_enabled",
        sql: "ALTER TABLE `auth_apps` ADD COLUMN `login_ip_binding_enabled` tinyint unsigned NOT NULL DEFAULT 0 COMMENT '1校验首次登录IP 0不校验' AFTER `api_token`",
    },
    ColumnPatch {
        table: "auth_apps",
        column: "web_card_query_enabled",
        sql: "ALTER TABLE `auth_apps` ADD COLUMN `web_card_query_enabled` tinyint unsigned NOT NULL DEFAULT 0 COMMENT '1允许网页查询卡密 0关闭' AFTER `login_ip_binding_enabled`",
    },
    ColumnPatch {
        table: "auth_apps",
        column: "api_success_code",
        sql: "ALTER TABLE `auth_apps` ADD COLUMN `api_success_code` int unsigned NOT NULL DEFAULT 0 COMMENT '客户端接口成功状态码' AFTER `web_card_query_enabled`",
    },
    ColumnPatch {
        table: "auth_apps",
        column: "api_config_json",
        sql: "ALTER TABLE `auth_apps` ADD COLUMN `api_config_json` longtext NULL COMMENT '接口开关与调用ID配置' AFTER `api_success_code`",
    },
    ColumnPatch {
        table: "auth_apps",
        column: "unbind_interval_seconds",
        sql: "ALTER TABLE `auth_apps` ADD COLUMN `unbind_interval_seconds` int unsigned NOT NULL DEFAULT 0 COMMENT '解绑冷却秒数' AFTER `web_card_query_enabled`",
    },
    ColumnPatch {
        table: "auth_apps",
        column: "unbind_deduct_seconds",
        sql: "ALTER TABLE `auth_apps` ADD COLUMN `unbind_deduct_seconds` int unsigned NOT NULL DEFAULT 0 COMMENT '解绑扣除时长秒数' AFTER `unbind_interval_seconds`",
    },
    ColumnPatch {
        table: "auth_apps",
        column: "unbind_deduct_uses",
        sql: "ALTER TABLE `auth_apps` ADD COLUMN `unbind_deduct_uses` int unsigned NOT NULL DEFAULT 0 COMMENT '解绑扣除次数' AFTER `unbind_deduct_seconds`",
    },
    ColumnPatch {
        table: "auth_cards",
        column: "card_type",
        sql: "ALTER TABLE `auth_cards` ADD COLUMN `card_type` varchar(16) NOT NULL DEFAULT 'time' COMMENT 'time/permanent/count' AFTER `card_hash`",
    },
    ColumnPatch {
        table: "auth_cards",
        column: "total_uses",
        sql: "ALTER TABLE `auth_cards` ADD COLUMN `total_uses` int unsigned NOT NULL DEFAULT 0 COMMENT '次数卡总次数' AFTER `duration_seconds`",
    },
    ColumnPatch {
        table: "auth_cards",
        column: "remaining_uses",
        sql: "ALTER TABLE `auth_cards` ADD COLUMN `remaining_uses` int unsigned NOT NULL DEFAULT 0 COMMENT '次数卡剩余次数' AFTER `total_uses`",
    },
    ColumnPatch {
        table: "auth_cards",
        column: "card_structure",
        sql: "ALTER TABLE `auth_cards` ADD COLUMN `card_structure` varchar(16) NOT NULL DEFAULT 'hex' COMMENT '卡密生成结构' AFTER `max_devices`",
    },
    ColumnPatch {
        table: "auth_cards",
        column: "prefix",
        sql: "ALTER TABLE `auth_cards` ADD COLUMN `prefix` varchar(12) NOT NULL DEFAULT '' COMMENT '卡密前缀' AFTER `card_structure`",
    },
    ColumnPatch {
        table: "auth_cards",
        column: "unbind_limit",
        sql: "ALTER TABLE `auth_cards` ADD COLUMN `unbind_limit` int unsigned NOT NULL DEFAULT 0 COMMENT '允许解绑次数，0为不限' AFTER `prefix`",
    },
    ColumnPatch {
        table: "auth_cards",
        column: "unbind_count",
        sql: "ALTER TABLE `auth_cards` ADD COLUMN `unbind_count` int unsigned NOT NULL DEFAULT 0 COMMENT '已解绑次数' AFTER `unbind_limit`",
    },
    ColumnPatch {
        table: "auth_cards",
        column: "last_unbound_at",
        sql: r#"ALTER TABLE `auth_cards` ADD COLUMN `last_unbound_at` datetime DEFAULT NULL COMMENT '最近解绑时间' AFTER `unbind_count`"#,
    },
    ColumnPatch {
        table: "auth_devices",
        column: "bind_ip",
        sql: "ALTER TABLE `auth_devices` ADD COLUMN `bind_ip` varchar(45) NOT NULL DEFAULT '' COMMENT '首次绑定IP' AFTER `device_name`",
    },
    ColumnPatch {
        table: "auth_devices",
        column: "bind_region",
        sql: "ALTER TABLE `auth_devices` ADD COLUMN `bind_region` varchar(120) NOT NULL DEFAULT '' COMMENT '首次绑定IP地区范围' AFTER `bind_ip`",
    },
    ColumnPatch {
        table: "auth_audit_logs",
        column: "region",
        sql: "ALTER TABLE `auth_audit_logs` ADD COLUMN `region` varchar(80) NOT NULL DEFAULT '' AFTER `ip`",
    },
    ColumnPatch {
        table: "auth_apps",
        column: "heartbeat_enabled",
        sql: "ALTER TABLE `auth_apps` ADD COLUMN `heartbeat_enabled` tinyint unsigned NOT NULL DEFAULT 1 COMMENT '1启用心跳 0关闭心跳' AFTER `heartbeat_interval`",
    },
    ColumnPatch {
        table: "auth_apps",
        column: "verification_enabled",
        sql: "ALTER TABLE `auth_apps` ADD COLUMN `verification_enabled` tinyint unsigned NOT NULL DEFAULT 1 COMMENT '1验证卡密 0任意卡密' AFTER `heartbeat_enabled`",
    },
    ColumnPatch {
        table: "auth_apps",
        column: "device_binding_enabled",
        sql: "ALTER TABLE `auth_apps` ADD COLUMN `device_binding_enabled` tinyint unsigned NOT NULL DEFAULT 1 COMMENT '1绑定设备 0不绑定设备' AFTER `verification_enabled`",
    },
    ColumnPatch {
        table: "auth_apps",
        column: "shared_cards_enabled",
        sql: "ALTER TABLE `auth_apps` ADD COLUMN `shared_cards_enabled` tinyint unsigned NOT NULL DEFAULT 0 COMMENT '1允许多人登录 0单人登录限制' AFTER `device_binding_enabled`",
    },
    ColumnPatch {
        table: "auth_apps",
        column: "remark",
        sql: "ALTER TABLE `auth_apps` ADD COLUMN `remark` varchar(255) NOT NULL DEFAULT '' COMMENT '备注' AFTER `latest_version`",
    },
    ColumnPatch {
        table: "auth_apps",
        column: "client_crypto_alg",
        sql: "ALTER TABLE `auth_apps` ADD COLUMN `client_crypto_alg` varchar(40) NOT NULL DEFAULT 'rsa_oaep_aes_256_gcm' COMMENT '客户端加密算法' AFTER `latest_version`",
    },
    ColumnPatch {
        table: "auth_apps",
        column: "client_auth_mode",
        sql: "ALTER TABLE `auth_apps` ADD COLUMN `client_auth_mode` varchar(32) NOT NULL DEFAULT 'local_key_v1' COMMENT '客户端鉴权模式' AFTER `latest_version`",
    },
    ColumnPatch {
        table: "auth_apps",
        column: "client_public_key",
        sql: r#"ALTER TABLE `auth_apps` ADD COLUMN `client_public_key` text NULL COMMENT '请求加密公钥' AFTER `client_crypto_alg`"#,
    },
    ColumnPatch {
        table: "auth_apps",
        column: "client_private_key_cipher",
        sql: r#"ALTER TABLE `auth_apps` ADD COLUMN `client_private_key_cipher` text NULL COMMENT '使用SYS_KEY加密后的客户端请求解密私钥' AFTER `client_public_key`"#,
    },
    ColumnPatch {
        table: "auth_remote_configs",
        column: "notice",
        sql: r#"ALTER TABLE `auth_remote_configs` ADD COLUMN `notice` text NULL COMMENT '应用公告' AFTER `app_id`"#,
    },
    ColumnPatch {
        table: "auth_remote_configs",
        column: "variables_json",
        sql: "ALTER TABLE `auth_remote_configs` ADD COLUMN `variables_json` longtext NULL AFTER `config_json`",
    },
    ColumnPatch {
        table: "auth_cards",
        column: "card_cipher",
        sql: "ALTER TABLE `auth_cards` ADD COLUMN `card_cipher` text NOT NULL COMMENT '使用SYS_KEY加密保存的完整卡密' AFTER `card_hash`",
    },
    ColumnPatch {
        table: "auth_cards",
        column: "card_fingerprint",
        sql: "ALTER TABLE `auth_cards` ADD COLUMN `card_fingerprint` varchar(32) NOT NULL DEFAULT '' COMMENT '卡密脱敏展示' AFTER `card_cipher`",
    },
    ColumnPatch {
        table: "auth_sessions",
        column: "card_id",
        sql: "ALTER TABLE `auth_sessions` ADD COLUMN `card_id` bigint unsigned DEFAULT NULL AFTER `device_id`",
    },
    ColumnPatch {
        table: "auth_sessions",
        column: "card_hash",
        sql: "ALTER TABLE `auth_sessions` ADD COLUMN `card_hash` char(64) NOT NULL DEFAULT '' AFTER `card_id`",
    },
    ColumnPatch {
        table: "auth_sessions",
        column: "card_fingerprint",
        sql: "ALTER TABLE `auth_sessions` ADD COLUMN `card_fingerprint` varchar(32) NOT NULL DEFAULT '' COMMENT '登录卡密脱敏展示' AFTER `card_hash`",
    },
    ColumnPatch {
        table: "auth_sessions",
        column: "request_counter",
        sql: "ALTER TABLE `auth_sessions` ADD COLUMN `request_counter` bigint unsigned NOT NULL DEFAULT 0 AFTER `token_hash`",
    },
    ColumnPatch {
        table: "auth_sessions",
        column: "proof_mode",
        sql: "ALTER TABLE `auth_sessions` ADD COLUMN `proof_mode` varchar(32) NOT NULL DEFAULT 'local_key_v1' COMMENT 'session证明模式' AFTER `request_counter`",
    },
    ColumnPatch {
        table: "auth_sessions",
        column: "ticket_hash",
        sql: "ALTER TABLE `auth_sessions` ADD COLUMN `ticket_hash` char(64) DEFAULT NULL COMMENT '临时票据哈希' AFTER `proof_mode`",
    },
    ColumnPatch {
        table: "auth_sessions",
        column: "ticket_expires_at",
        sql: "ALTER TABLE `auth_sessions` ADD COLUMN `ticket_expires_at` datetime DEFAULT NULL COMMENT '临时票据过期时间' AFTER `ticket_hash`",
    },
    ColumnPatch {
        table: "auth_devices",
        column: "card_id",
        sql: "ALTER TABLE `auth_devices` ADD COLUMN `card_id` bigint unsigned DEFAULT NULL AFTER `account_id`",
    },
    ColumnPatch {
        table: "auth_devices",
        column: "card_hash",
        sql: "ALTER TABLE `auth_devices` ADD COLUMN `card_hash` char(64) NOT NULL DEFAULT '' AFTER `card_id`",
    },
    ColumnPatch {
        table: "auth_devices",
        column: "install_id",
        sql: "ALTER TABLE `auth_devices` ADD COLUMN `install_id` varchar(80) NOT NULL DEFAULT '' AFTER `device_name`",
    },
    ColumnPatch {
        table: "auth_devices",
        column: "device_public_key",
        sql: "ALTER TABLE `auth_devices` ADD COLUMN `device_public_key` mediumtext NULL COMMENT '设备验签公钥' AFTER `install_id`",
    },
    ColumnPatch {
        table: "auth_devices",
        column: "device_key_alg",
        sql: "ALTER TABLE `auth_devices` ADD COLUMN `device_key_alg` varchar(32) NOT NULL DEFAULT 'local_key_v1' COMMENT '设备证明模式' AFTER `device_public_key`",
    },
    ColumnPatch {
        table: "auth_devices",
        column: "machine_profile_hash",
        sql: "ALTER TABLE `auth_devices` ADD COLUMN `machine_profile_hash` char(64) NOT NULL DEFAULT '' AFTER `device_key_alg`",
    },
    ColumnPatch {
        table: "auth_devices",
        column: "risk_level",
        sql: "ALTER TABLE `auth_devices` ADD COLUMN `risk_level` tinyint unsigned NOT NULL DEFAULT 0 AFTER `machine_profile_hash`",
    },
    ColumnPatch {
        table: "auth_login_challenges",
        column: "device_public_key",
        sql: r#"ALTER TABLE `auth_login_challenges` ADD COLUMN `device_public_key` mediumtext NULL COMMENT '设备验签公钥' AFTER `device_name`"#,
    },
    ColumnPatch {
        table: "auth_login_challenges",
        column: "device_key_mode",
        sql: "ALTER TABLE `auth_login_challenges` ADD COLUMN `device_key_mode` varchar(32) NOT NULL DEFAULT 'local_key_v1' COMMENT '设备证明模式' AFTER `device_public_key`",
    },
    ColumnPatch {
        table: "auth_admin_sessions",
        column: "admin_username",
        sql: "ALTER TABLE `auth_admin_sessions` ADD COLUMN `admin_username` varchar(64) NOT NULL DEFAULT '' COMMENT '当前后台管理员账号' AFTER `ip`",
    },
    ColumnPatch {
        table: "auth_messages",
        column: "read_at",
        sql: "ALTER TABLE `auth_messages` ADD COLUMN `read_at` datetime DEFAULT NULL AFTER `handled_by`",
    },
    ColumnPatch {
        table: "auth_security_policies",
        column: "enabled",
        sql: "ALTER TABLE `auth_security_policies` ADD COLUMN `enabled` tinyint unsigned NOT NULL DEFAULT 1 AFTER `app_id`",
    },
    ColumnPatch {
        table: "auth_security_policies",
        column: "kick_score",
        sql: "ALTER TABLE `auth_security_policies` ADD COLUMN `kick_score` smallint unsigned NOT NULL DEFAULT 80 AFTER `max_client_action`",
    },
    ColumnPatch {
        table: "auth_security_policies",
        column: "disable_device_score",
        sql: "ALTER TABLE `auth_security_policies` ADD COLUMN `disable_device_score` smallint unsigned NOT NULL DEFAULT 95 AFTER `kick_score`",
    },
    ColumnPatch {
        table: "auth_security_policies",
        column: "disable_card_score",
        sql: "ALTER TABLE `auth_security_policies` ADD COLUMN `disable_card_score` smallint unsigned NOT NULL DEFAULT 120 AFTER `disable_device_score`",
    },
    ColumnPatch {
        table: "auth_security_policies",
        column: "allowed_client_actions",
        sql: "ALTER TABLE `auth_security_policies` ADD COLUMN `allowed_client_actions` varchar(128) NOT NULL DEFAULT 'record_only,kick_session,disable_device,disable_card' AFTER `disable_card_score`",
    },
    ColumnPatch {
        table: "auth_security_policies",
        column: "client_disable_device_min_score",
        sql: "ALTER TABLE `auth_security_policies` ADD COLUMN `client_disable_device_min_score` smallint unsigned NOT NULL DEFAULT 80 AFTER `allowed_client_actions`",
    },
    ColumnPatch {
        table: "auth_security_policies",
        column: "client_disable_card_min_score",
        sql: "ALTER TABLE `auth_security_policies` ADD COLUMN `client_disable_card_min_score` smallint unsigned NOT NULL DEFAULT 95 AFTER `client_disable_device_min_score`",
    },
    ColumnPatch {
        table: "auth_security_policies",
        column: "report_rate_limit_per_minute",
        sql: "ALTER TABLE `auth_security_policies` ADD COLUMN `report_rate_limit_per_minute` int unsigned NOT NULL DEFAULT 20 AFTER `client_disable_card_min_score`",
    },
    ColumnPatch {
        table: "auth_security_policies",
        column: "report_retention_days",
        sql: "ALTER TABLE `auth_security_policies` ADD COLUMN `report_retention_days` int unsigned NOT NULL DEFAULT 90 AFTER `report_rate_limit_per_minute`",
    },
    ColumnPatch {
        table: "auth_security_policies",
        column: "message_retention_days",
        sql: "ALTER TABLE `auth_security_policies` ADD COLUMN `message_retention_days` int unsigned NOT NULL DEFAULT 180 AFTER `report_retention_days`",
    },
];

const NULLABLE_COLUMN_PATCHES: &[NullableColumnPatch] = &[
    NullableColumnPatch {
        table: "auth_devices",
        column: "account_id",
        foreign_key: "fk_auth_devices_account",
        modify_sql: "ALTER TABLE `auth_devices` MODIFY COLUMN `account_id` bigint unsigned DEFAULT NULL",
        restore_sql: "ALTER TABLE `auth_devices` ADD CONSTRAINT `fk_auth_devices_account` FOREIGN KEY (`account_id`) REFERENCES `auth_accounts` (`id`) ON DELETE CASCADE",
    },
    NullableColumnPatch {
        table: "auth_sessions",
        column: "account_id",
        foreign_key: "fk_auth_sessions_account",
        modify_sql: "ALTER TABLE `auth_sessions` MODIFY COLUMN `account_id` bigint unsigned DEFAULT NULL",
        restore_sql: "ALTER TABLE `auth_sessions` ADD CONSTRAINT `fk_auth_sessions_account` FOREIGN KEY (`account_id`) REFERENCES `auth_accounts` (`id`) ON DELETE CASCADE",
    },
    NullableColumnPatch {
        table: "auth_sessions",
        column: "device_id",
        foreign_key: "fk_auth_sessions_device",
        modify_sql: "ALTER TABLE `auth_sessions` MODIFY COLUMN `device_id` bigint unsigned DEFAULT NULL",
        restore_sql: "ALTER TABLE `auth_sessions` ADD CONSTRAINT `fk_auth_sessions_device` FOREIGN KEY (`device_id`) REFERENCES `auth_devices` (`id`) ON DELETE CASCADE",
    },
    NullableColumnPatch {
        table: "auth_audit_logs",
        column: "app_id",
        foreign_key: "fk_auth_audit_app",
        modify_sql: "ALTER TABLE `auth_audit_logs` MODIFY COLUMN `app_id` bigint unsigned DEFAULT NULL",
        restore_sql: "ALTER TABLE `auth_audit_logs` ADD CONSTRAINT `fk_auth_audit_app` FOREIGN KEY (`app_id`) REFERENCES `auth_apps` (`id`) ON DELETE CASCADE",
    },
];

const DROP_COLUMN_PATCHES: &[DropColumnPatch] = &[DropColumnPatch {
    table: "auth_devices",
    column: "device_secret_cipher",
}];

const INDEX_PATCHES: &[IndexPatch] = &[
    IndexPatch {
        table: "auth_sessions",
        index: "idx_auth_sessions_card",
        sql: "ALTER TABLE `auth_sessions` ADD INDEX `idx_auth_sessions_card` (`app_id`, `card_id`, `status`, `expires_at`)",
    },
    IndexPatch {
        table: "auth_sessions",
        index: "idx_auth_sessions_app_status_expire",
        sql: "ALTER TABLE `auth_sessions` ADD INDEX `idx_auth_sessions_app_status_expire` (`app_id`, `status`, `expires_at`)",
    },
    IndexPatch {
        table: "auth_sessions",
        index: "idx_auth_sessions_app_ip",
        sql: "ALTER TABLE `auth_sessions` ADD INDEX `idx_auth_sessions_app_ip` (`app_id`, `ip`)",
    },
    IndexPatch {
        table: "auth_sessions",
        index: "idx_auth_sessions_device_card",
        sql: "ALTER TABLE `auth_sessions` ADD INDEX `idx_auth_sessions_device_card` (`app_id`, `device_id`, `status`, `card_id`, `card_hash`, `id`)",
    },
    IndexPatch {
        table: "auth_devices",
        index: "idx_auth_devices_card",
        sql: "ALTER TABLE `auth_devices` ADD INDEX `idx_auth_devices_card` (`app_id`, `card_id`, `status`)",
    },
    IndexPatch {
        table: "auth_devices",
        index: "idx_auth_devices_card_device",
        sql: "ALTER TABLE `auth_devices` ADD INDEX `idx_auth_devices_card_device` (`app_id`, `card_hash`, `device_hash`)",
    },
    IndexPatch {
        table: "auth_devices",
        index: "idx_auth_devices_app_status",
        sql: "ALTER TABLE `auth_devices` ADD INDEX `idx_auth_devices_app_status` (`app_id`, `status`)",
    },
    IndexPatch {
        table: "auth_devices",
        index: "uk_auth_devices_install",
        sql: "ALTER TABLE `auth_devices` ADD UNIQUE INDEX `uk_auth_devices_install` (`app_id`, `install_id`)",
    },
    IndexPatch {
        table: "auth_cards",
        index: "idx_auth_cards_app_used",
        sql: "ALTER TABLE `auth_cards` ADD INDEX `idx_auth_cards_app_used` (`app_id`, `used_at`)",
    },
    IndexPatch {
        table: "auth_audit_logs",
        index: "idx_auth_audit_app_action_time",
        sql: "ALTER TABLE `auth_audit_logs` ADD INDEX `idx_auth_audit_app_action_time` (`app_id`, `action`, `created_at`)",
    },
    IndexPatch {
        table: "auth_audit_logs",
        index: "idx_auth_audit_app_id",
        sql: "ALTER TABLE `auth_audit_logs` ADD INDEX `idx_auth_audit_app_id` (`app_id`, `id`)",
    },
    IndexPatch {
        table: "auth_admin_sessions",
        index: "idx_auth_admin_sessions_admin_status",
        sql: "ALTER TABLE `auth_admin_sessions` ADD INDEX `idx_auth_admin_sessions_admin_status` (`admin_username`, `status`)",
    },
];

const CORE_SCHEMA_TABLES: &[&str] = &[
    "sub_admin",
    "site_settings",
    "log",
    "auth_apps",
    "auth_app_secrets",
    "auth_accounts",
    "auth_cards",
    "auth_card_search_tokens",
    "auth_devices",
    "auth_sessions",
    "auth_login_challenges",
    "auth_nonces",
    "auth_remote_configs",
    "auth_remote_variables",
    "auth_remote_variable_apps",
    "auth_remote_api_tokens",
    "auth_remote_api_nonces",
    "auth_remote_api_logs",
    "auth_cloud_storage_configs",
    "auth_cloud_files",
    "auth_cloud_download_token",
    "auth_cloud_upload_tickets",
    "auth_audit_logs",
    "auth_security_reports",
    "auth_messages",
    "auth_message_actions",
    "auth_security_policies",
    "auth_admin_sessions",
    "auth_admin_nonces",
];

impl SchemaMigrationPlan {
    pub fn from_file(
        path: impl AsRef<Path>,
        id_strategy: IdStrategy,
    ) -> Result<Self, InstallError> {
        let sql = fs::read_to_string(path.as_ref())
            .map_err(|error| InstallError::SchemaReadFailed(error.to_string()))?;
        Self::from_sql(&sql, id_strategy)
    }

    pub fn from_sql(sql: &str, id_strategy: IdStrategy) -> Result<Self, InstallError> {
        let statements = split_sql_statements(sql)
            .into_iter()
            .map(|statement| sql_for_id_strategy(&statement, id_strategy))
            .collect::<Vec<_>>();
        if statements.is_empty() {
            return Err(InstallError::SchemaEmpty);
        }
        Ok(Self {
            statements,
            id_strategy,
        })
    }

    pub fn statement_count(&self) -> usize {
        self.statements.len()
    }

    pub fn id_strategy(&self) -> IdStrategy {
        self.id_strategy
    }

    pub fn statements(&self) -> &[String] {
        &self.statements
    }
}

impl From<&InstallDatabaseConfig> for DatabaseConfig {
    fn from(config: &InstallDatabaseConfig) -> Self {
        Self {
            host: config.host.clone(),
            port: config.port,
            username: config.username.clone(),
            password: config.password.clone(),
            database_name: config.database_name.clone(),
        }
    }
}

pub fn normalize_database_config(
    host: &str,
    port: &str,
    username: &str,
    password: &str,
    database_name: &str,
) -> Result<InstallDatabaseConfig, InstallError> {
    let port = port.trim().parse::<u16>().map_err(|_| {
        InstallError::InvalidInput("数据库端口必须在 1 到 65535 之间。".to_string())
    })?;
    let config = InstallDatabaseConfig {
        host: normalize_database_host(host)?,
        port,
        username: username.trim().to_string(),
        password: password.to_string(),
        database_name: database_name.trim().to_string(),
    };
    assert_database_config(&config)?;
    Ok(config)
}

pub fn normalize_admin_account(
    username: &str,
    password: &str,
    confirm_password: &str,
) -> Result<InstallAdminAccount, InstallError> {
    if password != confirm_password {
        return Err(InstallError::InvalidInput(
            "两次输入的管理员密码不一致。".to_string(),
        ));
    }
    let account = InstallAdminAccount {
        username: username.trim().to_string(),
        password: password.to_string(),
    };
    assert_admin_account(&account)?;
    Ok(account)
}

pub async fn run_system_install(
    paths: &InstallSystemPaths,
    database_config: &InstallDatabaseConfig,
    create_database: bool,
    admin_account: &InstallAdminAccount,
) -> Result<InstallSystemResult, InstallError> {
    run_system_install_with_strategy(paths, database_config, create_database, admin_account, None)
        .await
}

pub async fn run_system_install_with_strategy(
    paths: &InstallSystemPaths,
    database_config: &InstallDatabaseConfig,
    create_database: bool,
    admin_account: &InstallAdminAccount,
    preferred_strategy: Option<IdStrategy>,
) -> Result<InstallSystemResult, InstallError> {
    let id_strategy =
        prepare_database_with_strategy(database_config, create_database, preferred_strategy)
            .await?;
    write_db_config(&paths.config_file, database_config, id_strategy)?;
    let system_key = config_system_key(&paths.config_file)?;
    let plan = SchemaMigrationPlan::from_file(&paths.schema_file, id_strategy)?;
    let pool = connect_install_database(database_config, true).await?;
    let migration = run_schema_migration(
        &pool,
        &plan,
        &database_config.database_name,
        system_key.as_deref(),
    )
    .await?;
    let admin_username = ensure_admin_account(&pool, admin_account).await?;
    let secret_result = ensure_secrets(&paths.config_file)?;
    pool.close().await;
    write_lock_file(&paths.lock_file)?;
    Ok(InstallSystemResult {
        config_file: relative_install_path(&paths.config_file),
        statement_count: migration.schema_statements,
        admin_username,
        admin_token: secret_result.admin_token,
        id_strategy,
    })
}

pub async fn prepare_database(
    config: &InstallDatabaseConfig,
    create_database: bool,
) -> Result<IdStrategy, InstallError> {
    prepare_database_with_strategy(config, create_database, None).await
}

pub async fn prepare_database_with_strategy(
    config: &InstallDatabaseConfig,
    create_database: bool,
    preferred_strategy: Option<IdStrategy>,
) -> Result<IdStrategy, InstallError> {
    if create_database {
        create_database_if_missing(config).await?;
    }
    let pool = connect_install_database(config, true).await?;
    sqlx::query("SELECT 1")
        .execute(&pool)
        .await
        .map_err(|error| InstallError::DatabaseConnectFailed(error.to_string()))?;
    let strategy = resolve_id_strategy(&pool, &config.database_name, preferred_strategy).await?;
    pool.close().await;
    Ok(strategy)
}

pub fn id_strategy_from_php_config(path: &Path) -> Result<Option<IdStrategy>, InstallError> {
    if !path.is_file() {
        return Ok(None);
    }
    let content = fs::read_to_string(path)
        .map_err(|error| InstallError::ConfigReadFailed(error.to_string()))?;
    read_string_define(&content, "NETWORK_AUTH_ID_STRATEGY")
        .map(|value| id_strategy_from_name(&value))
        .transpose()
}

fn normalize_database_host(host: &str) -> Result<String, InstallError> {
    let normalized = host.trim();
    if normalized.contains("://") {
        return Err(InstallError::InvalidInput(
            "数据库地址只填写 IP、域名或内网地址，不要填写 URL 协议。".to_string(),
        ));
    }
    if normalized
        .chars()
        .any(|character| character.is_whitespace() || "/\\@?#".contains(character))
    {
        return Err(InstallError::InvalidInput(
            "数据库地址格式不合法。".to_string(),
        ));
    }
    Ok(normalized.trim_matches(['[', ']']).to_string())
}

fn assert_database_config(config: &InstallDatabaseConfig) -> Result<(), InstallError> {
    if config.host.is_empty() || config.host.len() > 255 {
        return Err(InstallError::InvalidInput(
            "数据库地址不能为空且不能超过 255 个字符。".to_string(),
        ));
    }
    if config.username.is_empty() || config.username.len() > 80 {
        return Err(InstallError::InvalidInput(
            "数据库用户名不能为空且不能超过 80 个字符。".to_string(),
        ));
    }
    if !valid_database_name(&config.database_name) {
        return Err(InstallError::InvalidInput(
            "数据库名只能使用 1 到 64 位字母、数字和下划线。".to_string(),
        ));
    }
    Ok(())
}

fn valid_database_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn assert_admin_account(account: &InstallAdminAccount) -> Result<(), InstallError> {
    if !valid_admin_username(&account.username) {
        return Err(InstallError::InvalidInput(
            "管理员账号只能使用 3 到 32 位字母、数字、下划线、点、@ 或短横线。".to_string(),
        ));
    }
    if account.password.len() < 8 || account.password.len() > 72 {
        return Err(InstallError::InvalidInput(
            "管理员密码长度必须在 8 到 72 个字符之间。".to_string(),
        ));
    }
    Ok(())
}

fn valid_admin_username(value: &str) -> bool {
    value.len() >= 3
        && value.len() <= 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'@' | b'-'))
}

async fn create_database_if_missing(config: &InstallDatabaseConfig) -> Result<(), InstallError> {
    let pool = connect_install_database(config, false).await?;
    let sql = format!(
        "CREATE DATABASE IF NOT EXISTS `{}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
        config.database_name
    );
    sqlx::query(&sql)
        .execute(&pool)
        .await
        .map_err(|error| InstallError::SchemaExecuteFailed(error.to_string()))?;
    pool.close().await;
    Ok(())
}

async fn connect_install_database(
    config: &InstallDatabaseConfig,
    use_database: bool,
) -> Result<MySqlPool, InstallError> {
    let mut options = MySqlConnectOptions::new()
        .host(&config.host)
        .port(config.port)
        .username(&config.username)
        .password(&config.password);
    if use_database {
        options = options.database(&config.database_name);
    }
    MySqlPoolOptions::new()
        .max_connections(2)
        .connect_with(options)
        .await
        .map_err(|error| {
            if !use_database && !config.password.is_empty() {
                InstallError::DatabaseConnectFailed(sanitize_database_error(&error.to_string()))
            } else {
                InstallError::DatabaseConnectFailed(error.to_string())
            }
        })
}

fn sanitize_database_error(message: &str) -> String {
    message.to_string()
}

fn write_db_config(
    config_file: &Path,
    database_config: &InstallDatabaseConfig,
    id_strategy: IdStrategy,
) -> Result<(), InstallError> {
    assert_config_writable(config_file)?;
    let content = if config_file.is_file() {
        fs::read_to_string(config_file)
            .map_err(|error| InstallError::ConfigReadFailed(error.to_string()))?
    } else {
        "<?php\ndefined('IN_CRONLITE') or die('Access Denied');\n".to_string()
    };
    let content = ensure_config_header(&content);
    let content = upsert_db_config(&content, database_config);
    let content = upsert_define(
        &content,
        "NETWORK_AUTH_ID_STRATEGY",
        id_strategy_name(id_strategy),
    );
    fs::write(config_file, content)
        .map_err(|error| InstallError::ConfigWriteFailed(error.to_string()))
}

fn config_system_key(config_file: &Path) -> Result<Option<String>, InstallError> {
    let content = fs::read_to_string(config_file)
        .map_err(|error| InstallError::ConfigReadFailed(error.to_string()))?;
    Ok(read_string_define(&content, "SYS_KEY").filter(|value| !value.trim().is_empty()))
}

fn assert_config_writable(config_file: &Path) -> Result<(), InstallError> {
    let Some(directory) = config_file.parent() else {
        return Err(InstallError::ConfigWriteFailed(
            "配置文件路径无效。".to_string(),
        ));
    };
    if !directory.is_dir() {
        return Err(InstallError::ConfigWriteFailed(format!(
            "配置目录不可写：{}",
            directory.display()
        )));
    }
    if config_file.is_file() {
        let metadata = fs::metadata(config_file)
            .map_err(|error| InstallError::ConfigReadFailed(error.to_string()))?;
        if metadata.permissions().readonly() {
            return Err(InstallError::ConfigWriteFailed(format!(
                "配置文件不可写：{}",
                config_file.display()
            )));
        }
    }
    Ok(())
}

fn ensure_config_header(content: &str) -> String {
    let mut body = content.trim_start().to_string();
    if let Some(rest) = body.strip_prefix("<?php") {
        body = rest.to_string();
    }
    let body = body.trim().trim_end_matches("?>").trim();
    let body = if body.contains("defined('IN_CRONLITE')") {
        body.to_string()
    } else {
        format!(
            "defined('IN_CRONLITE') or die('Access Denied');\n{}",
            body.trim_start()
        )
    };
    format!("<?php\n{}\n", body.trim())
}

fn upsert_db_config(content: &str, config: &InstallDatabaseConfig) -> String {
    let assignment = format!(
        "$dbconfig = [\n    'host' => {},\n    'port' => {},\n    'user' => {},\n    'pwd' => {},\n    'dbname' => {},\n];",
        php_string(&config.host),
        config.port,
        php_string(&config.username),
        php_string(&config.password),
        php_string(&config.database_name)
    );
    if let Some(range) = db_config_assignment_range(content) {
        let mut output = String::with_capacity(content.len() + assignment.len());
        output.push_str(&content[..range.start]);
        output.push_str(&assignment);
        output.push_str(&content[range.end..]);
        return output;
    }
    format!("{}\n\n{}\n", content.trim_end(), assignment)
}

fn db_config_assignment_range(content: &str) -> Option<Range<usize>> {
    let start = content.find("$dbconfig")?;
    let tail = &content[start..];
    let mut quote = None;
    let mut escaped = false;
    let mut nested = 0usize;
    for (offset, character) in tail.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = quote.is_some();
            continue;
        }
        if character == '\'' || character == '"' {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            }
            continue;
        }
        if quote.is_some() {
            continue;
        }
        match character {
            '[' | '(' => nested += 1,
            ']' | ')' => nested = nested.saturating_sub(1),
            ';' if nested == 0 => return Some(start..start + offset + 1),
            _ => {}
        }
    }
    None
}

struct InstallSecretResult {
    admin_token: Option<String>,
}

fn ensure_secrets(config_file: &Path) -> Result<InstallSecretResult, InstallError> {
    if !config_file.is_file() {
        return Err(InstallError::ConfigReadFailed(format!(
            "Config file not found: {}",
            config_file.display()
        )));
    }
    assert_config_writable(config_file)?;
    let mut content = fs::read_to_string(config_file)
        .map_err(|error| InstallError::ConfigReadFailed(error.to_string()))?;
    let mut changed = false;
    let mut admin_token = None;

    if needs_define(&content, "SYS_KEY") {
        content = upsert_define(&content, "SYS_KEY", &random_hex(32));
        changed = true;
    }
    if needs_admin_token_hash(&content) {
        let token = crypto::token(32);
        content = upsert_define(
            &content,
            "AUTH_ADMIN_TOKEN_HASH",
            &crypto::sha256_hex(&token),
        );
        admin_token = Some(token);
        changed = true;
    }
    if !has_define(&content, "AUTH_CORS_ORIGINS") {
        content = upsert_define(&content, "AUTH_CORS_ORIGINS", "");
        changed = true;
    }
    if changed {
        fs::write(config_file, content)
            .map_err(|error| InstallError::ConfigWriteFailed(error.to_string()))?;
    }
    Ok(InstallSecretResult { admin_token })
}

async fn ensure_admin_account(
    pool: &MySqlPool,
    admin_account: &InstallAdminAccount,
) -> Result<Option<String>, InstallError> {
    let exists = sqlx::query("SELECT `id` FROM `sub_admin` LIMIT 1")
        .fetch_optional(pool)
        .await
        .map_err(|error| InstallError::SchemaInspectFailed(error.to_string()))?
        .is_some();
    if exists {
        return Ok(None);
    }
    let password_hash = bcrypt_hash(&admin_account.password, 10)
        .map_err(|error| InstallError::AdminCreateFailed(error.to_string()))?;
    sqlx::query("INSERT INTO `sub_admin` (`username`, `password`, `hostname`) VALUES (?, ?, ?)")
        .bind(&admin_account.username)
        .bind(password_hash)
        .bind("授权管理系统")
        .execute(pool)
        .await
        .map_err(|error| InstallError::AdminCreateFailed(error.to_string()))?;
    Ok(Some(admin_account.username.clone()))
}

fn write_lock_file(lock_file: &Path) -> Result<(), InstallError> {
    if let Some(directory) = lock_file.parent() {
        fs::create_dir_all(directory)
            .map_err(|error| InstallError::ConfigWriteFailed(error.to_string()))?;
    }
    fs::write(lock_file, Local::now().to_rfc3339())
        .map_err(|error| InstallError::ConfigWriteFailed(error.to_string()))
}

fn relative_install_path(path: &Path) -> String {
    let absolute = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let root = std::env::current_dir()
        .ok()
        .and_then(|dir| dir.canonicalize().ok());
    if let Some(root) = root {
        if let Ok(relative) = absolute.strip_prefix(root) {
            return relative.display().to_string();
        }
    }
    absolute.display().to_string()
}

fn needs_define(content: &str, name: &str) -> bool {
    read_string_define(content, name)
        .map(|value| value.trim().is_empty())
        .unwrap_or_else(|| !has_define(content, name))
}

fn needs_admin_token_hash(content: &str) -> bool {
    read_string_define(content, "AUTH_ADMIN_TOKEN_HASH")
        .map(|value| !valid_admin_token_hash(&value))
        .unwrap_or_else(|| !has_define(content, "AUTH_ADMIN_TOKEN_HASH"))
}

fn valid_admin_token_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn has_define(content: &str, name: &str) -> bool {
    content
        .lines()
        .any(|line| define_name(line).is_some_and(|define| define == name))
}

fn read_string_define(content: &str, name: &str) -> Option<String> {
    content.lines().find_map(|line| {
        if define_name(line)? != name {
            return None;
        }
        let inner = define_inner(line)?;
        let parts = split_php_arguments(inner);
        if parts.len() == 2 {
            return Some(parts[1].clone());
        }
        None
    })
}

fn upsert_define(content: &str, name: &str, value: &str) -> String {
    let define = format!("define('{}', {});", name, php_string(value));
    let mut replaced = false;
    let mut lines = content
        .lines()
        .map(|line| {
            if define_name(line).is_some_and(|define_name| define_name == name) {
                replaced = true;
                define.clone()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>();
    if !replaced {
        lines.push(define);
    }
    format!("{}\n", lines.join("\n").trim_end())
}

fn define_name(line: &str) -> Option<String> {
    let inner = define_inner(line)?;
    split_php_arguments(inner).into_iter().next()
}

fn define_inner(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    let rest = trimmed.strip_prefix("define")?.trim_start();
    rest.strip_prefix('(')
        .and_then(|value| value.strip_suffix(");"))
}

fn split_php_arguments(value: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' {
            current.push(character);
            escaped = true;
            continue;
        }
        if character == '\'' || character == '"' {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            }
            current.push(character);
            continue;
        }
        if character == ',' && quote.is_none() {
            parts.push(trim_php_literal(&current));
            current.clear();
            continue;
        }
        current.push(character);
    }
    if !current.trim().is_empty() {
        parts.push(trim_php_literal(&current));
    }
    parts
}

fn trim_php_literal(value: &str) -> String {
    let trimmed = value.trim();
    php_string_literal(trimmed).unwrap_or_else(|| trimmed.to_string())
}

fn php_string_literal(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.len() < 2 {
        return None;
    }
    let bytes = trimmed.as_bytes();
    if (bytes[0] == b'\'' && bytes[trimmed.len() - 1] == b'\'')
        || (bytes[0] == b'"' && bytes[trimmed.len() - 1] == b'"')
    {
        return Some(
            trimmed[1..trimmed.len() - 1]
                .replace("\\'", "'")
                .replace("\\\"", "\"")
                .replace("\\\\", "\\"),
        );
    }
    None
}

fn php_string(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn random_hex(byte_count: usize) -> String {
    let mut bytes = vec![0u8; byte_count];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn id_strategy_name(strategy: IdStrategy) -> &'static str {
    match strategy {
        IdStrategy::AutoIncrement => "auto_increment",
        IdStrategy::UuidShortDefault => "uuid_short_default",
    }
}

async fn resolve_id_strategy(
    pool: &MySqlPool,
    database_name: &str,
    preferred_strategy: Option<IdStrategy>,
) -> Result<IdStrategy, InstallError> {
    if let Some(strategy) = existing_core_id_strategy(pool, database_name).await? {
        return Ok(strategy);
    }
    if let Some(strategy) = preferred_strategy {
        let probe = id_strategy_probe(pool, database_name, strategy).await?;
        return if probe.supported() {
            Ok(strategy)
        } else {
            Err(InstallError::SchemaInvariantFailed(format!(
                "当前数据库不支持配置的 {} 主键策略，检测结果：{}。",
                id_strategy_name(strategy),
                probe.summary()
            )))
        };
    }
    if auto_increment_strategy_works(pool, database_name).await? {
        return Ok(IdStrategy::AutoIncrement);
    }
    if uuid_short_strategy_works(pool, database_name).await? {
        return Ok(IdStrategy::UuidShortDefault);
    }
    Err(InstallError::SchemaInvariantFailed(
        "当前数据库不支持安全的自增主键或 UUID_SHORT 主键策略。".to_string(),
    ))
}

async fn id_strategy_probe(
    pool: &MySqlPool,
    database_name: &str,
    strategy: IdStrategy,
) -> Result<StrategyProbe, InstallError> {
    match strategy {
        IdStrategy::AutoIncrement => auto_increment_strategy_probe(pool, database_name).await,
        IdStrategy::UuidShortDefault => uuid_short_strategy_probe(pool, database_name).await,
    }
}

pub fn id_strategy_from_name(value: &str) -> Result<IdStrategy, InstallError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "auto_increment" | "auto-increment" => Ok(IdStrategy::AutoIncrement),
        "uuid_short_default" | "uuid-short-default" => Ok(IdStrategy::UuidShortDefault),
        _ => Err(InstallError::InvalidInput(
            "NETWORK_AUTH_ID_STRATEGY 必须是 auto_increment 或 uuid_short_default。".to_string(),
        )),
    }
}

async fn existing_core_id_strategy(
    pool: &MySqlPool,
    database_name: &str,
) -> Result<Option<IdStrategy>, InstallError> {
    let Some(row) = sqlx::query(
        "SELECT `COLUMN_TYPE`, `COLUMN_DEFAULT`, `EXTRA` FROM `information_schema`.`COLUMNS` WHERE `TABLE_SCHEMA` = ? AND `TABLE_NAME` = ? AND `COLUMN_NAME` = ?",
    )
    .bind(database_name)
    .bind("auth_apps")
    .bind("id")
    .fetch_optional(pool)
    .await
    .map_err(|error| InstallError::SchemaInspectFailed(error.to_string()))?
    else {
        return Ok(None);
    };
    let column_type = optional_row_string(&row, "COLUMN_TYPE");
    let column_default = optional_row_string(&row, "COLUMN_DEFAULT");
    let extra = optional_row_string(&row, "EXTRA");
    if is_unsigned_integer_type(&column_type)
        && extra.to_ascii_lowercase().contains("auto_increment")
    {
        return Ok(Some(IdStrategy::AutoIncrement));
    }
    if is_bigint_unsigned_type(&column_type)
        && column_default.to_ascii_lowercase().contains("uuid_short")
    {
        return Ok(Some(IdStrategy::UuidShortDefault));
    }
    Ok(None)
}

async fn auto_increment_strategy_works(
    pool: &MySqlPool,
    database_name: &str,
) -> Result<bool, InstallError> {
    Ok(auto_increment_strategy_probe(pool, database_name)
        .await?
        .supported())
}

async fn auto_increment_strategy_probe(
    pool: &MySqlPool,
    database_name: &str,
) -> Result<StrategyProbe, InstallError> {
    let table = probe_table_name("auto");
    let create_sql = format!(
        "CREATE TABLE `{table}` (`id` bigint unsigned NOT NULL AUTO_INCREMENT, `name` varchar(12) NOT NULL, PRIMARY KEY (`id`)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
    );
    let result = async {
        execute_patch(pool, &create_sql).await?;
        sqlx::query(&format!(
            "INSERT INTO `{table}` (`name`) VALUES ('a'), ('b')"
        ))
        .execute(pool)
        .await
        .map_err(|error| InstallError::SchemaExecuteFailed(error.to_string()))?;
        let ids_valid = probe_ids_are_valid(pool, &table).await?;
        let uses_auto_increment =
            probe_column_uses_auto_increment(pool, database_name, &table).await?;
        let uses_innodb = probe_table_uses_innodb(pool, database_name, &table).await?;
        Ok::<StrategyProbe, InstallError>(StrategyProbe {
            ids_valid,
            column_valid: uses_auto_increment,
            engine_valid: uses_innodb,
        })
    }
    .await;
    let _ = drop_probe_table(pool, &table).await;
    result
}

async fn uuid_short_strategy_works(
    pool: &MySqlPool,
    database_name: &str,
) -> Result<bool, InstallError> {
    Ok(uuid_short_strategy_probe(pool, database_name)
        .await?
        .supported())
}

async fn uuid_short_strategy_probe(
    pool: &MySqlPool,
    database_name: &str,
) -> Result<StrategyProbe, InstallError> {
    let table = probe_table_name("uuid");
    let create_sql = format!(
        "CREATE TABLE `{table}` (`id` bigint unsigned NOT NULL DEFAULT (UUID_SHORT()), `name` varchar(12) NOT NULL, PRIMARY KEY (`id`)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
    );
    let result = async {
        execute_patch(pool, &create_sql).await?;
        sqlx::query(&format!(
            "INSERT INTO `{table}` (`name`) VALUES ('a'), ('b')"
        ))
        .execute(pool)
        .await
        .map_err(|error| InstallError::SchemaExecuteFailed(error.to_string()))?;
        let ids_valid = probe_ids_are_valid(pool, &table).await?;
        let uses_uuid_default = probe_column_uses_uuid_default(pool, database_name, &table).await?;
        let uses_innodb = probe_table_uses_innodb(pool, database_name, &table).await?;
        Ok::<StrategyProbe, InstallError>(StrategyProbe {
            ids_valid,
            column_valid: uses_uuid_default || ids_valid,
            engine_valid: uses_innodb,
        })
    }
    .await;
    let _ = drop_probe_table(pool, &table).await;
    result
}

fn probe_table_name(suffix: &str) -> String {
    let token = crypto::token(6).replace(['-', '_'], "");
    format!("network_auth_install_probe_{suffix}_{token}")
}

async fn probe_ids_are_valid(pool: &MySqlPool, table: &str) -> Result<bool, InstallError> {
    let sql = format!("SELECT CAST(`id` AS CHAR) AS `id_value` FROM `{table}` ORDER BY `id` ASC");
    let rows = sqlx::query(&sql)
        .fetch_all(pool)
        .await
        .map_err(|error| InstallError::SchemaInspectFailed(error.to_string()))?;
    let ids = rows
        .iter()
        .filter_map(|row| row.try_get::<String, _>("id_value").ok())
        .filter_map(|value| value.parse::<u128>().ok())
        .collect::<Vec<_>>();
    Ok(ids.len() == 2 && ids[0] > 0 && ids[1] > ids[0])
}

async fn probe_column_uses_auto_increment(
    pool: &MySqlPool,
    database_name: &str,
    table: &str,
) -> Result<bool, InstallError> {
    let row = probe_id_column(pool, database_name, table).await?;
    let column_type = optional_row_string(&row, "COLUMN_TYPE");
    let extra = optional_row_string(&row, "EXTRA");
    Ok(is_unsigned_integer_type(&column_type)
        && extra.to_ascii_lowercase().contains("auto_increment"))
}

async fn probe_column_uses_uuid_default(
    pool: &MySqlPool,
    database_name: &str,
    table: &str,
) -> Result<bool, InstallError> {
    let row = probe_id_column(pool, database_name, table).await?;
    let column_type = optional_row_string(&row, "COLUMN_TYPE");
    let column_default = optional_row_string(&row, "COLUMN_DEFAULT");
    Ok(is_bigint_unsigned_type(&column_type)
        && column_default.to_ascii_lowercase().contains("uuid_short"))
}

async fn probe_id_column(
    pool: &MySqlPool,
    database_name: &str,
    table: &str,
) -> Result<sqlx::mysql::MySqlRow, InstallError> {
    sqlx::query(
        "SELECT `COLUMN_TYPE`, `COLUMN_DEFAULT`, `EXTRA` FROM `information_schema`.`COLUMNS` WHERE `TABLE_SCHEMA` = ? AND `TABLE_NAME` = ? AND `COLUMN_NAME` = ?",
    )
    .bind(database_name)
    .bind(table)
    .bind("id")
    .fetch_optional(pool)
    .await
    .map_err(|error| InstallError::SchemaInspectFailed(error.to_string()))?
    .ok_or_else(|| InstallError::SchemaInspectFailed(format!("probe table {table}.id missing")))
}

async fn probe_table_uses_innodb(
    pool: &MySqlPool,
    database_name: &str,
    table: &str,
) -> Result<bool, InstallError> {
    let row = sqlx::query(
        "SELECT `ENGINE` FROM `information_schema`.`TABLES` WHERE `TABLE_SCHEMA` = ? AND `TABLE_NAME` = ?",
    )
    .bind(database_name)
    .bind(table)
    .fetch_optional(pool)
    .await
    .map_err(|error| InstallError::SchemaInspectFailed(error.to_string()))?;
    let engine = row
        .as_ref()
        .map(|row| optional_row_string(row, "ENGINE"))
        .unwrap_or_default();
    Ok(engine.eq_ignore_ascii_case("InnoDB"))
}

fn optional_row_string(row: &sqlx::mysql::MySqlRow, column: &str) -> String {
    row.try_get::<Option<String>, _>(column)
        .ok()
        .flatten()
        .or_else(|| row.try_get::<String, _>(column).ok())
        .or_else(|| {
            row.try_get::<Vec<u8>, _>(column)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
        })
        .unwrap_or_default()
}

async fn drop_probe_table(pool: &MySqlPool, table: &str) -> Result<(), InstallError> {
    execute_patch(pool, &format!("DROP TABLE IF EXISTS `{table}`")).await
}

pub async fn run_schema_migration(
    pool: &MySqlPool,
    plan: &SchemaMigrationPlan,
    database_name: &str,
    system_key: Option<&str>,
) -> Result<SchemaMigrationResult, InstallError> {
    for statement in plan.statements() {
        sqlx::query(statement)
            .execute(pool)
            .await
            .map_err(|error| InstallError::SchemaExecuteFailed(error.to_string()))?;
    }
    let runtime_patches = ensure_runtime_schema(pool, database_name).await?;
    backfill_card_search_tokens(pool, system_key).await?;
    Ok(SchemaMigrationResult {
        schema_statements: plan.statement_count(),
        runtime_patches,
    })
}

pub fn runtime_schema_patch_check_count() -> usize {
    COLUMN_PATCHES.len()
        + NULLABLE_COLUMN_PATCHES.len()
        + DROP_COLUMN_PATCHES.len()
        + INDEX_PATCHES.len()
        + 1
}

pub fn split_sql_statements(sql: &str) -> Vec<String> {
    let without_comments = sql
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");
    without_comments
        .split(';')
        .map(str::trim)
        .filter(|statement| !statement.is_empty())
        .map(str::to_string)
        .collect()
}

pub fn sql_for_id_strategy(sql: &str, id_strategy: IdStrategy) -> String {
    if id_strategy == IdStrategy::AutoIncrement {
        return sql.to_string();
    }

    let mut output = String::with_capacity(sql.len());
    let mut rest = sql;
    let auto_increment_patterns = [
        "`id` int unsigned NOT NULL AUTO_INCREMENT",
        "`id` bigint unsigned NOT NULL AUTO_INCREMENT",
    ];
    while let Some((position, pattern)) = auto_increment_patterns
        .iter()
        .filter_map(|pattern| rest.find(pattern).map(|position| (position, *pattern)))
        .min_by_key(|(position, _)| *position)
    {
        output.push_str(&rest[..position]);
        output.push_str("`id` bigint unsigned NOT NULL DEFAULT (UUID_SHORT())");
        rest = &rest[position + pattern.len()..];
    }
    output.push_str(rest);
    output
}

async fn ensure_runtime_schema(
    pool: &MySqlPool,
    database_name: &str,
) -> Result<usize, InstallError> {
    execute_patch(pool, "SET SESSION default_storage_engine=InnoDB").await?;
    let mut patch_count = 0;
    for patch in COLUMN_PATCHES {
        patch_count += ensure_column(pool, database_name, patch).await?;
    }
    for patch in NULLABLE_COLUMN_PATCHES {
        patch_count += ensure_nullable_column(pool, database_name, patch).await?;
    }
    for patch in DROP_COLUMN_PATCHES {
        patch_count += drop_column_if_exists(pool, database_name, patch).await?;
    }
    for patch in INDEX_PATCHES {
        patch_count += ensure_index(pool, database_name, patch).await?;
    }
    patch_count += ensure_site_settings(pool).await?;
    assert_core_schema(pool, database_name).await?;
    Ok(patch_count)
}

async fn backfill_card_search_tokens(
    pool: &MySqlPool,
    system_key: Option<&str>,
) -> Result<usize, InstallError> {
    let Some(system_key) = system_key.filter(|value| !value.trim().is_empty()) else {
        return Ok(0);
    };
    let rows = sqlx::query(
        "SELECT c.`id`, c.`app_id`, c.`card_cipher` FROM `auth_cards` c \
         WHERE c.`card_cipher` <> '' \
         AND NOT EXISTS (SELECT 1 FROM `auth_card_search_tokens` t WHERE t.`card_id` = c.`id`) \
         ORDER BY c.`id` ASC LIMIT ?",
    )
    .bind(CARD_SEARCH_BACKFILL_BATCH_SIZE)
    .fetch_all(pool)
    .await
    .map_err(|error| InstallError::SchemaInspectFailed(error.to_string()))?;

    let mut indexed_count = 0;
    for row in rows {
        let card = card_search_backfill_row(row)?;
        if card.card_id == 0 || card.app_id == 0 || card.card_cipher.trim().is_empty() {
            continue;
        }
        let card_key = crypto::decrypt_protected_text(card.card_cipher.trim(), system_key)
            .map_err(|error| {
                InstallError::SchemaExecuteFailed(format!(
                    "Card search token backfill failed for card {}: {error}",
                    card.card_id
                ))
            })?;
        let token_hashes =
            card_search::card_token_hashes(&card_key, system_key).map_err(|error| {
                InstallError::SchemaExecuteFailed(format!(
                    "Card search token build failed for card {}: {error}",
                    card.card_id
                ))
            })?;
        replace_card_search_tokens(pool, card.app_id, card.card_id, &token_hashes).await?;
        indexed_count += 1;
    }
    Ok(indexed_count)
}

fn card_search_backfill_row(
    row: sqlx::mysql::MySqlRow,
) -> Result<CardSearchBackfillRow, InstallError> {
    Ok(CardSearchBackfillRow {
        card_id: row
            .try_get::<u64, _>("id")
            .map_err(|error| InstallError::SchemaInspectFailed(error.to_string()))?,
        app_id: row
            .try_get::<u64, _>("app_id")
            .map_err(|error| InstallError::SchemaInspectFailed(error.to_string()))?,
        card_cipher: row
            .try_get::<String, _>("card_cipher")
            .map_err(|error| InstallError::SchemaInspectFailed(error.to_string()))?,
    })
}

async fn replace_card_search_tokens(
    pool: &MySqlPool,
    app_id: u64,
    card_id: u64,
    token_hashes: &[String],
) -> Result<(), InstallError> {
    sqlx::query("DELETE FROM `auth_card_search_tokens` WHERE `app_id` = ? AND `card_id` = ?")
        .bind(app_id)
        .bind(card_id)
        .execute(pool)
        .await
        .map_err(|error| InstallError::SchemaExecuteFailed(error.to_string()))?;
    for chunk in valid_token_hashes(token_hashes).chunks(200) {
        insert_card_search_token_chunk(pool, app_id, card_id, chunk).await?;
    }
    Ok(())
}

async fn insert_card_search_token_chunk(
    pool: &MySqlPool,
    app_id: u64,
    card_id: u64,
    token_hashes: &[String],
) -> Result<(), InstallError> {
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
        .execute(pool)
        .await
        .map_err(|error| InstallError::SchemaExecuteFailed(error.to_string()))?;
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

async fn ensure_column(
    pool: &MySqlPool,
    database_name: &str,
    patch: &ColumnPatch,
) -> Result<usize, InstallError> {
    if column_exists(pool, database_name, patch.table, patch.column).await? {
        return Ok(0);
    }
    execute_patch(pool, patch.sql).await?;
    Ok(1)
}

async fn ensure_index(
    pool: &MySqlPool,
    database_name: &str,
    patch: &IndexPatch,
) -> Result<usize, InstallError> {
    if index_exists(pool, database_name, patch.table, patch.index).await? {
        return Ok(0);
    }
    execute_patch(pool, patch.sql).await?;
    Ok(1)
}

async fn drop_column_if_exists(
    pool: &MySqlPool,
    database_name: &str,
    patch: &DropColumnPatch,
) -> Result<usize, InstallError> {
    if !column_exists(pool, database_name, patch.table, patch.column).await? {
        return Ok(0);
    }
    execute_patch(
        pool,
        &format!(
            "ALTER TABLE `{}` DROP COLUMN `{}`",
            patch.table, patch.column
        ),
    )
    .await?;
    Ok(1)
}

async fn ensure_nullable_column(
    pool: &MySqlPool,
    database_name: &str,
    patch: &NullableColumnPatch,
) -> Result<usize, InstallError> {
    let Some(nullable) = column_nullable(pool, database_name, patch.table, patch.column).await?
    else {
        return Ok(0);
    };
    if nullable {
        return Ok(0);
    }
    let had_foreign_key =
        drop_foreign_key_if_exists(pool, database_name, patch.table, patch.foreign_key).await?;
    execute_patch(pool, patch.modify_sql).await?;
    if had_foreign_key {
        execute_patch(pool, patch.restore_sql).await?;
    }
    Ok(1)
}

async fn ensure_site_settings(pool: &MySqlPool) -> Result<usize, InstallError> {
    let exists = sqlx::query("SELECT `id` FROM `site_settings` WHERE `id` = 1")
        .fetch_optional(pool)
        .await
        .map_err(|error| InstallError::SchemaInspectFailed(error.to_string()))?
        .is_some();
    if exists {
        return Ok(0);
    }

    let admin =
        sqlx::query("SELECT `hostname`, `siteurl` FROM `sub_admin` ORDER BY `id` ASC LIMIT 1")
            .fetch_optional(pool)
            .await
            .map_err(|error| InstallError::SchemaInspectFailed(error.to_string()))?;
    let hostname = admin
        .as_ref()
        .and_then(|row| row.try_get::<String, _>("hostname").ok())
        .unwrap_or_else(|| "授权管理系统".to_string());
    let siteurl = admin
        .as_ref()
        .and_then(|row| row.try_get::<String, _>("siteurl").ok())
        .unwrap_or_default();
    sqlx::query(
        "INSERT INTO `site_settings` (`id`, `hostname`, `siteurl`, `announcement`) VALUES (1, ?, ?, ?)",
    )
    .bind(hostname)
    .bind(siteurl)
    .bind("")
    .execute(pool)
    .await
    .map_err(|error| InstallError::SchemaExecuteFailed(error.to_string()))?;
    Ok(1)
}

async fn assert_core_schema(pool: &MySqlPool, database_name: &str) -> Result<(), InstallError> {
    for table in CORE_SCHEMA_TABLES {
        if *table != "site_settings" {
            assert_innodb_table(pool, database_name, table).await?;
            assert_compatible_id_column(pool, database_name, table).await?;
        }
    }
    Ok(())
}

async fn assert_innodb_table(
    pool: &MySqlPool,
    database_name: &str,
    table: &str,
) -> Result<(), InstallError> {
    let row = sqlx::query(
        "SELECT `ENGINE` FROM `information_schema`.`TABLES` WHERE `TABLE_SCHEMA` = ? AND `TABLE_NAME` = ?",
    )
    .bind(database_name)
    .bind(table)
    .fetch_optional(pool)
    .await
    .map_err(|error| InstallError::SchemaInspectFailed(error.to_string()))?;
    let engine = row
        .as_ref()
        .map(|row| optional_row_string(row, "ENGINE"))
        .unwrap_or_default();
    if engine.to_ascii_uppercase() != "INNODB" {
        return Err(InstallError::SchemaInvariantFailed(format!(
            "数据库表结构异常：{table} 必须使用 InnoDB，请删除错误表后重新安装。"
        )));
    }
    Ok(())
}

async fn assert_compatible_id_column(
    pool: &MySqlPool,
    database_name: &str,
    table: &str,
) -> Result<(), InstallError> {
    let row = sqlx::query(
        "SELECT `COLUMN_TYPE`, `COLUMN_DEFAULT`, `EXTRA` FROM `information_schema`.`COLUMNS` WHERE `TABLE_SCHEMA` = ? AND `TABLE_NAME` = ? AND `COLUMN_NAME` = ?",
    )
    .bind(database_name)
    .bind(table)
    .bind("id")
    .fetch_optional(pool)
    .await
    .map_err(|error| InstallError::SchemaInspectFailed(error.to_string()))?
    .ok_or_else(|| {
        InstallError::SchemaInvariantFailed(format!(
            "数据库表结构异常：{table}.id 必须使用自增或自动 UUID 主键，请删除错误表后重新安装。"
        ))
    })?;
    let column_type = optional_row_string(&row, "COLUMN_TYPE");
    let column_default = optional_row_string(&row, "COLUMN_DEFAULT");
    let extra = optional_row_string(&row, "EXTRA");
    if !compatible_id_column(&column_type, &column_default, &extra) {
        return Err(InstallError::SchemaInvariantFailed(format!(
            "数据库表结构异常：{table}.id 必须使用自增或自动 UUID 主键，请删除错误表后重新安装。"
        )));
    }
    Ok(())
}

async fn column_exists(
    pool: &MySqlPool,
    database_name: &str,
    table: &str,
    column: &str,
) -> Result<bool, InstallError> {
    Ok(sqlx::query(
        "SELECT `COLUMN_NAME` FROM `information_schema`.`COLUMNS` WHERE `TABLE_SCHEMA` = ? AND `TABLE_NAME` = ? AND `COLUMN_NAME` = ?",
    )
    .bind(database_name)
    .bind(table)
    .bind(column)
    .fetch_optional(pool)
    .await
    .map_err(|error| InstallError::SchemaInspectFailed(error.to_string()))?
    .is_some())
}

async fn column_nullable(
    pool: &MySqlPool,
    database_name: &str,
    table: &str,
    column: &str,
) -> Result<Option<bool>, InstallError> {
    let Some(row) = sqlx::query(
        "SELECT `IS_NULLABLE` FROM `information_schema`.`COLUMNS` WHERE `TABLE_SCHEMA` = ? AND `TABLE_NAME` = ? AND `COLUMN_NAME` = ?",
    )
    .bind(database_name)
    .bind(table)
    .bind(column)
    .fetch_optional(pool)
    .await
    .map_err(|error| InstallError::SchemaInspectFailed(error.to_string()))?
    else {
        return Ok(None);
    };
    let nullable = row
        .try_get::<String, _>("IS_NULLABLE")
        .unwrap_or_default()
        .eq_ignore_ascii_case("YES");
    Ok(Some(nullable))
}

async fn index_exists(
    pool: &MySqlPool,
    database_name: &str,
    table: &str,
    index: &str,
) -> Result<bool, InstallError> {
    Ok(sqlx::query(
        "SELECT `INDEX_NAME` FROM `information_schema`.`STATISTICS` WHERE `TABLE_SCHEMA` = ? AND `TABLE_NAME` = ? AND `INDEX_NAME` = ?",
    )
    .bind(database_name)
    .bind(table)
    .bind(index)
    .fetch_optional(pool)
    .await
    .map_err(|error| InstallError::SchemaInspectFailed(error.to_string()))?
    .is_some())
}

async fn foreign_key_exists(
    pool: &MySqlPool,
    database_name: &str,
    table: &str,
    foreign_key: &str,
) -> Result<bool, InstallError> {
    Ok(sqlx::query(
        "SELECT `CONSTRAINT_NAME` FROM `information_schema`.`TABLE_CONSTRAINTS` WHERE `TABLE_SCHEMA` = ? AND `TABLE_NAME` = ? AND `CONSTRAINT_NAME` = ? AND `CONSTRAINT_TYPE` = ?",
    )
    .bind(database_name)
    .bind(table)
    .bind(foreign_key)
    .bind("FOREIGN KEY")
    .fetch_optional(pool)
    .await
    .map_err(|error| InstallError::SchemaInspectFailed(error.to_string()))?
    .is_some())
}

async fn drop_foreign_key_if_exists(
    pool: &MySqlPool,
    database_name: &str,
    table: &str,
    foreign_key: &str,
) -> Result<bool, InstallError> {
    if !foreign_key_exists(pool, database_name, table, foreign_key).await? {
        return Ok(false);
    }
    execute_patch(
        pool,
        &format!("ALTER TABLE `{table}` DROP FOREIGN KEY `{foreign_key}`"),
    )
    .await?;
    Ok(true)
}

async fn execute_patch(pool: &MySqlPool, sql: &str) -> Result<(), InstallError> {
    sqlx::query(sql)
        .execute(pool)
        .await
        .map_err(|error| InstallError::SchemaExecuteFailed(error.to_string()))?;
    Ok(())
}

fn compatible_id_column(column_type: &str, column_default: &str, extra: &str) -> bool {
    let auto_increment_id = is_unsigned_integer_type(column_type)
        && extra.to_ascii_lowercase().contains("auto_increment");
    let extra_lower = extra.to_ascii_lowercase();
    let uuid_default_id = is_bigint_unsigned_type(column_type)
        && (column_default.to_ascii_lowercase().contains("uuid_short")
            || extra_lower.contains("default_generated"));
    auto_increment_id || uuid_default_id
}

fn is_unsigned_integer_type(column_type: &str) -> bool {
    matches!(
        unsigned_integer_base_type(column_type).as_deref(),
        Some("int" | "bigint")
    )
}

fn is_bigint_unsigned_type(column_type: &str) -> bool {
    unsigned_integer_base_type(column_type).as_deref() == Some("bigint")
}

fn unsigned_integer_base_type(column_type: &str) -> Option<String> {
    let lower = column_type.trim().to_ascii_lowercase();
    let unsigned_type = lower.strip_suffix(" unsigned")?.trim();
    let base_type = unsigned_type
        .split_once('(')
        .map(|(base, _)| base)
        .unwrap_or(unsigned_type)
        .trim();
    Some(base_type.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_sql_statements_like_php_installer() {
        let statements = split_sql_statements(
            r#"
-- comment
SET NAMES utf8mb4;

CREATE TABLE `demo` (`id` int unsigned NOT NULL AUTO_INCREMENT);
-- trailing comment
"#,
        );

        assert_eq!(
            vec![
                "SET NAMES utf8mb4".to_string(),
                "CREATE TABLE `demo` (`id` int unsigned NOT NULL AUTO_INCREMENT)".to_string(),
            ],
            statements
        );
    }

    #[test]
    fn rewrites_auto_increment_id_for_uuid_short_strategy() {
        let sql =
            "CREATE TABLE `demo` (`id` int unsigned NOT NULL AUTO_INCREMENT, PRIMARY KEY (`id`))";
        let rewritten = sql_for_id_strategy(sql, IdStrategy::UuidShortDefault);

        assert_eq!(
            "CREATE TABLE `demo` (`id` bigint unsigned NOT NULL DEFAULT (UUID_SHORT()), PRIMARY KEY (`id`))",
            rewritten
        );
    }

    #[test]
    fn loads_php_schema_resource() {
        let plan = SchemaMigrationPlan::from_file(
            "resources/install/schema.sql",
            IdStrategy::AutoIncrement,
        )
        .expect("schema should load");

        assert!(plan.statement_count() > 20);
        assert_eq!(IdStrategy::AutoIncrement, plan.id_strategy());
        assert!(
            plan.statements()
                .iter()
                .any(|statement| statement.contains("CREATE TABLE IF NOT EXISTS `auth_apps`"))
        );
    }

    #[test]
    fn counts_php_runtime_schema_patch_checks() {
        assert_eq!(62, COLUMN_PATCHES.len());
        assert_eq!(4, NULLABLE_COLUMN_PATCHES.len());
        assert_eq!(1, DROP_COLUMN_PATCHES.len());
        assert_eq!(12, INDEX_PATCHES.len());
        assert_eq!(80, runtime_schema_patch_check_count());
    }

    #[test]
    fn normalizes_admin_account_like_php_installer() {
        let account =
            normalize_admin_account(" admin.user ", "password123", "password123").expect("admin");

        assert_eq!("admin.user", account.username);
        assert_eq!("password123", account.password);
        assert!(matches!(
            normalize_admin_account("ad", "password123", "password123"),
            Err(InstallError::InvalidInput(_))
        ));
        assert!(matches!(
            normalize_admin_account("admin", "password-a", "password-b"),
            Err(InstallError::InvalidInput(_))
        ));
    }

    #[test]
    fn upserts_db_config_without_breaking_semicolon_passwords() {
        let content = "<?php\ndefined('IN_CRONLITE') or die('Access Denied');\n$dbconfig = [\n    'host' => 'old',\n    'pwd' => 'old;value',\n];\ndefine('SYS_KEY', 'key');\n";
        let config = InstallDatabaseConfig {
            host: "127.0.0.1".to_string(),
            port: 3306,
            username: "network".to_string(),
            password: "new;secret".to_string(),
            database_name: "network_auth".to_string(),
        };
        let updated = upsert_db_config(content, &config);

        assert!(updated.contains("'pwd' => 'new;secret'"));
        assert!(updated.contains("define('SYS_KEY', 'key');"));
        assert!(!updated.contains("old;value"));
    }

    #[test]
    fn accepts_php_compatible_id_columns() {
        assert!(compatible_id_column(
            "int(10) unsigned",
            "",
            "auto_increment"
        ));
        assert!(compatible_id_column(
            "bigint unsigned",
            "(uuid_short())",
            ""
        ));
        assert!(compatible_id_column(
            "bigint unsigned",
            "",
            "DEFAULT_GENERATED"
        ));
        assert!(!compatible_id_column("varchar(32)", "", ""));
        assert!(!compatible_id_column("int(10) unsigned", "", ""));
    }

    #[test]
    fn parses_configured_id_strategy_names() {
        assert_eq!(
            IdStrategy::AutoIncrement,
            id_strategy_from_name("auto_increment").expect("auto increment")
        );
        assert_eq!(
            IdStrategy::UuidShortDefault,
            id_strategy_from_name("uuid_short_default").expect("uuid short")
        );
        assert!(matches!(
            id_strategy_from_name("bad"),
            Err(InstallError::InvalidInput(_))
        ));
    }

    #[test]
    fn reads_id_strategy_from_php_config() {
        let path =
            std::env::temp_dir().join(format!("network-auth-id-strategy-{}.php", random_hex(6)));
        fs::write(
            &path,
            "<?php\ndefine('NETWORK_AUTH_ID_STRATEGY', 'uuid_short_default');\n",
        )
        .expect("write config");

        let strategy = id_strategy_from_php_config(&path)
            .expect("read strategy")
            .expect("strategy");
        fs::remove_file(path).expect("remove config");

        assert_eq!(IdStrategy::UuidShortDefault, strategy);
    }
}
