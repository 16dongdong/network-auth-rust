SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

CREATE TABLE IF NOT EXISTS `sub_admin` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `username` varchar(64) NOT NULL,
  `password` varchar(255) NOT NULL,
  `cookies` text,
  `remember_login_token_hash` char(64) NOT NULL DEFAULT '',
  `remember_login_expires_at` datetime DEFAULT NULL,
  `hostname` varchar(80) NOT NULL DEFAULT '授权管理系统',
  `siteurl` varchar(255) NOT NULL DEFAULT '',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_sub_admin_username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='后台管理员表';

CREATE TABLE IF NOT EXISTS `site_settings` (
  `id` tinyint unsigned NOT NULL DEFAULT 1,
  `hostname` varchar(80) NOT NULL DEFAULT '授权管理系统',
  `site_subtitle` varchar(120) NOT NULL DEFAULT '授权管理平台',
  `siteurl` varchar(255) NOT NULL DEFAULT '',
  `logo_url` varchar(500) NOT NULL DEFAULT '',
  `announcement` text NOT NULL,
  `contact` varchar(255) NOT NULL DEFAULT '',
  `footer_text` varchar(255) NOT NULL DEFAULT '',
  `custom_json` json DEFAULT NULL COMMENT '站长扩展自定义 JSON',
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='站点展示与品牌配置';

INSERT INTO `site_settings` (`id`, `hostname`, `site_subtitle`, `announcement`)
VALUES (1, '授权管理系统', '授权管理平台', '')
ON DUPLICATE KEY UPDATE `id` = `id`;

CREATE TABLE IF NOT EXISTS `log` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `operation` varchar(255) NOT NULL,
  `msg` varchar(255) NOT NULL,
  `operationer` varchar(255) NOT NULL DEFAULT 'SYSTEM',
  `ip` varchar(45) NOT NULL DEFAULT '',
  `addtime` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_log_addtime` (`addtime`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='后台操作日志表';

CREATE TABLE IF NOT EXISTS `auth_apps` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `app_code` varchar(32) NOT NULL COMMENT '应用编号',
  `api_token` varchar(64) NOT NULL DEFAULT '' COMMENT '客户端请求Token',
  `name` varchar(80) NOT NULL COMMENT '应用名称',
  `status` tinyint unsigned NOT NULL DEFAULT 1 COMMENT '1启用 0停用',
  `max_devices` int unsigned NOT NULL DEFAULT 50 COMMENT '默认设备上限',
  `heartbeat_interval` int unsigned NOT NULL DEFAULT 86400 COMMENT '会话Token过期秒数',
  `heartbeat_enabled` tinyint unsigned NOT NULL DEFAULT 1 COMMENT '1启用心跳 0关闭心跳',
  `verification_enabled` tinyint unsigned NOT NULL DEFAULT 1 COMMENT '1验证卡密 0任意卡密',
  `device_binding_enabled` tinyint unsigned NOT NULL DEFAULT 1 COMMENT '1绑定设备 0不绑定设备',
  `shared_cards_enabled` tinyint unsigned NOT NULL DEFAULT 0 COMMENT '1允许多人登录 0单人登录限制',
  `login_ip_binding_enabled` tinyint unsigned NOT NULL DEFAULT 0 COMMENT '1校验首次登录IP 0不校验',
  `web_card_query_enabled` tinyint unsigned NOT NULL DEFAULT 0 COMMENT '1允许网页查询卡密 0关闭',
  `unbind_interval_seconds` int unsigned NOT NULL DEFAULT 0 COMMENT '解绑冷却秒数',
  `unbind_deduct_seconds` int unsigned NOT NULL DEFAULT 0 COMMENT '解绑扣除时长秒数',
  `unbind_deduct_uses` int unsigned NOT NULL DEFAULT 0 COMMENT '解绑扣除次数',
  `api_success_code` int unsigned NOT NULL DEFAULT 0 COMMENT '客户端接口成功状态码',
  `api_config_json` longtext NOT NULL COMMENT '接口开关与调用ID配置',
  `latest_version` varchar(40) NOT NULL DEFAULT '' COMMENT '最新版本',
  `client_auth_mode` varchar(32) NOT NULL DEFAULT 'local_key_v1' COMMENT '客户端鉴权模式',
  `client_crypto_alg` varchar(40) NOT NULL DEFAULT 'rsa_oaep_aes_256_gcm' COMMENT '客户端加密算法',
  `client_public_key` text NOT NULL COMMENT '请求加密公钥',
  `client_private_key_cipher` text NOT NULL COMMENT '使用SYS_KEY加密后的客户端请求解密私钥',
  `remark` varchar(255) NOT NULL DEFAULT '' COMMENT '备注',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_auth_apps_code` (`app_code`),
  KEY `idx_auth_apps_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='网络验证应用表';

CREATE TABLE IF NOT EXISTS `auth_app_secrets` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `app_id` bigint unsigned NOT NULL,
  `secret_cipher` text NOT NULL COMMENT '使用SYS_KEY加密后的应用密钥',
  `secret_fingerprint` char(64) NOT NULL COMMENT '应用密钥SHA256指纹',
  `status` tinyint unsigned NOT NULL DEFAULT 1 COMMENT '1启用 0停用',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_auth_app_secrets_app` (`app_id`, `status`),
  KEY `idx_auth_app_secrets_fingerprint` (`secret_fingerprint`),
  CONSTRAINT `fk_auth_app_secrets_app` FOREIGN KEY (`app_id`) REFERENCES `auth_apps` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='网络验证应用密钥表';

CREATE TABLE IF NOT EXISTS `auth_accounts` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `app_id` bigint unsigned NOT NULL,
  `username` varchar(64) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `status` tinyint unsigned NOT NULL DEFAULT 1 COMMENT '1启用 0停用',
  `expires_at` datetime NOT NULL,
  `max_devices` int unsigned NOT NULL DEFAULT 50,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_auth_accounts_app_username` (`app_id`, `username`),
  KEY `idx_auth_accounts_expire` (`expires_at`),
  CONSTRAINT `fk_auth_accounts_app` FOREIGN KEY (`app_id`) REFERENCES `auth_apps` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='网络验证账号表';

CREATE TABLE IF NOT EXISTS `auth_cards` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `app_id` bigint unsigned NOT NULL,
  `card_hash` char(64) NOT NULL COMMENT '卡密哈希',
  `card_cipher` text NOT NULL COMMENT '使用SYS_KEY加密保存的完整卡密',
  `card_fingerprint` varchar(32) NOT NULL DEFAULT '' COMMENT '卡密脱敏展示',
  `card_type` varchar(16) NOT NULL DEFAULT 'time' COMMENT 'time/permanent/count',
  `duration_seconds` int unsigned NOT NULL COMMENT '授权时长秒',
  `total_uses` int unsigned NOT NULL DEFAULT 0 COMMENT '次数卡总次数',
  `remaining_uses` int unsigned NOT NULL DEFAULT 0 COMMENT '次数卡剩余次数',
  `max_devices` int unsigned NOT NULL DEFAULT 50,
  `card_structure` varchar(16) NOT NULL DEFAULT 'hex' COMMENT '卡密生成结构',
  `prefix` varchar(12) NOT NULL DEFAULT '' COMMENT '卡密前缀',
  `unbind_limit` int unsigned NOT NULL DEFAULT 0 COMMENT '允许解绑次数，0为不限',
  `unbind_count` int unsigned NOT NULL DEFAULT 0 COMMENT '已解绑次数',
  `last_unbound_at` datetime DEFAULT NULL COMMENT '最近解绑时间',
  `status` tinyint unsigned NOT NULL DEFAULT 0 COMMENT '0未用 1已用 2作废',
  `used_account_id` bigint unsigned DEFAULT NULL,
  `used_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_auth_cards_app_hash` (`app_id`, `card_hash`),
  KEY `idx_auth_cards_status` (`app_id`, `status`),
  KEY `idx_auth_cards_app_used` (`app_id`, `used_at`),
  CONSTRAINT `fk_auth_cards_app` FOREIGN KEY (`app_id`) REFERENCES `auth_apps` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_auth_cards_account` FOREIGN KEY (`used_account_id`) REFERENCES `auth_accounts` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='网络验证卡密表';

CREATE TABLE IF NOT EXISTS `auth_card_search_tokens` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `app_id` bigint unsigned NOT NULL,
  `card_id` bigint unsigned NOT NULL,
  `token_hash` char(64) NOT NULL COMMENT '卡密模糊搜索片段HMAC',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_auth_card_search_token` (`app_id`, `token_hash`, `card_id`),
  KEY `idx_auth_card_search_card` (`card_id`),
  CONSTRAINT `fk_auth_card_search_app` FOREIGN KEY (`app_id`) REFERENCES `auth_apps` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_auth_card_search_card` FOREIGN KEY (`card_id`) REFERENCES `auth_cards` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='卡密模糊搜索安全索引表';

CREATE TABLE IF NOT EXISTS `auth_devices` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `app_id` bigint unsigned NOT NULL,
  `account_id` bigint unsigned DEFAULT NULL,
  `card_id` bigint unsigned DEFAULT NULL,
  `card_hash` char(64) NOT NULL DEFAULT '',
  `device_hash` char(64) NOT NULL,
  `device_name` varchar(80) NOT NULL DEFAULT '',
  `install_id` varchar(80) NOT NULL DEFAULT '',
  `device_public_key` mediumtext NOT NULL COMMENT '设备验签公钥',
  `device_key_alg` varchar(32) NOT NULL DEFAULT 'local_key_v1' COMMENT '设备证明模式',
  `machine_profile_hash` char(64) NOT NULL DEFAULT '',
  `bind_ip` varchar(45) NOT NULL DEFAULT '' COMMENT '首次绑定IP',
  `bind_region` varchar(120) NOT NULL DEFAULT '' COMMENT '首次绑定IP地区范围',
  `risk_level` tinyint unsigned NOT NULL DEFAULT 0,
  `status` tinyint unsigned NOT NULL DEFAULT 1 COMMENT '1启用 0停用',
  `first_seen_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `last_seen_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_auth_devices_install` (`app_id`, `install_id`),
  UNIQUE KEY `uk_auth_devices_account_device` (`app_id`, `account_id`, `device_hash`),
  KEY `idx_auth_devices_account` (`account_id`, `status`),
  KEY `idx_auth_devices_card` (`app_id`, `card_id`, `status`),
  KEY `idx_auth_devices_card_device` (`app_id`, `card_hash`, `device_hash`),
  KEY `idx_auth_devices_app_status` (`app_id`, `status`),
  CONSTRAINT `fk_auth_devices_app` FOREIGN KEY (`app_id`) REFERENCES `auth_apps` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_auth_devices_account` FOREIGN KEY (`account_id`) REFERENCES `auth_accounts` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_auth_devices_card` FOREIGN KEY (`card_id`) REFERENCES `auth_cards` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='网络验证设备表';

CREATE TABLE IF NOT EXISTS `auth_sessions` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `app_id` bigint unsigned NOT NULL,
  `account_id` bigint unsigned DEFAULT NULL,
  `device_id` bigint unsigned DEFAULT NULL,
  `card_id` bigint unsigned DEFAULT NULL,
  `card_hash` char(64) NOT NULL DEFAULT '',
  `card_fingerprint` varchar(32) NOT NULL DEFAULT '' COMMENT '登录卡密脱敏展示',
  `token_hash` char(64) NOT NULL,
  `request_counter` bigint unsigned NOT NULL DEFAULT 0,
  `proof_mode` varchar(32) NOT NULL DEFAULT 'local_key_v1' COMMENT 'session证明模式',
  `ticket_hash` char(64) DEFAULT NULL COMMENT '临时票据哈希',
  `ticket_expires_at` datetime DEFAULT NULL COMMENT '临时票据过期时间',
  `status` tinyint unsigned NOT NULL DEFAULT 1 COMMENT '1启用 0撤销',
  `ip` varchar(45) NOT NULL DEFAULT '',
  `expires_at` datetime NOT NULL,
  `last_heartbeat_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_auth_sessions_token` (`token_hash`),
  KEY `idx_auth_sessions_account` (`account_id`, `status`),
  KEY `idx_auth_sessions_card` (`app_id`, `card_id`, `status`, `expires_at`),
  KEY `idx_auth_sessions_app_status_expire` (`app_id`, `status`, `expires_at`),
  KEY `idx_auth_sessions_app_ip` (`app_id`, `ip`),
  KEY `idx_auth_sessions_device_card` (`app_id`, `device_id`, `status`, `card_id`, `card_hash`, `id`),
  KEY `idx_auth_sessions_expire` (`expires_at`),
  CONSTRAINT `fk_auth_sessions_app` FOREIGN KEY (`app_id`) REFERENCES `auth_apps` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_auth_sessions_account` FOREIGN KEY (`account_id`) REFERENCES `auth_accounts` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_auth_sessions_device` FOREIGN KEY (`device_id`) REFERENCES `auth_devices` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_auth_sessions_card` FOREIGN KEY (`card_id`) REFERENCES `auth_cards` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='网络验证会话表';

CREATE TABLE IF NOT EXISTS `auth_login_challenges` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `app_id` bigint unsigned NOT NULL,
  `install_id` varchar(80) NOT NULL,
  `device_name` varchar(80) NOT NULL DEFAULT '',
  `device_public_key` mediumtext NULL COMMENT '设备验签公钥',
  `device_key_mode` varchar(32) NOT NULL DEFAULT 'local_key_v1' COMMENT '设备证明模式',
  `challenge_id` varchar(128) NOT NULL,
  `server_nonce` varchar(128) NOT NULL,
  `expires_at` datetime NOT NULL,
  `used_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_auth_login_challenges_id` (`challenge_id`),
  KEY `idx_auth_login_challenges_expire` (`expires_at`),
  CONSTRAINT `fk_auth_login_challenges_app` FOREIGN KEY (`app_id`) REFERENCES `auth_apps` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='客户端登录挑战表';

CREATE TABLE IF NOT EXISTS `auth_nonces` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `app_id` bigint unsigned NOT NULL,
  `nonce_hash` char(64) NOT NULL,
  `expires_at` datetime NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_auth_nonces_app_nonce` (`app_id`, `nonce_hash`),
  KEY `idx_auth_nonces_expire` (`expires_at`),
  CONSTRAINT `fk_auth_nonces_app` FOREIGN KEY (`app_id`) REFERENCES `auth_apps` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='请求nonce防重放表';

CREATE TABLE IF NOT EXISTS `auth_remote_configs` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `app_id` bigint unsigned NOT NULL,
  `notice` text NOT NULL COMMENT '应用公告',
  `config_json` longtext NOT NULL,
  `variables_json` longtext NOT NULL,
  `version` varchar(40) NOT NULL DEFAULT '',
  `force_update` tinyint unsigned NOT NULL DEFAULT 0,
  `download_url` varchar(255) NOT NULL DEFAULT '',
  `status` tinyint unsigned NOT NULL DEFAULT 1,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_auth_remote_configs_app` (`app_id`),
  CONSTRAINT `fk_auth_remote_configs_app` FOREIGN KEY (`app_id`) REFERENCES `auth_apps` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='网络验证远程配置表';

CREATE TABLE IF NOT EXISTS `auth_remote_variables` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(80) NOT NULL COMMENT '变量名',
  `value` text NOT NULL COMMENT '变量值',
  `scope` varchar(16) NOT NULL DEFAULT 'public' COMMENT 'public/private',
  `status` tinyint unsigned NOT NULL DEFAULT 1 COMMENT '1启用 0禁用',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_auth_remote_variables_name` (`name`),
  KEY `idx_auth_remote_variables_scope_status` (`scope`, `status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='远程变量表';

CREATE TABLE IF NOT EXISTS `auth_remote_variable_apps` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `variable_id` bigint unsigned NOT NULL,
  `app_id` bigint unsigned NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_auth_remote_variable_apps_variable_app` (`variable_id`, `app_id`),
  KEY `idx_auth_remote_variable_apps_app` (`app_id`),
  CONSTRAINT `fk_auth_remote_variable_apps_variable` FOREIGN KEY (`variable_id`) REFERENCES `auth_remote_variables` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_auth_remote_variable_apps_app` FOREIGN KEY (`app_id`) REFERENCES `auth_apps` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='私有远程变量应用授权表';

CREATE TABLE IF NOT EXISTS `auth_remote_api_tokens` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(80) NOT NULL COMMENT 'Token名称',
  `access_key` varchar(64) NOT NULL COMMENT '公开访问Key',
  `secret_cipher` text NOT NULL COMMENT 'SYS_KEY加密后的HMAC secret',
  `status` tinyint unsigned NOT NULL DEFAULT 1 COMMENT '1启用 0禁用',
  `expires_at` datetime DEFAULT NULL COMMENT '过期时间',
  `ip_allowlist_json` text NULL COMMENT 'IP白名单JSON数组',
  `last_used_at` datetime DEFAULT NULL,
  `last_ip` varchar(45) NOT NULL DEFAULT '',
  `created_by` varchar(64) NOT NULL DEFAULT '',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_auth_remote_api_tokens_access_key` (`access_key`),
  KEY `idx_auth_remote_api_tokens_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='远程管理API Token表';

CREATE TABLE IF NOT EXISTS `auth_remote_api_nonces` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `token_id` bigint unsigned NOT NULL,
  `nonce_hash` char(64) NOT NULL,
  `expires_at` datetime NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_auth_remote_api_nonces_token_nonce` (`token_id`, `nonce_hash`),
  KEY `idx_auth_remote_api_nonces_expire` (`expires_at`),
  CONSTRAINT `fk_auth_remote_api_nonces_token` FOREIGN KEY (`token_id`) REFERENCES `auth_remote_api_tokens` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='远程管理API防重放nonce表';

CREATE TABLE IF NOT EXISTS `auth_remote_api_logs` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `token_id` bigint unsigned DEFAULT NULL,
  `access_key` varchar(64) NOT NULL DEFAULT '',
  `route` varchar(96) NOT NULL,
  `target_app_id` bigint unsigned DEFAULT NULL,
  `request_hash` char(64) NOT NULL DEFAULT '',
  `status` varchar(16) NOT NULL COMMENT 'success/failed',
  `error_code` varchar(64) NOT NULL DEFAULT '',
  `message` varchar(255) NOT NULL DEFAULT '',
  `ip` varchar(45) NOT NULL DEFAULT '',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_auth_remote_api_logs_token_time` (`token_id`, `created_at`),
  KEY `idx_auth_remote_api_logs_route_time` (`route`, `created_at`),
  KEY `idx_auth_remote_api_logs_app_time` (`target_app_id`, `created_at`),
  CONSTRAINT `fk_auth_remote_api_logs_token` FOREIGN KEY (`token_id`) REFERENCES `auth_remote_api_tokens` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_auth_remote_api_logs_app` FOREIGN KEY (`target_app_id`) REFERENCES `auth_apps` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='远程管理API调用日志表';

CREATE TABLE IF NOT EXISTS `auth_cloud_storage_configs` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `provider` varchar(20) NOT NULL COMMENT 'local/aliyun_oss/tencent_cos',
  `status` tinyint unsigned NOT NULL DEFAULT 1 COMMENT '1启用 0禁用',
  `is_default` tinyint unsigned NOT NULL DEFAULT 0 COMMENT '1当前默认存储',
  `bucket` varchar(128) NOT NULL DEFAULT '',
  `region` varchar(80) NOT NULL DEFAULT '',
  `endpoint` varchar(255) NOT NULL DEFAULT '',
  `access_key` varchar(128) NOT NULL DEFAULT '',
  `secret_cipher` text NULL COMMENT 'SYS_KEY加密后的云厂商Secret',
  `path_prefix` varchar(180) NOT NULL DEFAULT '',
  `custom_domain` varchar(255) NOT NULL DEFAULT '',
  `max_file_size` bigint unsigned NOT NULL DEFAULT 104857600,
  `allowed_extensions` varchar(500) NOT NULL DEFAULT '',
  `signed_url_ttl_seconds` int unsigned NOT NULL DEFAULT 300,
  `last_test_status` varchar(16) NOT NULL DEFAULT '',
  `last_test_message` varchar(255) NOT NULL DEFAULT '',
  `last_test_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_auth_cloud_storage_configs_provider` (`provider`),
  KEY `idx_auth_cloud_storage_configs_default` (`is_default`),
  KEY `idx_auth_cloud_storage_configs_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='云存储配置表';

CREATE TABLE IF NOT EXISTS `auth_cloud_files` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `file_key` varchar(64) NOT NULL COMMENT '对外文件标识',
  `provider` varchar(20) NOT NULL COMMENT 'local/aliyun_oss/tencent_cos',
  `config_id` bigint unsigned DEFAULT NULL,
  `original_name` varchar(255) NOT NULL,
  `mime_type` varchar(120) NOT NULL DEFAULT '',
  `extension` varchar(24) NOT NULL DEFAULT '',
  `size_bytes` bigint unsigned NOT NULL DEFAULT 0,
  `sha256` char(64) NOT NULL DEFAULT '',
  `object_key` varchar(500) NOT NULL,
  `local_path` varchar(500) NOT NULL DEFAULT '',
  `status` varchar(16) NOT NULL DEFAULT 'active',
  `remark` varchar(255) NOT NULL DEFAULT '',
  `download_count` bigint unsigned NOT NULL DEFAULT 0,
  `last_download_ip` varchar(45) NOT NULL DEFAULT '',
  `last_download_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_auth_cloud_files_key` (`file_key`),
  KEY `idx_auth_cloud_files_provider_status` (`provider`, `status`),
  KEY `idx_auth_cloud_files_created` (`created_at`),
  KEY `idx_auth_cloud_files_config` (`config_id`),
  CONSTRAINT `fk_auth_cloud_files_config` FOREIGN KEY (`config_id`) REFERENCES `auth_cloud_storage_configs` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='云存储文件表';

CREATE TABLE IF NOT EXISTS `auth_cloud_download_token` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `token_hash` char(64) NOT NULL DEFAULT '',
  `token_cipher` text NULL COMMENT 'SYS_KEY加密后的下载Token',
  `status` tinyint unsigned NOT NULL DEFAULT 0 COMMENT '1启用 0禁用',
  `last_used_ip` varchar(45) NOT NULL DEFAULT '',
  `last_used_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='云存储全局下载Token表';

CREATE TABLE IF NOT EXISTS `auth_cloud_upload_tickets` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `ticket_hash` char(64) NOT NULL,
  `admin_session_id` bigint unsigned DEFAULT NULL,
  `provider` varchar(20) NOT NULL,
  `expected_sha256` char(64) NOT NULL DEFAULT '',
  `expected_size` bigint unsigned NOT NULL DEFAULT 0,
  `original_name` varchar(255) NOT NULL DEFAULT '',
  `mime_type` varchar(120) NOT NULL DEFAULT '',
  `remark` varchar(255) NOT NULL DEFAULT '',
  `status` varchar(16) NOT NULL DEFAULT 'pending',
  `expires_at` datetime NOT NULL,
  `used_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_auth_cloud_upload_tickets_hash` (`ticket_hash`),
  KEY `idx_auth_cloud_upload_tickets_expire` (`expires_at`),
  KEY `idx_auth_cloud_upload_tickets_session` (`admin_session_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='云存储上传短期票据表';

CREATE TABLE IF NOT EXISTS `auth_audit_logs` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `app_id` bigint unsigned DEFAULT NULL,
  `account_id` bigint unsigned DEFAULT NULL,
  `action` varchar(40) NOT NULL,
  `message` varchar(255) NOT NULL,
  `ip` varchar(45) NOT NULL DEFAULT '',
  `region` varchar(80) NOT NULL DEFAULT '',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_auth_audit_app_time` (`app_id`, `created_at`),
  KEY `idx_auth_audit_app_action_time` (`app_id`, `action`, `created_at`),
  KEY `idx_auth_audit_app_id` (`app_id`, `id`),
  KEY `idx_auth_audit_account_time` (`account_id`, `created_at`),
  CONSTRAINT `fk_auth_audit_app` FOREIGN KEY (`app_id`) REFERENCES `auth_apps` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_auth_audit_account` FOREIGN KEY (`account_id`) REFERENCES `auth_accounts` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='网络验证审计日志表';

CREATE TABLE IF NOT EXISTS `auth_security_reports` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `app_id` bigint unsigned NOT NULL,
  `session_id` bigint unsigned DEFAULT NULL,
  `device_id` bigint unsigned DEFAULT NULL,
  `card_id` bigint unsigned DEFAULT NULL,
  `card_hash` char(64) NOT NULL DEFAULT '',
  `card_fingerprint` varchar(32) NOT NULL DEFAULT '',
  `install_id` varchar(80) NOT NULL DEFAULT '',
  `event_id` varchar(96) NOT NULL,
  `event_type` varchar(40) NOT NULL,
  `risk_level` varchar(16) NOT NULL,
  `confidence` tinyint unsigned NOT NULL DEFAULT 0,
  `requested_action` varchar(32) NOT NULL DEFAULT 'record_only',
  `action` varchar(32) NOT NULL DEFAULT 'record_only',
  `action_source` varchar(32) NOT NULL DEFAULT 'client',
  `risk_score` smallint unsigned NOT NULL DEFAULT 0,
  `action_reason` varchar(255) NOT NULL DEFAULT '',
  `title` varchar(120) NOT NULL DEFAULT '',
  `message` varchar(500) NOT NULL DEFAULT '',
  `evidence_json` mediumtext NOT NULL,
  `attestation_json` mediumtext NOT NULL,
  `sdk_version` varchar(40) NOT NULL DEFAULT '',
  `detector_version` varchar(40) NOT NULL DEFAULT '',
  `platform` varchar(40) NOT NULL DEFAULT '',
  `ip` varchar(45) NOT NULL DEFAULT '',
  `occurred_at` datetime NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_auth_security_reports_event` (`app_id`, `session_id`, `event_id`),
  KEY `idx_auth_security_reports_app_time` (`app_id`, `created_at`),
  KEY `idx_auth_security_reports_app_risk` (`app_id`, `risk_level`, `created_at`),
  KEY `idx_auth_security_reports_card` (`app_id`, `card_id`, `created_at`),
  KEY `idx_auth_security_reports_device` (`app_id`, `device_id`, `created_at`),
  CONSTRAINT `fk_auth_security_reports_app` FOREIGN KEY (`app_id`) REFERENCES `auth_apps` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_auth_security_reports_session` FOREIGN KEY (`session_id`) REFERENCES `auth_sessions` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_auth_security_reports_device` FOREIGN KEY (`device_id`) REFERENCES `auth_devices` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_auth_security_reports_card` FOREIGN KEY (`card_id`) REFERENCES `auth_cards` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='客户端安全上报事实表';

CREATE TABLE IF NOT EXISTS `auth_messages` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `app_id` bigint unsigned NOT NULL,
  `report_id` bigint unsigned DEFAULT NULL,
  `session_id` bigint unsigned DEFAULT NULL,
  `device_id` bigint unsigned DEFAULT NULL,
  `card_id` bigint unsigned DEFAULT NULL,
  `message_type` varchar(32) NOT NULL DEFAULT 'security_report',
  `severity` varchar(16) NOT NULL DEFAULT 'low',
  `status` varchar(16) NOT NULL DEFAULT 'unread',
  `title` varchar(120) NOT NULL DEFAULT '',
  `summary` varchar(500) NOT NULL DEFAULT '',
  `action` varchar(32) NOT NULL DEFAULT 'record_only',
  `action_source` varchar(32) NOT NULL DEFAULT 'client',
  `risk_score` smallint unsigned NOT NULL DEFAULT 0,
  `handled_by` varchar(64) NOT NULL DEFAULT '',
  `read_at` datetime DEFAULT NULL,
  `handled_at` datetime DEFAULT NULL,
  `archived_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_auth_messages_app_status` (`app_id`, `status`, `created_at`),
  KEY `idx_auth_messages_app_action` (`app_id`, `action`, `created_at`),
  KEY `idx_auth_messages_report` (`report_id`),
  CONSTRAINT `fk_auth_messages_app` FOREIGN KEY (`app_id`) REFERENCES `auth_apps` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_auth_messages_report` FOREIGN KEY (`report_id`) REFERENCES `auth_security_reports` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_auth_messages_session` FOREIGN KEY (`session_id`) REFERENCES `auth_sessions` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_auth_messages_device` FOREIGN KEY (`device_id`) REFERENCES `auth_devices` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_auth_messages_card` FOREIGN KEY (`card_id`) REFERENCES `auth_cards` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='后台消息中心表';

CREATE TABLE IF NOT EXISTS `auth_message_actions` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `app_id` bigint unsigned NOT NULL,
  `message_id` bigint unsigned NOT NULL,
  `action` varchar(32) NOT NULL,
  `actor_type` varchar(16) NOT NULL DEFAULT 'system',
  `actor_name` varchar(64) NOT NULL DEFAULT '',
  `result` varchar(32) NOT NULL DEFAULT 'success',
  `remark` varchar(255) NOT NULL DEFAULT '',
  `ip` varchar(45) NOT NULL DEFAULT '',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_auth_message_actions_app_time` (`app_id`, `created_at`),
  KEY `idx_auth_message_actions_message` (`message_id`),
  CONSTRAINT `fk_auth_message_actions_app` FOREIGN KEY (`app_id`) REFERENCES `auth_apps` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_auth_message_actions_message` FOREIGN KEY (`message_id`) REFERENCES `auth_messages` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='消息处置动作流水表';

CREATE TABLE IF NOT EXISTS `auth_security_policies` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `app_id` bigint unsigned NOT NULL,
  `enabled` tinyint unsigned NOT NULL DEFAULT 1,
  `mode` varchar(24) NOT NULL DEFAULT 'honor_client',
  `min_confidence_for_client_action` tinyint unsigned NOT NULL DEFAULT 0,
  `max_client_action` varchar(32) NOT NULL DEFAULT 'disable_card',
  `kick_score` smallint unsigned NOT NULL DEFAULT 80,
  `disable_device_score` smallint unsigned NOT NULL DEFAULT 95,
  `disable_card_score` smallint unsigned NOT NULL DEFAULT 120,
  `allowed_client_actions` varchar(128) NOT NULL DEFAULT 'record_only,kick_session,disable_device,disable_card',
  `client_disable_device_min_score` smallint unsigned NOT NULL DEFAULT 80,
  `client_disable_card_min_score` smallint unsigned NOT NULL DEFAULT 95,
  `report_rate_limit_per_minute` int unsigned NOT NULL DEFAULT 20,
  `report_retention_days` int unsigned NOT NULL DEFAULT 90,
  `message_retention_days` int unsigned NOT NULL DEFAULT 180,
  `server_critical_action` varchar(32) NOT NULL DEFAULT 'disable_card',
  `server_high_action` varchar(32) NOT NULL DEFAULT 'disable_device',
  `server_medium_action` varchar(32) NOT NULL DEFAULT 'manual_review',
  `server_low_action` varchar(32) NOT NULL DEFAULT 'record_only',
  `trusted_event_types_json` mediumtext NOT NULL,
  `updated_by` varchar(64) NOT NULL DEFAULT '',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_auth_security_policies_app` (`app_id`),
  CONSTRAINT `fk_auth_security_policies_app` FOREIGN KEY (`app_id`) REFERENCES `auth_apps` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='客户端安全上报处置策略表';

CREATE TABLE IF NOT EXISTS `auth_admin_sessions` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `token_hash` char(64) NOT NULL,
  `key_cipher` text NOT NULL COMMENT '使用SYS_KEY加密后的后台会话密钥',
  `ip` varchar(45) NOT NULL DEFAULT '',
  `admin_username` varchar(64) NOT NULL DEFAULT '' COMMENT '当前后台管理员账号',
  `status` tinyint unsigned NOT NULL DEFAULT 1 COMMENT '1启用 0撤销',
  `expires_at` datetime NOT NULL,
  `last_seen_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_auth_admin_sessions_token` (`token_hash`),
  KEY `idx_auth_admin_sessions_admin_status` (`admin_username`, `status`),
  KEY `idx_auth_admin_sessions_expire` (`expires_at`, `status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='后台管理短期会话表';

CREATE TABLE IF NOT EXISTS `auth_admin_nonces` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `session_id` bigint unsigned NOT NULL,
  `nonce_hash` char(64) NOT NULL,
  `expires_at` datetime NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_auth_admin_nonces_session_nonce` (`session_id`, `nonce_hash`),
  KEY `idx_auth_admin_nonces_expire` (`expires_at`),
  CONSTRAINT `fk_auth_admin_nonces_session` FOREIGN KEY (`session_id`) REFERENCES `auth_admin_sessions` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='后台管理请求nonce防重放表';

SET FOREIGN_KEY_CHECKS = 1;
