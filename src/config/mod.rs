use std::{collections::HashMap, fs, path::Path};

use crate::error::AppError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppConfig {
    pub system_key: String,
    pub admin_token_hash: String,
    pub demo_mode: bool,
    pub database: DatabaseConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub database_name: String,
}

impl AppConfig {
    pub fn from_php_file(path: impl AsRef<Path>) -> Result<Self, AppError> {
        let path = path.as_ref();
        if !path.is_file() {
            return Err(AppError::ConfigMissing(path.display().to_string()));
        }

        let content = fs::read_to_string(path)
            .map_err(|error| AppError::ConfigReadFailed(error.to_string()))?;
        Self::from_php_text(&content)
    }

    pub fn from_php_text(content: &str) -> Result<Self, AppError> {
        let defines = parse_defines(content);
        let database = parse_database_config(content);
        Ok(Self {
            system_key: required_value(&defines, "SYS_KEY")?,
            admin_token_hash: required_value(&defines, "AUTH_ADMIN_TOKEN_HASH")?,
            demo_mode: php_truthy_define(&defines, "NETWORK_AUTH_DEMO_MODE"),
            database: DatabaseConfig {
                host: required_value(&database, "host")?,
                port: database
                    .get("port")
                    .and_then(|value| value.parse::<u16>().ok())
                    .unwrap_or(3306),
                username: required_value(&database, "user")?,
                password: database.get("pwd").cloned().unwrap_or_default(),
                database_name: required_value(&database, "dbname")?,
            },
        })
    }

    pub fn validate(&self) -> Result<(), AppError> {
        require_non_empty(&self.system_key, "SYS_KEY")?;
        require_non_empty(&self.admin_token_hash, "AUTH_ADMIN_TOKEN_HASH")?;
        require_non_empty(&self.database.host, "dbconfig.host")?;
        require_non_empty(&self.database.username, "dbconfig.user")?;
        require_non_empty(&self.database.database_name, "dbconfig.dbname")?;
        Ok(())
    }
}

fn parse_defines(content: &str) -> HashMap<String, String> {
    let mut defines = HashMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("define(") {
            continue;
        }
        let Some(inner) = trimmed
            .strip_prefix("define(")
            .and_then(|value| value.strip_suffix(");"))
        else {
            continue;
        };
        let parts = split_php_arguments(inner);
        if parts.len() == 2 {
            defines.insert(parts[0].clone(), parts[1].clone());
        }
    }
    defines
}

fn parse_database_config(content: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    let Some(start) = content.find("$dbconfig") else {
        return values;
    };
    let database_section = &content[start..];
    let Some(array_start) = database_section.find('[') else {
        return values;
    };
    let Some(array_end) = database_section[array_start..].find("];") else {
        return values;
    };
    let array_body = &database_section[array_start + 1..array_start + array_end];
    for line in array_body.lines() {
        let trimmed = line.trim().trim_end_matches(',');
        let Some((key, value)) = trimmed.split_once("=>") else {
            continue;
        };
        values.insert(trim_php_literal(key), trim_php_literal(value));
    }
    values
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
    if trimmed.len() >= 2 {
        let bytes = trimmed.as_bytes();
        if (bytes[0] == b'\'' && bytes[trimmed.len() - 1] == b'\'')
            || (bytes[0] == b'"' && bytes[trimmed.len() - 1] == b'"')
        {
            return trimmed[1..trimmed.len() - 1]
                .replace("\\'", "'")
                .replace("\\\"", "\"")
                .replace("\\\\", "\\");
        }
    }
    trimmed.to_string()
}

fn required_value(values: &HashMap<String, String>, key: &'static str) -> Result<String, AppError> {
    let value = values
        .get(key)
        .cloned()
        .ok_or(AppError::ConfigValueMissing(key))?;
    require_non_empty(&value, key)?;
    Ok(value)
}

fn require_non_empty(value: &str, key: &'static str) -> Result<(), AppError> {
    if value.trim().is_empty() {
        return Err(AppError::ConfigValueMissing(key));
    }
    Ok(())
}

fn php_truthy_define(values: &HashMap<String, String>, key: &str) -> bool {
    values
        .get(key)
        .is_some_and(|value| matches!(value.trim().to_ascii_lowercase().as_str(), "true" | "1"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_installer_style_php_config() {
        let config = AppConfig::from_php_text(
            r#"<?php
defined('IN_CRONLITE') || exit();
define('SYS_KEY', 'system-key-value');
define('AUTH_ADMIN_TOKEN_HASH', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
define('NETWORK_AUTH_DEMO_MODE', true);
$dbconfig = [
    'host' => '127.0.0.1',
    'port' => 3307,
    'user' => 'network_user',
    'pwd' => 'network_password',
    'dbname' => 'network_auth',
];
"#,
        )
        .expect("config should parse");

        assert_eq!("system-key-value", config.system_key);
        assert_eq!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            config.admin_token_hash
        );
        assert!(config.demo_mode);
        assert_eq!("127.0.0.1", config.database.host);
        assert_eq!(3307, config.database.port);
        assert_eq!("network_user", config.database.username);
        assert_eq!("network_password", config.database.password);
        assert_eq!("network_auth", config.database.database_name);
    }

    #[test]
    fn rejects_missing_system_key() {
        let error = AppConfig::from_php_text(
            r#"<?php
define('AUTH_ADMIN_TOKEN_HASH', 'hash');
$dbconfig = ['host' => '127.0.0.1', 'user' => 'root', 'dbname' => 'auth'];
"#,
        )
        .expect_err("missing key should fail");

        assert!(matches!(error, AppError::ConfigValueMissing("SYS_KEY")));
    }
}
