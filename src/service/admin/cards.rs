use std::collections::HashSet;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Local;
use rand::{Rng, rngs::OsRng};
use serde_json::{Value, json};

use crate::{
    card_search::{
        card_token_hashes, keyword_token_hashes, normalize as normalize_card_search_text,
    },
    crypto,
    error::AppError,
    repository::{AppDetailRow, CardQuery, NewCard},
};

use super::{
    MAX_CARD_DURATION_SECONDS, ids, normalize_card_type, payload_int_range, payload_string_or,
};

pub(super) const MAX_CARD_EXPORT_ROWS: usize = 5_000;
pub(super) const MAX_CARD_IMPORT_COUNT: usize = 500;

const MAX_CARD_IMPORT_BYTES: usize = 70_000;
const DIGIT_CARD_ALPHABET: &[u8] = b"0123456789";
const UPPER_CARD_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const ALNUM_CARD_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
const HEX_CARD_ALPHABET: &[u8] = b"0123456789ABCDEF";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CardRule {
    pub(super) card_type: String,
    pub(super) duration_seconds: i64,
    pub(super) total_uses: i64,
    pub(super) max_devices: i64,
    pub(super) unbind_limit: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CardImport {
    pub(super) cards: Vec<String>,
    pub(super) input_count: usize,
    pub(super) duplicate_count: usize,
}

pub(super) fn card_rule(payload: &Value, app: &AppDetailRow) -> Result<CardRule, AppError> {
    let card_type = normalize_card_type(&payload_string_or(payload, "card_type", "time"))?;
    Ok(CardRule {
        duration_seconds: if card_type == "time" {
            payload_int_range(
                payload.get("duration_seconds"),
                60,
                MAX_CARD_DURATION_SECONDS,
                86_400,
            )?
        } else {
            0
        },
        total_uses: if card_type == "count" {
            payload_int_range(payload.get("total_uses"), 1, 1_000_000, 1)?
        } else {
            0
        },
        max_devices: if card_type == "count" {
            0
        } else {
            payload_int_range(payload.get("max_devices"), 1, 50, app.max_devices)?
        },
        unbind_limit: if card_type == "count" {
            0
        } else {
            payload_int_range(payload.get("unbind_limit"), 0, 1_000_000, 0)?
        },
        card_type,
    })
}

pub(super) fn create_card_keys(
    prefix: &str,
    structure: &str,
    card_length: i64,
    count: usize,
) -> Result<Vec<String>, AppError> {
    let mut cards = Vec::with_capacity(count);
    for _ in 0..count {
        cards.push(create_card_key(prefix, structure, card_length as usize)?);
    }
    Ok(cards)
}

pub(super) fn build_new_cards(
    app: &AppDetailRow,
    card_keys: &[String],
    rule: &CardRule,
    card_structure: &str,
    prefix: &str,
    system_key: &str,
) -> Result<Vec<NewCard>, AppError> {
    card_keys
        .iter()
        .map(|card_key| new_card(app, card_key, rule, card_structure, prefix, system_key))
        .collect()
}

pub(super) fn card_hash(app: &AppDetailRow, card_key: &str) -> String {
    crypto::sha256_hex(&format!("{}:{}", app.app_code, card_key))
}

pub(super) fn card_create_response(card_keys: &[String], rule: &CardRule) -> Value {
    let mut response = card_rule_response(rule);
    response["cards"] = json!(card_keys);
    response
}

pub(super) fn card_import_response(card_import: &CardImport, rule: &CardRule) -> Value {
    let mut response = card_rule_response(rule);
    response["cards"] = json!(card_import.cards);
    response["custom_import"] = json!(true);
    response["custom_input_count"] = json!(card_import.input_count);
    response["custom_duplicate_count"] = json!(card_import.duplicate_count);
    response
}

pub(super) fn parse_card_import(value: Option<&Value>) -> Result<CardImport, AppError> {
    let text = card_import_text(value)?;
    if text.trim().is_empty() {
        return Ok(CardImport {
            cards: Vec::new(),
            input_count: 0,
            duplicate_count: 0,
        });
    }
    if text.len() > MAX_CARD_IMPORT_BYTES {
        return Err(AppError::InvalidInput("自定义导入内容过长"));
    }
    unique_import_cards(card_import_tokens(&text))
}

pub(super) fn card_prefix(value: &str) -> Result<String, AppError> {
    let prefix = value.trim();
    if prefix.is_empty() {
        return Ok(String::new());
    }
    if prefix.len() <= 12
        && prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Ok(prefix.to_ascii_uppercase());
    }
    Err(AppError::InvalidInput("卡密前缀格式错误"))
}

pub(super) fn card_structure(value: &str) -> Result<String, AppError> {
    let structure = value.trim().to_ascii_lowercase();
    match structure.as_str() {
        "hex" | "upper" | "digit" | "alnum" => Ok(structure),
        _ => Err(AppError::InvalidInput("卡密结构不支持")),
    }
}

pub(super) fn export_card_ids(payload: &Value) -> Result<Vec<u64>, AppError> {
    match payload.get("card_ids") {
        Some(Value::Array(_)) => ids(payload.get("card_ids")),
        _ => Ok(Vec::new()),
    }
}

pub(super) fn selected_export_ids(card_ids: &[u64]) -> HashSet<u64> {
    card_ids.iter().copied().collect()
}

pub(super) fn export_card_query(
    app: &AppDetailRow,
    status: &str,
    duration_category: &str,
    keyword: &str,
    system_key: &str,
) -> Result<CardQuery, AppError> {
    Ok(CardQuery {
        status: status.to_string(),
        duration_category: duration_category.to_string(),
        keyword: keyword.to_string(),
        card_hash: if keyword.is_empty() {
            String::new()
        } else {
            card_hash(app, keyword)
        },
        search_token_hashes: keyword_token_hashes(keyword, system_key)?,
        limit: MAX_CARD_EXPORT_ROWS as i64 + 1,
        offset: 0,
    })
}

pub(super) fn card_matches_export_filter(
    card: &Value,
    status: &str,
    duration_category: &str,
    keyword: &str,
    selected_ids: &HashSet<u64>,
) -> Result<bool, AppError> {
    if !selected_ids.is_empty() && !selected_ids.contains(&json_u64(card, "id")) {
        return Ok(false);
    }
    if !card_matches_status_filter(card, status)?
        || !card_matches_duration_filter(card, duration_category)
    {
        return Ok(false);
    }
    Ok(keyword.is_empty() || card_matches_keyword(card, keyword))
}

pub(super) fn exportable_card_keys(cards: &[Value]) -> Result<Vec<String>, AppError> {
    let mut card_keys = Vec::new();
    for card in cards {
        if !card
            .get("card_recoverable")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            continue;
        }
        let card_key = json_text(card, "card_key");
        if card_key.is_empty() {
            continue;
        }
        if card_key.contains('\r') || card_key.contains('\n') {
            return Err(AppError::InvalidInput("卡密包含非法换行字符，无法按行导出"));
        }
        card_keys.push(card_key);
    }
    Ok(card_keys)
}

pub(super) fn card_export_response(
    app_code: &str,
    card_keys: &[String],
    view_count: usize,
) -> Value {
    let content = format!("{}\n", card_keys.join("\n"));
    json!({
        "filename": format!("cards-{}-{}.txt", export_app_code(app_code), Local::now().format("%Y%m%d-%H%M%S")),
        "mime": "text/plain;charset=utf-8",
        "content_base64": STANDARD.encode(content.as_bytes()),
        "rows": card_keys.len(),
        "skipped_unrecoverable": view_count - card_keys.len(),
    })
}

fn create_card_key(prefix: &str, structure: &str, card_length: usize) -> Result<String, AppError> {
    let body = random_card_body(structure, card_length)?;
    if prefix.is_empty() {
        return Ok(body);
    }
    Ok(format!("{prefix}-{body}"))
}

fn random_card_body(structure: &str, length: usize) -> Result<String, AppError> {
    let alphabet = card_alphabet(structure)?;
    let mut rng = OsRng;
    let body = (0..length)
        .map(|_| alphabet[rng.gen_range(0..alphabet.len())] as char)
        .collect();
    Ok(body)
}

fn card_alphabet(structure: &str) -> Result<&'static [u8], AppError> {
    match structure {
        "digit" => Ok(DIGIT_CARD_ALPHABET),
        "upper" => Ok(UPPER_CARD_ALPHABET),
        "alnum" => Ok(ALNUM_CARD_ALPHABET),
        "hex" => Ok(HEX_CARD_ALPHABET),
        _ => Err(AppError::InvalidInput("卡密结构不支持")),
    }
}

fn new_card(
    app: &AppDetailRow,
    card_key: &str,
    rule: &CardRule,
    card_structure: &str,
    prefix: &str,
    system_key: &str,
) -> Result<NewCard, AppError> {
    Ok(NewCard {
        app_id: app.id,
        card_hash: card_hash(app, card_key),
        card_cipher: crypto::encrypt_protected_text(card_key, system_key)?,
        card_fingerprint: card_key_fingerprint(card_key),
        card_type: rule.card_type.clone(),
        duration_seconds: rule.duration_seconds,
        total_uses: rule.total_uses,
        remaining_uses: rule.total_uses,
        max_devices: rule.max_devices,
        card_structure: card_structure.to_string(),
        prefix: prefix.to_string(),
        unbind_limit: rule.unbind_limit,
        status: 0,
        search_token_hashes: card_token_hashes(card_key, system_key)?,
    })
}

fn card_key_fingerprint(card_key: &str) -> String {
    if card_key.len() <= 10 {
        return card_key.to_string();
    }
    format!("{}...{}", &card_key[..6], &card_key[card_key.len() - 4..])
}

fn card_rule_response(rule: &CardRule) -> Value {
    json!({
        "card_type": rule.card_type,
        "duration_seconds": rule.duration_seconds,
        "total_uses": rule.total_uses,
        "max_devices": rule.max_devices,
        "unbind_limit": rule.unbind_limit,
    })
}

fn card_import_text(value: Option<&Value>) -> Result<String, AppError> {
    match value {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::Array(values)) => values
            .iter()
            .map(card_import_scalar_text)
            .collect::<Result<Vec<_>, _>>()
            .map(|rows| rows.join("\n")),
        Some(value) => card_import_scalar_text(value),
    }
}

fn card_import_scalar_text(value: &Value) -> Result<String, AppError> {
    match value {
        Value::String(text) => Ok(text.to_string()),
        Value::Number(number) => Ok(number.to_string()),
        Value::Bool(true) => Ok("1".to_string()),
        Value::Bool(false) => Ok(String::new()),
        _ => Err(AppError::InvalidInput("自定义导入格式错误")),
    }
}

fn card_import_tokens(text: &str) -> Vec<String> {
    text.replace('\u{feff}', "")
        .trim()
        .split(is_card_import_separator)
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn is_card_import_separator(character: char) -> bool {
    character.is_whitespace() || matches!(character, ',' | ';' | '，' | '；' | '、' | '|')
}

fn unique_import_cards(tokens: Vec<String>) -> Result<CardImport, AppError> {
    let input_count = tokens.len();
    let mut seen_cards = HashSet::new();
    let mut cards = Vec::new();
    let mut duplicate_count = 0;
    for token in tokens {
        let card_key = validate_card_key(&token)?;
        if seen_cards.insert(card_key.clone()) {
            cards.push(card_key);
        } else {
            duplicate_count += 1;
        }
    }
    if cards.len() > MAX_CARD_IMPORT_COUNT {
        return Err(AppError::InvalidInput("自定义导入最多 500 张"));
    }
    Ok(CardImport {
        cards,
        input_count,
        duplicate_count,
    })
}

fn validate_card_key(value: &str) -> Result<String, AppError> {
    let length = value.len();
    if (8..=128).contains(&length)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Ok(value.to_string());
    }
    Err(AppError::InvalidInput("卡密格式错误"))
}

fn card_matches_status_filter(card: &Value, status: &str) -> Result<bool, AppError> {
    match status {
        "" => Ok(true),
        "active" => Ok(json_i64(card, "status") == 1 && json_i64(card, "remaining_seconds") > 0),
        "expired" => Ok(json_i64(card, "status") == 1 && json_i64(card, "remaining_seconds") <= 0),
        "0" | "1" | "2" => Ok(card
            .get("status")
            .and_then(Value::as_i64)
            .is_some_and(|value| value.to_string() == status)),
        _ => Err(AppError::InvalidInput("卡密状态筛选格式错误")),
    }
}

fn card_matches_duration_filter(card: &Value, duration_category: &str) -> bool {
    duration_category.is_empty()
        || card.get("duration_category").and_then(Value::as_str) == Some(duration_category)
}

fn card_matches_keyword(card: &Value, keyword: &str) -> bool {
    let search_text = [
        json_text(card, "id"),
        json_text(card, "card_key"),
        json_text(card, "card_fingerprint"),
        json_text(card, "remaining_text"),
        json_text(card, "duration_text"),
    ]
    .join(" ")
    .to_lowercase();
    let normalized_keyword = normalize_card_search_text(keyword);
    let normalized_card_key = normalize_card_search_text(&json_text(card, "card_key"));
    search_text.contains(&keyword.to_lowercase())
        || (!normalized_keyword.is_empty() && normalized_card_key.contains(&normalized_keyword))
}

fn export_app_code(app_code: &str) -> String {
    app_code
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-') {
                character
            } else {
                '-'
            }
        })
        .collect()
}

fn json_text(value: &Value, key: &str) -> String {
    match value.get(key) {
        Some(Value::String(text)) => text.to_string(),
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::Bool(flag)) => flag.to_string(),
        _ => String::new(),
    }
}

fn json_i64(value: &Value, key: &str) -> i64 {
    value.get(key).and_then(Value::as_i64).unwrap_or(0)
}

fn json_u64(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}
