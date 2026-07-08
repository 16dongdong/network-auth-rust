use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::Duration as StdDuration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{Duration, Local, Utc};
use hmac::{Hmac, Mac};
use reqwest::{
    Method,
    header::{AUTHORIZATION, CONTENT_TYPE, DATE, HOST},
};
use serde_json::{Value, json};
use sha1::{Digest, Sha1};

use crate::{
    crypto,
    error::AppError,
    repository::{
        CloudDownloadTokenRow, CloudFileFilters, CloudFileInput, CloudFileRow,
        CloudProviderCountRow, CloudStorageConfigInput, CloudStorageConfigRow, CloudStorageSummary,
        CloudUploadTicketInput, CloudUploadTicketRow,
    },
};

const PROVIDER_LOCAL: &str = "local";
const PROVIDER_ALIYUN: &str = "aliyun_oss";
const PROVIDER_TENCENT: &str = "tencent_cos";
const STATUS_ACTIVE: &str = "active";
const STATUS_DELETED: &str = "deleted";
const STATUS_FAILED: &str = "failed";
const TICKET_PENDING: &str = "pending";
const FLAG_ENABLED: i64 = 1;
const DEFAULT_MAX_FILE_SIZE: i64 = 104_857_600;
const DEFAULT_SIGNED_URL_TTL: i64 = 300;
const SIGNED_URL_MIN_TTL: i64 = 60;
const SIGNED_URL_MAX_TTL: i64 = 86_400;
const UPLOAD_TICKET_TTL_SECONDS: i64 = 300;
const REMOTE_REQUEST_TIMEOUT_SECONDS: u64 = 20;
const REMOTE_UPLOAD_TIMEOUT_SECONDS: u64 = 60;

type HmacSha1 = Hmac<Sha1>;

pub struct CloudConfigPayload {
    pub config: CloudStorageConfigInput,
    pub set_default: bool,
}

pub struct UploadTicketPayload {
    pub ticket: CloudUploadTicketInput,
    pub token: String,
    pub expires_at: i64,
}

pub struct CloudUploadForm {
    pub ticket: String,
    pub file_name: String,
    pub mime_type: String,
    pub content: Vec<u8>,
}

struct PreparedCloudUpload {
    original_name: String,
    mime_type: String,
    extension: String,
    size_bytes: i64,
    sha256: String,
    remark: String,
    content: Vec<u8>,
}

pub fn cloud_storage_summary_view(
    summary: CloudStorageSummary,
    system_key: &str,
) -> Result<Value, AppError> {
    Ok(json!({
        "file_total": summary.file_total,
        "size_total": summary.size_total,
        "provider_counts": provider_counts(summary.providers),
        "default_config": config_view(summary.default_config.as_ref()),
        "download_token": download_token_view(summary.download_token.as_ref(), system_key)?,
    }))
}

pub fn cloud_config_get_view(
    configs: &[CloudStorageConfigRow],
    default_config: Option<&CloudStorageConfigRow>,
) -> Value {
    json!({
        "providers": provider_options(),
        "configs": configs.iter().map(|config| config_view(Some(config))).collect::<Vec<_>>(),
        "default_config": config_view(default_config),
    })
}

pub fn cloud_file_filters(payload: &Value) -> Result<CloudFileFilters, AppError> {
    let page = int_from_value(payload.get("page"))
        .unwrap_or(1)
        .clamp(1, 1_000_000);
    let limit = int_from_value(payload.get("limit"))
        .unwrap_or(50)
        .clamp(1, 100);
    let offset = int_from_value(payload.get("offset")).unwrap_or((page - 1) * limit);
    Ok(CloudFileFilters {
        keyword: safe_text(&payload_string(payload, "keyword"), 120)?,
        provider: optional_provider(&payload_string(payload, "provider"))?,
        status: optional_file_status(&payload_string(payload, "status"))?,
        start: safe_text(&payload_string(payload, "start"), 32)?,
        end: safe_text(&payload_string(payload, "end"), 32)?,
        limit,
        offset: offset.clamp(0, 1_000_000),
    })
}

pub fn cloud_file_view(file: &CloudFileRow) -> Value {
    json!({
        "id": file.id.to_string(),
        "file_key": file.file_key,
        "provider": provider_view(&file.provider),
        "original_name": file.original_name,
        "mime_type": file.mime_type,
        "extension": file.extension,
        "size_bytes": file.size_bytes,
        "sha256": file.sha256,
        "object_key": file.object_key,
        "status": file.status,
        "remark": file.remark,
        "download_count": file.download_count,
        "last_download_ip": file.last_download_ip,
        "last_download_at": format_datetime(file.last_download_at),
        "created_at": format_datetime(file.created_at),
        "updated_at": format_datetime(file.updated_at),
        "external_download_path": download_url(&file.file_key),
    })
}

pub fn cloud_config_payload(
    payload: &Value,
    existing: Option<&CloudStorageConfigRow>,
    system_key: &str,
    persisting: bool,
) -> Result<CloudConfigPayload, AppError> {
    let provider = cloud_config_provider(payload)?;
    let set_default = enabled_flag(payload.get("set_default")) == FLAG_ENABLED;
    let secret_cipher = secret_cipher(payload, existing, system_key, provider == PROVIDER_LOCAL)?;
    let config = CloudStorageConfigInput {
        provider: provider.clone(),
        status: enabled_flag(payload.get("status")),
        bucket: safe_text(&payload_string(payload, "bucket"), 128)?,
        region: safe_text(&payload_string(payload, "region"), 80)?,
        endpoint: safe_text(&payload_string(payload, "endpoint"), 255)?,
        access_key: safe_text(&payload_string(payload, "access_key"), 128)?,
        secret_cipher,
        path_prefix: path_prefix(&payload_string(payload, "path_prefix"))?,
        custom_domain: safe_text(&payload_string(payload, "custom_domain"), 255)?,
        max_file_size: bounded_int(
            payload.get("max_file_size"),
            1,
            10_737_418_240,
            DEFAULT_MAX_FILE_SIZE,
        )?,
        allowed_extensions: allowed_extensions(&payload_string(payload, "allowed_extensions"))?,
        signed_url_ttl_seconds: bounded_int(
            payload.get("signed_url_ttl_seconds"),
            60,
            86_400,
            DEFAULT_SIGNED_URL_TTL,
        )?,
    };
    if set_default && config.status != FLAG_ENABLED {
        return Err(AppError::CloudStorageDefaultDisabled);
    }
    if !persisting || config.status == FLAG_ENABLED || set_default {
        assert_config_complete(&config)?;
    }
    Ok(CloudConfigPayload {
        config,
        set_default,
    })
}

pub fn default_local_config() -> CloudStorageConfigInput {
    CloudStorageConfigInput {
        provider: PROVIDER_LOCAL.to_string(),
        status: FLAG_ENABLED,
        bucket: String::new(),
        region: String::new(),
        endpoint: String::new(),
        access_key: String::new(),
        secret_cipher: None,
        path_prefix: String::new(),
        custom_domain: String::new(),
        max_file_size: DEFAULT_MAX_FILE_SIZE,
        allowed_extensions: String::new(),
        signed_url_ttl_seconds: DEFAULT_SIGNED_URL_TTL,
    }
}

pub fn assert_local_storage_writable(storage_root: &Path) -> Result<(), AppError> {
    fs::create_dir_all(storage_root).map_err(|_| AppError::CloudStorageDirectoryFailed)?;
    let probe_path = storage_root.join(format!(".probe-{}", crypto::token(8)));
    fs::write(&probe_path, b"ok").map_err(|_| AppError::CloudStorageLocalWriteFailed)?;
    fs::remove_file(probe_path).map_err(|_| AppError::CloudStorageLocalWriteFailed)?;
    Ok(())
}

pub fn cloud_config_provider(payload: &Value) -> Result<String, AppError> {
    provider(&payload_string(payload, "provider"))
}

pub fn cloud_config_test_view(provider: &str) -> Value {
    let message = match provider {
        PROVIDER_LOCAL => "本地存储可写",
        PROVIDER_ALIYUN => "阿里云 OSS 连接正常",
        PROVIDER_TENCENT => "腾讯云 COS 连接正常",
        _ => "配置格式有效",
    };
    json!({
        "status": "success",
        "message": message,
    })
}

pub async fn run_cloud_storage_config_test(
    config: &CloudStorageConfigInput,
    system_key: &str,
) -> Result<Value, AppError> {
    if config.provider == PROVIDER_LOCAL {
        assert_local_storage_writable(&cloud_storage_root())?;
        return Ok(cloud_config_test_view(&config.provider));
    }
    let row = transient_config_row(config);
    let object_key = prefixed_key(
        config,
        &format!(".network-auth-probe/{}.txt", crypto::token(8)),
    );
    let upload = PreparedCloudUpload {
        original_name: "probe.txt".to_string(),
        mime_type: "text/plain".to_string(),
        extension: "txt".to_string(),
        size_bytes: 2,
        sha256: crypto::sha256_hex("ok"),
        remark: String::new(),
        content: b"ok".to_vec(),
    };
    match config.provider.as_str() {
        PROVIDER_ALIYUN => {
            put_aliyun_object(&row, &object_key, &upload, system_key).await?;
            delete_aliyun_object(&row, &object_key, system_key).await?;
        }
        PROVIDER_TENCENT => {
            put_tencent_object(&row, &object_key, &upload, system_key).await?;
            delete_tencent_object(&row, &object_key, system_key).await?;
        }
        _ => return Err(AppError::CloudStorageProviderInvalid),
    }
    Ok(cloud_config_test_view(&config.provider))
}

pub fn download_token_view(
    token: Option<&CloudDownloadTokenRow>,
    system_key: &str,
) -> Result<Value, AppError> {
    let Some(token) = token else {
        return Ok(json!({
            "status": 0,
            "token": "",
            "last_used_ip": "",
            "last_used_at": "",
        }));
    };
    let token_text = match token.token_cipher.as_deref().map(str::trim) {
        Some(cipher) if !cipher.is_empty() => crypto::decrypt_protected_text(cipher, system_key)?,
        _ => String::new(),
    };
    Ok(json!({
        "status": token.status,
        "token": token_text,
        "last_used_ip": token.last_used_ip,
        "last_used_at": format_datetime(token.last_used_at),
    }))
}

pub fn download_token_hash(token: &str, system_key: &str) -> Result<String, AppError> {
    crypto::hmac_sha256_hex_string(
        system_key.as_bytes(),
        &format!("cloud-download:{}", token.trim()),
    )
}

pub fn temporary_download_url(
    config: &CloudStorageConfigRow,
    object_key: &str,
    system_key: &str,
) -> Result<String, AppError> {
    let ttl_seconds = signed_url_ttl(config.signed_url_ttl_seconds);
    match config.provider.as_str() {
        PROVIDER_ALIYUN => aliyun_temporary_url(config, object_key, system_key, ttl_seconds),
        PROVIDER_TENCENT => tencent_temporary_url(config, object_key, system_key, ttl_seconds),
        PROVIDER_LOCAL => Ok(String::new()),
        _ => Err(AppError::CloudStorageProviderInvalid),
    }
}

async fn put_aliyun_object(
    config: &CloudStorageConfigRow,
    object_key: &str,
    upload: &PreparedCloudUpload,
    system_key: &str,
) -> Result<(), AppError> {
    let content_type = content_type_or_default(&upload.mime_type);
    let date = gmt_date();
    let resource = aliyun_canonical_resource(config, object_key);
    let secret = config_secret(config, system_key)?;
    let signature = hmac_sha1_base64(
        secret.as_bytes(),
        &format!("PUT\n\n{content_type}\n{date}\n{resource}"),
    )?;
    let authorization = format!("OSS {}:{signature}", config.access_key);
    send_cloud_request(
        Method::PUT,
        &aliyun_object_url(config, object_key, false)?,
        vec![
            (DATE.as_str(), date),
            (CONTENT_TYPE.as_str(), content_type),
            (AUTHORIZATION.as_str(), authorization),
        ],
        Some(upload.content.clone()),
        "OSS 上传失败",
        REMOTE_UPLOAD_TIMEOUT_SECONDS,
    )
    .await
}

async fn delete_aliyun_object(
    config: &CloudStorageConfigRow,
    object_key: &str,
    system_key: &str,
) -> Result<(), AppError> {
    let date = gmt_date();
    let resource = aliyun_canonical_resource(config, object_key);
    let secret = config_secret(config, system_key)?;
    let signature = hmac_sha1_base64(
        secret.as_bytes(),
        &format!("DELETE\n\n\n{date}\n{resource}"),
    )?;
    let authorization = format!("OSS {}:{signature}", config.access_key);
    send_cloud_request(
        Method::DELETE,
        &aliyun_object_url(config, object_key, false)?,
        vec![
            (DATE.as_str(), date),
            (AUTHORIZATION.as_str(), authorization),
        ],
        None,
        "OSS 请求失败",
        REMOTE_REQUEST_TIMEOUT_SECONDS,
    )
    .await
}

async fn put_tencent_object(
    config: &CloudStorageConfigRow,
    object_key: &str,
    upload: &PreparedCloudUpload,
    system_key: &str,
) -> Result<(), AppError> {
    let host = tencent_host(config)?;
    let path = encoded_object_path(object_key);
    let secret = config_secret(config, system_key)?;
    let authorization = tencent_authorization(config, "put", &path, &host, 300, &secret)?;
    send_cloud_request(
        Method::PUT,
        &format!("https://{host}{path}"),
        vec![
            (HOST.as_str(), host),
            (
                CONTENT_TYPE.as_str(),
                content_type_or_default(&upload.mime_type),
            ),
            (AUTHORIZATION.as_str(), authorization),
        ],
        Some(upload.content.clone()),
        "COS 上传失败",
        REMOTE_UPLOAD_TIMEOUT_SECONDS,
    )
    .await
}

async fn delete_tencent_object(
    config: &CloudStorageConfigRow,
    object_key: &str,
    system_key: &str,
) -> Result<(), AppError> {
    let host = tencent_host(config)?;
    let path = encoded_object_path(object_key);
    let secret = config_secret(config, system_key)?;
    let authorization = tencent_authorization(config, "delete", &path, &host, 300, &secret)?;
    send_cloud_request(
        Method::DELETE,
        &format!("https://{host}{path}"),
        vec![
            (HOST.as_str(), host),
            (AUTHORIZATION.as_str(), authorization),
        ],
        None,
        "COS 请求失败",
        REMOTE_REQUEST_TIMEOUT_SECONDS,
    )
    .await
}

async fn send_cloud_request(
    method: Method,
    url: &str,
    headers: Vec<(&'static str, String)>,
    body: Option<Vec<u8>>,
    message: &'static str,
    timeout_seconds: u64,
) -> Result<(), AppError> {
    let client = reqwest::Client::builder()
        .timeout(StdDuration::from_secs(timeout_seconds))
        .build()
        .map_err(|error| cloud_remote_error(message, Some(&error.to_string()), None))?;
    let mut request = client.request(method, url);
    for (name, value) in headers {
        request = request.header(name, value);
    }
    if let Some(body) = body {
        request = request.body(body);
    }
    let response = request
        .send()
        .await
        .map_err(|error| cloud_remote_error(message, Some(&error.to_string()), None))?;
    if !response.status().is_success() {
        return Err(cloud_remote_error(
            message,
            None,
            Some(response.status().as_u16()),
        ));
    }
    Ok(())
}

fn cloud_remote_error(
    message: &'static str,
    detail: Option<&str>,
    status: Option<u16>,
) -> AppError {
    let mut text = message.to_string();
    if let Some(detail) = detail.filter(|detail| !detail.is_empty()) {
        text.push('：');
        text.push_str(detail);
    } else if let Some(status) = status {
        text.push_str(&format!(" HTTP {status}"));
    }
    AppError::CloudStorageRemoteFailed(text)
}

fn content_type_or_default(value: &str) -> String {
    let content_type = value.trim();
    if content_type.is_empty() {
        "application/octet-stream".to_string()
    } else {
        content_type.to_string()
    }
}

fn gmt_date() -> String {
    Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

pub fn upload_ticket_hash(ticket: &str, system_key: &str) -> Result<String, AppError> {
    crypto::hmac_sha256_hex_string(
        system_key.as_bytes(),
        &format!("cloud-upload:{}", ticket.trim()),
    )
}

pub fn enabled_flag(value: Option<&Value>) -> i64 {
    match int_from_value(value) {
        Some(1) => FLAG_ENABLED,
        _ => 0,
    }
}

pub fn require_enabled_default_config(
    config: Option<CloudStorageConfigRow>,
) -> Result<CloudStorageConfigRow, AppError> {
    let config = config.ok_or(AppError::CloudStorageDefaultMissing)?;
    if config.status != FLAG_ENABLED {
        return Err(AppError::CloudStorageDefaultMissing);
    }
    Ok(config)
}

pub fn create_upload_ticket_payload(
    payload: &Value,
    config: &CloudStorageConfigRow,
    admin_session_id: u64,
    system_key: &str,
) -> Result<UploadTicketPayload, AppError> {
    let input = upload_ticket_input(payload, config)?;
    let token = crypto::token(32);
    let expires_at = Local::now() + Duration::seconds(UPLOAD_TICKET_TTL_SECONDS);
    Ok(UploadTicketPayload {
        ticket: CloudUploadTicketInput {
            ticket_hash: upload_ticket_hash(&token, system_key)?,
            admin_session_id: Some(admin_session_id),
            provider: config.provider.clone(),
            expected_sha256: input.sha256,
            expected_size: input.size_bytes,
            original_name: input.original_name,
            mime_type: input.mime_type,
            remark: input.remark,
            status: TICKET_PENDING.to_string(),
            expires_at: expires_at.naive_local(),
        },
        token,
        expires_at: expires_at.timestamp(),
    })
}

pub fn upload_ticket_response(ticket: &UploadTicketPayload, provider: &str) -> Value {
    json!({
        "ticket": ticket.token,
        "expires_at": ticket.expires_at,
        "provider": provider_view(provider),
        "upload_url": "/api/v1/index.php?route=%2Fadmin%2Fcloud-storage%2Ffiles%2Fupload",
    })
}

pub fn upload_ticket_token(value: &str) -> Result<String, AppError> {
    let ticket = value.trim();
    if (32..=256).contains(&ticket.len())
        && ticket
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Ok(ticket.to_string());
    }
    Err(AppError::CloudUploadTicketInvalid)
}

pub fn require_pending_upload_ticket(
    ticket: Option<CloudUploadTicketRow>,
) -> Result<CloudUploadTicketRow, AppError> {
    let ticket = ticket.ok_or(AppError::CloudUploadTicketInvalid)?;
    if ticket.status != TICKET_PENDING || ticket.expires_at < Local::now().naive_local() {
        return Err(AppError::CloudUploadTicketInvalid);
    }
    Ok(ticket)
}

pub fn assert_upload_session(
    ticket: &CloudUploadTicketRow,
    session_id: u64,
) -> Result<(), AppError> {
    if ticket.admin_session_id == Some(session_id) {
        return Ok(());
    }
    Err(AppError::CloudUploadTicketInvalid)
}

pub async fn store_cloud_upload(
    ticket: &CloudUploadTicketRow,
    config: &CloudStorageConfigRow,
    upload: CloudUploadForm,
    system_key: &str,
) -> Result<CloudFileInput, AppError> {
    if config.status != FLAG_ENABLED {
        return Err(AppError::CloudStorageConfigMissing);
    }
    assert_upload_content(ticket, config, &upload)?;
    let prepared = PreparedCloudUpload {
        original_name: ticket.original_name.clone(),
        mime_type: ticket.mime_type.clone(),
        extension: extension(&ticket.original_name)?,
        size_bytes: ticket.expected_size,
        sha256: ticket.expected_sha256.clone(),
        remark: ticket.remark.clone(),
        content: upload.content,
    };
    store_cloud_object(config, prepared, system_key).await
}

pub async fn store_cloud_base64_upload(
    payload: &Value,
    config: &CloudStorageConfigRow,
    system_key: &str,
) -> Result<CloudFileInput, AppError> {
    if config.status != FLAG_ENABLED {
        return Err(AppError::CloudStorageConfigMissing);
    }
    let original_name = file_name(&payload_string(payload, "original_name"))?;
    let content = base64_content(&payload_string(payload, "content_base64"))?;
    if content.len() as i64 > config.max_file_size {
        return Err(AppError::CloudUploadTooLarge);
    }
    let extension = extension(&original_name)?;
    assert_extension_allowed(&extension, &config.allowed_extensions)?;
    let computed_hash = crypto::sha256_hex_bytes(&content);
    let expected_hash = payload_string(payload, "sha256");
    if !expected_hash.is_empty() && sha256(&expected_hash)? != computed_hash {
        return Err(AppError::CloudUploadHashMismatch);
    }
    let prepared = PreparedCloudUpload {
        original_name,
        mime_type: safe_text(
            &payload_string_or(payload, "mime_type", "application/octet-stream"),
            120,
        )?,
        extension,
        size_bytes: content.len() as i64,
        sha256: computed_hash,
        remark: safe_text(&payload_string(payload, "remark"), 255)?,
        content,
    };
    store_cloud_object(config, prepared, system_key).await
}

async fn store_cloud_object(
    config: &CloudStorageConfigRow,
    upload: PreparedCloudUpload,
    system_key: &str,
) -> Result<CloudFileInput, AppError> {
    let object_key = object_key(config, &upload.extension);
    let local_path = match config.provider.as_str() {
        PROVIDER_LOCAL => {
            write_local_object(&object_key, &upload.content)?;
            object_key.clone()
        }
        PROVIDER_ALIYUN => {
            put_aliyun_object(config, &object_key, &upload, system_key).await?;
            String::new()
        }
        PROVIDER_TENCENT => {
            put_tencent_object(config, &object_key, &upload, system_key).await?;
            String::new()
        }
        _ => return Err(AppError::CloudStorageProviderInvalid),
    };
    Ok(CloudFileInput {
        file_key: unique_file_key(),
        provider: config.provider.clone(),
        config_id: config.id,
        original_name: upload.original_name,
        mime_type: upload.mime_type,
        extension: upload.extension,
        size_bytes: upload.size_bytes,
        sha256: upload.sha256,
        object_key,
        local_path,
        status: STATUS_ACTIVE.to_string(),
        remark: upload.remark,
    })
}

fn write_local_object(object_key: &str, content: &[u8]) -> Result<(), AppError> {
    let target_path = local_object_path(object_key)?;
    if let Some(parent) = target_path.parent() {
        fs::create_dir_all(parent).map_err(|_| AppError::CloudStorageDirectoryFailed)?;
    }
    fs::write(&target_path, content).map_err(|_| AppError::CloudStorageLocalWriteFailed)?;
    Ok(())
}

pub fn cloud_storage_root() -> PathBuf {
    PathBuf::from("storage").join("cloud-storage")
}

pub fn local_object_path(object_key: &str) -> Result<PathBuf, AppError> {
    let normalized = object_key.trim_matches('/').replace('\\', "/");
    if normalized.is_empty() || normalized.contains("..") || normalized.contains('\0') {
        return Err(AppError::InvalidInput("文件路径非法"));
    }
    let root = cloud_storage_root();
    fs::create_dir_all(&root).map_err(|_| AppError::CloudStorageDirectoryFailed)?;
    let base = root
        .canonicalize()
        .map_err(|_| AppError::InvalidInput("文件路径不可解析"))?;
    let path = base.join(normalized.replace('/', std::path::MAIN_SEPARATOR_STR));
    let parent = path
        .parent()
        .ok_or(AppError::InvalidInput("文件路径不可解析"))?;
    if parent.exists() {
        let parent = parent
            .canonicalize()
            .map_err(|_| AppError::InvalidInput("文件路径不可解析"))?;
        if !parent.starts_with(&base) {
            return Err(AppError::InvalidInput("文件路径越界"));
        }
    }
    Ok(path)
}

pub fn delete_local_object(object_key: &str) -> Result<(), AppError> {
    let path = local_object_path(object_key)?;
    if path.is_file() {
        fs::remove_file(path).map_err(|_| AppError::CloudStorageDeleteFailed)?;
    }
    Ok(())
}

pub async fn delete_cloud_object(
    config: &CloudStorageConfigRow,
    object_key: &str,
    system_key: &str,
) -> Result<(), AppError> {
    match config.provider.as_str() {
        PROVIDER_LOCAL => delete_local_object(object_key),
        PROVIDER_ALIYUN => delete_aliyun_object(config, object_key, system_key).await,
        PROVIDER_TENCENT => delete_tencent_object(config, object_key, system_key).await,
        _ => Err(AppError::CloudStorageProviderInvalid),
    }
}

pub fn config_view(config: Option<&CloudStorageConfigRow>) -> Value {
    let Some(config) = config else {
        return json!({});
    };
    json!({
        "id": config.id.to_string(),
        "provider": provider_view(&config.provider),
        "status": config.status,
        "is_default": config.is_default,
        "bucket": config.bucket,
        "region": config.region,
        "endpoint": config.endpoint,
        "access_key": config.access_key,
        "secret_saved": config.secret_cipher.as_deref().unwrap_or_default().trim() != "",
        "path_prefix": config.path_prefix,
        "custom_domain": config.custom_domain,
        "max_file_size": config.max_file_size,
        "allowed_extensions": config.allowed_extensions,
        "signed_url_ttl_seconds": config.signed_url_ttl_seconds,
        "last_test_status": config.last_test_status,
        "last_test_message": config.last_test_message,
        "last_test_at": format_datetime(config.last_test_at),
    })
}

fn provider_counts(rows: Vec<CloudProviderCountRow>) -> Value {
    let mut counts = provider_options()
        .into_iter()
        .filter_map(|provider| {
            let value = provider.get("value")?.as_str()?.to_string();
            Some((value, json!({"file_count": 0, "size_total": 0})))
        })
        .collect::<BTreeMap<_, _>>();
    for row in rows {
        if let Some(count) = counts.get_mut(&row.provider) {
            *count = json!({"file_count": row.file_count, "size_total": row.size_total});
        }
    }
    json!(counts)
}

fn provider_options() -> Vec<Value> {
    [PROVIDER_LOCAL, PROVIDER_ALIYUN, PROVIDER_TENCENT]
        .into_iter()
        .map(provider_view)
        .collect()
}

fn provider_view(provider: &str) -> Value {
    match provider {
        PROVIDER_ALIYUN => json!({"value": PROVIDER_ALIYUN, "label": "阿里云 OSS"}),
        PROVIDER_TENCENT => json!({"value": PROVIDER_TENCENT, "label": "腾讯云 COS"}),
        _ => json!({"value": PROVIDER_LOCAL, "label": "服务器本地"}),
    }
}

fn provider(value: &str) -> Result<String, AppError> {
    let provider = value.trim();
    if matches!(
        provider,
        PROVIDER_LOCAL | PROVIDER_ALIYUN | PROVIDER_TENCENT
    ) {
        return Ok(provider.to_string());
    }
    Err(AppError::CloudStorageProviderInvalid)
}

fn optional_provider(value: &str) -> Result<String, AppError> {
    let provider = value.trim();
    if provider.is_empty() {
        return Ok(String::new());
    }
    self::provider(provider)
}

fn optional_file_status(value: &str) -> Result<String, AppError> {
    let status = value.trim();
    if status.is_empty() {
        return Ok(String::new());
    }
    if matches!(status, STATUS_ACTIVE | STATUS_DELETED | STATUS_FAILED) {
        return Ok(status.to_string());
    }
    Err(AppError::CloudFileStatusInvalid)
}

fn secret_cipher(
    payload: &Value,
    existing: Option<&CloudStorageConfigRow>,
    system_key: &str,
    force_empty: bool,
) -> Result<Option<String>, AppError> {
    if force_empty {
        return Ok(None);
    }
    let secret = payload_string(payload, "secret");
    if !secret.is_empty() {
        return crypto::encrypt_protected_text(&secret, system_key).map(Some);
    }
    Ok(existing.and_then(|config| config.secret_cipher.clone()))
}

fn assert_config_complete(config: &CloudStorageConfigInput) -> Result<(), AppError> {
    if config.provider == PROVIDER_LOCAL {
        return Ok(());
    }
    if config.bucket.is_empty()
        || config.access_key.is_empty()
        || config
            .secret_cipher
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
    {
        return Err(AppError::CloudStorageConfigIncomplete);
    }
    if config.provider == PROVIDER_ALIYUN && config.endpoint.is_empty() {
        return Err(AppError::CloudStorageConfigIncomplete);
    }
    if config.provider == PROVIDER_TENCENT && config.region.is_empty() {
        return Err(AppError::CloudStorageConfigIncomplete);
    }
    Ok(())
}

fn upload_ticket_input(
    payload: &Value,
    config: &CloudStorageConfigRow,
) -> Result<UploadFileInput, AppError> {
    let original_name = file_name(&payload_string(payload, "original_name"))?;
    let size_bytes = bounded_int(
        payload.get("size_bytes"),
        1,
        config.max_file_size,
        config.max_file_size,
    )?;
    let extension = extension(&original_name)?;
    assert_extension_allowed(&extension, &config.allowed_extensions)?;
    Ok(UploadFileInput {
        original_name,
        size_bytes,
        sha256: sha256(&payload_string(payload, "sha256"))?,
        mime_type: safe_text(
            &payload_string_or(payload, "mime_type", "application/octet-stream"),
            120,
        )?,
        remark: safe_text(&payload_string(payload, "remark"), 255)?,
    })
}

fn assert_upload_content(
    ticket: &CloudUploadTicketRow,
    config: &CloudStorageConfigRow,
    upload: &CloudUploadForm,
) -> Result<(), AppError> {
    if upload.content.is_empty() {
        return Err(AppError::CloudUploadFileInvalid);
    }
    let actual_size = upload.content.len() as i64;
    if actual_size != ticket.expected_size {
        return Err(AppError::CloudUploadSizeMismatch);
    }
    if actual_size > config.max_file_size {
        return Err(AppError::CloudUploadTooLarge);
    }
    let actual_hash = crypto::sha256_hex_bytes(&upload.content);
    if actual_hash != ticket.expected_sha256 {
        return Err(AppError::CloudUploadHashMismatch);
    }
    if file_name(&upload.file_name)? != ticket.original_name {
        return Err(AppError::CloudUploadFileInvalid);
    }
    let mime_type = safe_text(&upload.mime_type, 120)?;
    if !mime_type.is_empty() && mime_type != ticket.mime_type {
        return Err(AppError::CloudUploadFileInvalid);
    }
    Ok(())
}

fn base64_content(value: &str) -> Result<Vec<u8>, AppError> {
    let normalized = value
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    if normalized.is_empty() {
        return Err(AppError::CloudUploadContentInvalid);
    }
    let content = BASE64_STANDARD
        .decode(normalized)
        .map_err(|_| AppError::CloudUploadContentInvalid)?;
    if content.is_empty() {
        return Err(AppError::CloudUploadContentInvalid);
    }
    Ok(content)
}

fn object_key(config: &CloudStorageConfigRow, extension: &str) -> String {
    let prefix = config.path_prefix.trim_matches('/');
    let date_path = Local::now().format("%Y/%m").to_string();
    let suffix = if extension.is_empty() {
        String::new()
    } else {
        format!(".{extension}")
    };
    let file_name = format!("{}{}", crypto::token(18), suffix);
    if prefix.is_empty() {
        return format!("{date_path}/{file_name}");
    }
    format!("{prefix}/{date_path}/{file_name}")
}

fn prefixed_key(config: &CloudStorageConfigInput, path: &str) -> String {
    let prefix = config.path_prefix.trim_matches('/');
    let path = path.trim_start_matches('/');
    if prefix.is_empty() {
        path.to_string()
    } else {
        format!("{prefix}/{path}")
    }
}

fn transient_config_row(config: &CloudStorageConfigInput) -> CloudStorageConfigRow {
    CloudStorageConfigRow {
        id: 0,
        provider: config.provider.clone(),
        status: config.status,
        is_default: 0,
        bucket: config.bucket.clone(),
        region: config.region.clone(),
        endpoint: config.endpoint.clone(),
        access_key: config.access_key.clone(),
        secret_cipher: config.secret_cipher.clone(),
        path_prefix: config.path_prefix.clone(),
        custom_domain: config.custom_domain.clone(),
        max_file_size: config.max_file_size,
        allowed_extensions: config.allowed_extensions.clone(),
        signed_url_ttl_seconds: config.signed_url_ttl_seconds,
        last_test_status: String::new(),
        last_test_message: String::new(),
        last_test_at: None,
    }
}

fn unique_file_key() -> String {
    format!("cf_{}", crypto::token(18))
}

struct UploadFileInput {
    original_name: String,
    size_bytes: i64,
    sha256: String,
    mime_type: String,
    remark: String,
}

fn path_prefix(value: &str) -> Result<String, AppError> {
    let prefix = value.trim_matches(|ch: char| ch == '/' || ch.is_whitespace());
    if prefix.is_empty() {
        return Ok(String::new());
    }
    if prefix.len() > 180
        || prefix.contains("..")
        || !prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
    {
        return Err(AppError::InvalidInput("存储路径前缀格式错误"));
    }
    Ok(prefix.to_string())
}

fn allowed_extensions(value: &str) -> Result<String, AppError> {
    let mut extensions = Vec::new();
    for extension in value
        .to_ascii_lowercase()
        .split(',')
        .map(extension_token)
        .collect::<Result<Vec<_>, _>>()?
    {
        if !extension.is_empty() && !extensions.contains(&extension) {
            extensions.push(extension);
        }
    }
    Ok(extensions.join(","))
}

fn extension_token(value: &str) -> Result<String, AppError> {
    let extension = value.trim_matches(|ch: char| ch == '.' || ch.is_whitespace());
    if extension.is_empty() {
        return Ok(String::new());
    }
    if (1..=24).contains(&extension.len())
        && extension.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Ok(extension.to_string());
    }
    Err(AppError::InvalidInput("文件扩展名格式错误"))
}

fn assert_extension_allowed(extension: &str, allowed_extensions: &str) -> Result<(), AppError> {
    if allowed_extensions.trim().is_empty() {
        return Ok(());
    }
    let allowed = allowed_extensions
        .split(',')
        .map(str::trim)
        .any(|allowed| allowed.eq_ignore_ascii_case(extension));
    if allowed {
        return Ok(());
    }
    Err(AppError::InvalidInput("文件扩展名不允许上传"))
}

fn file_name(value: &str) -> Result<String, AppError> {
    let normalized = value.replace('\\', "/");
    let name = normalized
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    if name.is_empty()
        || name.len() > 255
        || name.bytes().any(|byte| {
            matches!(
                byte,
                0..=31 | b'<' | b'>' | b':' | b'"' | b'|' | b'?' | b'*'
            )
        })
    {
        return Err(AppError::InvalidInput("文件名格式错误"));
    }
    Ok(name)
}

fn extension(file_name: &str) -> Result<String, AppError> {
    let Some((_, extension)) = file_name.rsplit_once('.') else {
        return Ok(String::new());
    };
    extension_token(&extension.to_ascii_lowercase())
}

fn sha256(value: &str) -> Result<String, AppError> {
    let hash = value.trim().to_ascii_lowercase();
    if hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Ok(hash);
    }
    Err(AppError::InvalidInput("文件 SHA256 格式错误"))
}

fn bounded_int(value: Option<&Value>, min: i64, max: i64, default: i64) -> Result<i64, AppError> {
    let number = int_from_value(value).unwrap_or(default);
    if (min..=max).contains(&number) {
        return Ok(number);
    }
    Err(AppError::InvalidInput("数字超出允许范围"))
}

fn safe_text(value: &str, max_bytes: usize) -> Result<String, AppError> {
    if value.len() <= max_bytes
        && !value
            .bytes()
            .any(|byte| matches!(byte, b'<' | b'>' | b'"' | 0..=31))
    {
        return Ok(value.trim().to_string());
    }
    Err(AppError::InvalidText)
}

fn payload_string(payload: &Value, key: &str) -> String {
    payload
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn payload_string_or(payload: &Value, key: &str, default: &str) -> String {
    payload
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or(default)
        .trim()
        .to_string()
}

fn int_from_value(value: Option<&Value>) -> Option<i64> {
    value.and_then(|value| {
        value
            .as_i64()
            .or_else(|| value.as_str().and_then(|text| text.parse::<i64>().ok()))
    })
}

fn download_url(file_key: &str) -> String {
    format!("/api/v1/index.php?route=%2Fcloud%2Fdownload&file_key={file_key}")
}

fn signed_url_ttl(ttl_seconds: i64) -> i64 {
    ttl_seconds.clamp(SIGNED_URL_MIN_TTL, SIGNED_URL_MAX_TTL)
}

fn aliyun_temporary_url(
    config: &CloudStorageConfigRow,
    object_key: &str,
    system_key: &str,
    ttl_seconds: i64,
) -> Result<String, AppError> {
    let expires = Local::now().timestamp() + ttl_seconds;
    let resource = aliyun_canonical_resource(config, object_key);
    let secret = config_secret(config, system_key)?;
    let signature = hmac_sha1_base64(
        secret.as_bytes(),
        &format!("GET\n\n\n{expires}\n{resource}"),
    )?;
    let expires_text = expires.to_string();
    let query = query_string_rfc1738(&[
        ("OSSAccessKeyId", config.access_key.as_str()),
        ("Expires", expires_text.as_str()),
        ("Signature", signature.as_str()),
    ]);
    Ok(format!(
        "{}?{}",
        aliyun_object_url(config, object_key, true)?,
        query
    ))
}

fn tencent_temporary_url(
    config: &CloudStorageConfigRow,
    object_key: &str,
    system_key: &str,
    ttl_seconds: i64,
) -> Result<String, AppError> {
    let host = if config.custom_domain.trim().is_empty() {
        tencent_host(config)?
    } else {
        tencent_host_from_domain(&config.custom_domain)?
    };
    let path = encoded_object_path(object_key);
    let secret = config_secret(config, system_key)?;
    let authorization = tencent_authorization(config, "get", &path, &host, ttl_seconds, &secret)?;
    Ok(format!("https://{host}{path}?{authorization}"))
}

fn config_secret(config: &CloudStorageConfigRow, system_key: &str) -> Result<String, AppError> {
    let Some(cipher) = config.secret_cipher.as_deref().map(str::trim) else {
        return Ok(String::new());
    };
    if cipher.is_empty() {
        return Ok(String::new());
    }
    crypto::decrypt_protected_text(cipher, system_key)
}

fn aliyun_object_url(
    config: &CloudStorageConfigRow,
    object_key: &str,
    allow_custom_domain: bool,
) -> Result<String, AppError> {
    let host = if allow_custom_domain && !config.custom_domain.trim().is_empty() {
        aliyun_host_from_endpoint(&config.custom_domain)?
    } else {
        format!(
            "{}.{}",
            config.bucket,
            aliyun_host_from_endpoint(&config.endpoint)?
        )
    };
    Ok(format!("https://{host}{}", encoded_object_path(object_key)))
}

fn aliyun_canonical_resource(config: &CloudStorageConfigRow, object_key: &str) -> String {
    format!("/{}/{}", config.bucket, object_key.trim_start_matches('/'))
}

fn aliyun_host_from_endpoint(endpoint: &str) -> Result<String, AppError> {
    let host = trim_scheme_host(endpoint);
    if invalid_storage_host(&host) {
        return Err(AppError::CloudStorageEndpointInvalid(
            "OSS Endpoint 格式错误",
        ));
    }
    Ok(host)
}

fn tencent_host(config: &CloudStorageConfigRow) -> Result<String, AppError> {
    let bucket = config.bucket.trim();
    let region = config.region.trim();
    if bucket.is_empty() || region.is_empty() {
        return Err(AppError::CloudStorageConfigInvalid(
            "COS Bucket 和 Region 不能为空",
        ));
    }
    Ok(format!("{bucket}.cos.{region}.myqcloud.com"))
}

fn tencent_host_from_domain(domain: &str) -> Result<String, AppError> {
    let host = trim_scheme_host(domain);
    if invalid_storage_host(&host) {
        return Err(AppError::CloudStorageEndpointInvalid(
            "COS 自定义域名格式错误",
        ));
    }
    Ok(host)
}

fn trim_scheme_host(value: &str) -> String {
    let trimmed = value.trim();
    let lower = trimmed.to_ascii_lowercase();
    let without_scheme = if lower.starts_with("https://") {
        &trimmed[8..]
    } else if lower.starts_with("http://") {
        &trimmed[7..]
    } else {
        trimmed
    };
    without_scheme
        .trim_matches(|ch: char| ch == '/' || ch.is_whitespace())
        .to_string()
}

fn invalid_storage_host(host: &str) -> bool {
    host.is_empty()
        || host
            .chars()
            .any(|ch| ch.is_whitespace() || ch == '/' || ch == '\\')
}

fn tencent_authorization(
    config: &CloudStorageConfigRow,
    method: &str,
    path: &str,
    host: &str,
    ttl_seconds: i64,
    secret: &str,
) -> Result<String, AppError> {
    let start = Local::now().timestamp() - 60;
    let end = start + ttl_seconds + 60;
    let key_time = format!("{start};{end}");
    let header_list = "host";
    let url_param_list = "";
    let http_string = format!(
        "{}\n{path}\n\nhost={}\n",
        method.to_ascii_lowercase(),
        raw_url_encode(&host.to_ascii_lowercase())
    );
    let string_to_sign = format!("sha1\n{key_time}\n{}\n", sha1_hex(&http_string));
    let sign_key = hmac_sha1_hex(secret.as_bytes(), &key_time)?;
    let signature = hmac_sha1_hex(sign_key.as_bytes(), &string_to_sign)?;
    Ok(tencent_authorization_query(
        config.access_key.as_str(),
        &key_time,
        header_list,
        url_param_list,
        &signature,
    ))
}

fn tencent_authorization_query(
    access_key: &str,
    key_time: &str,
    header_list: &str,
    url_param_list: &str,
    signature: &str,
) -> String {
    [
        ("q-sign-algorithm", "sha1".to_string()),
        ("q-ak", raw_url_encode(access_key)),
        ("q-sign-time", key_time.to_string()),
        ("q-key-time", key_time.to_string()),
        ("q-header-list", raw_url_encode(header_list)),
        ("q-url-param-list", raw_url_encode(url_param_list)),
        ("q-signature", raw_url_encode(signature)),
    ]
    .into_iter()
    .map(|(key, value)| format!("{key}={value}"))
    .collect::<Vec<_>>()
    .join("&")
}

fn encoded_object_path(object_key: &str) -> String {
    let path = object_key.trim_start_matches('/');
    let segments = path.split('/').map(raw_url_encode).collect::<Vec<_>>();
    format!("/{}", segments.join("/"))
}

fn query_string_rfc1738(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                percent_encode(key, true),
                percent_encode(value, true)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn raw_url_encode(value: &str) -> String {
    percent_encode(value, false)
}

fn percent_encode(value: &str, space_as_plus: bool) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else if space_as_plus && byte == b' ' {
            encoded.push('+');
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn hmac_sha1_base64(key: &[u8], text: &str) -> Result<String, AppError> {
    let mut mac =
        HmacSha1::new_from_slice(key).map_err(|_| AppError::CryptoError("云存储签名失败"))?;
    mac.update(text.as_bytes());
    Ok(BASE64_STANDARD.encode(mac.finalize().into_bytes()))
}

fn hmac_sha1_hex(key: &[u8], text: &str) -> Result<String, AppError> {
    let mut mac =
        HmacSha1::new_from_slice(key).map_err(|_| AppError::CryptoError("云存储签名失败"))?;
    mac.update(text.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn sha1_hex(text: &str) -> String {
    hex::encode(Sha1::digest(text.as_bytes()))
}

fn format_datetime(value: Option<chrono::NaiveDateTime>) -> String {
    value
        .map(|datetime| datetime.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use serde_json::json;

    use crate::error::AppError;

    use super::{
        allowed_extensions, base64_content, cloud_config_payload, cloud_config_test_view,
        cloud_file_filters, cloud_remote_error, content_type_or_default, default_local_config,
        encoded_object_path, file_name, provider_view, query_string_rfc1738, raw_url_encode,
        tencent_authorization, tencent_authorization_query, trim_scheme_host,
    };
    use crate::repository::CloudStorageConfigRow;

    #[test]
    fn normalizes_local_config_payload_like_frontend() {
        let payload = json!({
            "provider": "local",
            "status": 1,
            "max_file_size": 1048576,
            "allowed_extensions": " zip,TXT,zip ",
            "signed_url_ttl_seconds": 300,
            "set_default": 1
        });

        let config =
            cloud_config_payload(&payload, None, "system-key", true).expect("config payload");

        assert_eq!("local", config.config.provider);
        assert!(config.set_default);
        assert_eq!("zip,txt", config.config.allowed_extensions);
    }

    #[test]
    fn parses_cloud_file_filters() {
        let filters = cloud_file_filters(&json!({
            "keyword": "sdk",
            "provider": "local",
            "status": "active",
            "page": 2,
            "limit": 20
        }))
        .expect("filters");

        assert_eq!("sdk", filters.keyword);
        assert_eq!("local", filters.provider);
        assert_eq!("active", filters.status);
        assert_eq!(20, filters.offset);
    }

    #[test]
    fn validates_file_names_and_extensions() {
        assert_eq!("app.zip", file_name("C:\\tmp\\app.zip").expect("file name"));
        assert_eq!(
            "zip,txt",
            allowed_extensions("ZIP, txt,zip").expect("extensions")
        );
        assert!(file_name("../bad:name").is_err());
        assert_eq!("服务器本地", provider_view("local")["label"]);
        assert_eq!(104_857_600, default_local_config().max_file_size);
    }

    #[test]
    fn decodes_remote_base64_upload_content_like_php() {
        assert_eq!(
            b"hello".to_vec(),
            base64_content(" aGVs\nbG8= ").expect("base64 content")
        );
        assert!(matches!(
            base64_content(""),
            Err(AppError::CloudUploadContentInvalid)
        ));
        assert!(matches!(
            base64_content("bad@@"),
            Err(AppError::CloudUploadContentInvalid)
        ));
    }

    #[test]
    fn encodes_signed_url_paths_like_php_rawurlencode() {
        assert_eq!(
            "/dir/a%20b/%E4%B8%AD%E6%96%87.txt",
            encoded_object_path("dir/a b/中文.txt")
        );
    }

    #[test]
    fn encodes_aliyun_signed_url_queries_like_php_query() {
        assert_eq!(
            "Signature=a%2Bb%2Fc%3D&Name=a+b",
            query_string_rfc1738(&[("Signature", "a+b/c="), ("Name", "a b")])
        );
        assert_eq!("Name%20With%20Space", raw_url_encode("Name With Space"));
    }

    #[test]
    fn trims_storage_hosts_like_php_drivers() {
        assert_eq!(
            "oss-cn-hangzhou.aliyuncs.com",
            trim_scheme_host("HTTPS://oss-cn-hangzhou.aliyuncs.com/")
        );
    }

    #[test]
    fn renders_config_test_messages_like_php_drivers() {
        assert_eq!("本地存储可写", cloud_config_test_view("local")["message"]);
        assert_eq!(
            "阿里云 OSS 连接正常",
            cloud_config_test_view("aliyun_oss")["message"]
        );
        assert_eq!(
            "腾讯云 COS 连接正常",
            cloud_config_test_view("tencent_cos")["message"]
        );
    }

    #[test]
    fn maps_remote_storage_failures_like_php_drivers() {
        let error = cloud_remote_error("OSS 上传失败", None, Some(403));

        assert_eq!("CLOUD_STORAGE_REMOTE_FAILED", error.error_code());
        assert_eq!(StatusCode::BAD_GATEWAY, error.status_code());
        assert_eq!("OSS 上传失败 HTTP 403", error.to_string());
        assert_eq!(
            "application/octet-stream",
            content_type_or_default(" ").as_str()
        );
    }

    #[test]
    fn signs_tencent_requests_with_requested_method_like_php_driver() {
        let config = tencent_config();
        let host = "bucket-123.cos.ap-guangzhou.myqcloud.com";
        let path = encoded_object_path("dir/app.zip");
        let put = tencent_authorization(&config, "put", &path, host, 300, "secret")
            .expect("put authorization");
        let delete = tencent_authorization(&config, "delete", &path, host, 300, "secret")
            .expect("delete authorization");

        assert_ne!(put, delete);
        assert!(put.contains("q-ak=ak"));
        assert!(put.contains("q-header-list=host"));
        assert!(delete.contains("q-url-param-list="));
    }

    #[test]
    fn keeps_tencent_sign_time_separator_unescaped_for_cos() {
        let authorization = tencent_authorization_query(
            "ak:with space",
            "1700000000;1700000360",
            "host",
            "",
            "abcdef",
        );

        assert!(authorization.contains("q-ak=ak%3Awith%20space"));
        assert!(authorization.contains("q-sign-time=1700000000;1700000360"));
        assert!(authorization.contains("q-key-time=1700000000;1700000360"));
        assert!(!authorization.contains("1700000000%3B1700000360"));
    }

    fn tencent_config() -> CloudStorageConfigRow {
        CloudStorageConfigRow {
            id: 1,
            provider: "tencent_cos".to_string(),
            status: 1,
            is_default: 0,
            bucket: "bucket-123".to_string(),
            region: "ap-guangzhou".to_string(),
            endpoint: String::new(),
            access_key: "ak".to_string(),
            secret_cipher: None,
            path_prefix: String::new(),
            custom_domain: String::new(),
            max_file_size: 104_857_600,
            allowed_extensions: String::new(),
            signed_url_ttl_seconds: 300,
            last_test_status: String::new(),
            last_test_message: String::new(),
            last_test_at: None,
        }
    }
}
