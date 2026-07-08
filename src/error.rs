use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("配置文件不存在: {0}")]
    ConfigMissing(String),
    #[error("配置文件读取失败: {0}")]
    ConfigReadFailed(String),
    #[error("配置项缺失: {0}")]
    ConfigValueMissing(&'static str),
    #[error("数据库连接失败")]
    DatabaseConnectFailed,
    #[error("数据库操作失败: {0}")]
    DatabaseQueryFailed(&'static str),
    #[error("加密处理失败: {0}")]
    CryptoError(&'static str),
    #[error("{0}")]
    CryptoMessage(&'static str),
    #[error("加密载荷格式错误")]
    BadEncryptedPayloadFormat,
    #[error("会话密钥解密失败")]
    BadEncryptedSessionKeyDecryptFailed,
    #[error("会话密钥长度错误")]
    BadEncryptedSessionKeyLength,
    #[error("加密载荷校验失败")]
    BadEncryptedPayloadVerificationFailed,
    #[error("请求体过大")]
    PayloadTooLarge,
    #[error("请先登录后台管理端")]
    AdminLoginRequired,
    #[error("管理接口未授权")]
    AdminUnauthorized,
    #[error("后台会话无效或已过期")]
    AdminSessionInvalid,
    #[error("管理员不存在")]
    AdminNotFound,
    #[error("{0}")]
    InvalidInput(&'static str),
    #[error("数字参数超出范围")]
    InvalidNumber,
    #[error("SDK 接口地址必须是 http/https 绝对地址")]
    InvalidApiUrl,
    #[error("应用不存在")]
    AppNotFound,
    #[error("应用不存在或已停用")]
    AppDisabled,
    #[error("卡密不存在")]
    CardNotFound,
    #[error("卡密不存在或不可用")]
    CardInvalid,
    #[error("卡密已过期")]
    CardExpired,
    #[error("次数卡已用完")]
    CardExhausted,
    #[error("{0}")]
    DevicePublicKeyInvalid(&'static str),
    #[error("{0}")]
    DeviceKeyModeInvalid(&'static str),
    #[error("{0}")]
    DeviceKeyModeMismatch(&'static str),
    #[error("明文登录仅允许临时票据模式")]
    PlainLoginModeInvalid,
    #[error("明文会话仅允许临时票据模式")]
    PlainSessionModeInvalid,
    #[error("{0}")]
    LoginChallengeInvalid(&'static str),
    #[error("{0}")]
    SessionInvalid(&'static str),
    #[error("临时票据缺失")]
    SessionTicketMissing,
    #[error("临时票据无效")]
    SessionTicketInvalid,
    #[error("临时票据已过期")]
    SessionTicketExpired,
    #[error("已绑定本地设备密钥的设备不能降级为临时票据模式")]
    DeviceKeyModeDowngrade,
    #[error("设备公钥与首次绑定不一致")]
    DeviceKeyChanged,
    #[error("设备已被禁用")]
    DeviceDisabled,
    #[error("当前登录 IP 不在设备首次绑定地区范围内")]
    LoginIpMismatch,
    #[error("服务端 IP 地区库不可用，无法校验登录 IP 地区")]
    IpRegionUnavailable,
    #[error("卡密绑定设备数量已达上限")]
    DeviceLimit,
    #[error("卡密已在其他设备使用中")]
    CardInUse,
    #[error("当前客户端版本过低，请更新后登录")]
    ClientVersionOutdated,
    #[error("账号不存在")]
    AccountNotFound,
    #[error("设备不存在")]
    DeviceNotFound,
    #[error("远程变量不存在")]
    VariableNotFound,
    #[error("远程变量名已存在: {0}")]
    DuplicateVariable(String),
    #[error("远程变量编号或名称错误")]
    InvalidVariable,
    #[error("请选择远程变量")]
    InvalidVariableIds,
    #[error("请选择变量授权应用")]
    InvalidVariableApps,
    #[error("远程变量作用域错误")]
    InvalidVariableScope,
    #[error("远程变量已在独立管理页面维护")]
    RemoteVariablesMoved,
    #[error("{0}")]
    RemoteLuaSourceInvalid(&'static str),
    #[error("RemoteLua 函数名格式错误")]
    RemoteLuaFunctionInvalid,
    #[error("编号格式错误")]
    InvalidId,
    #[error("应用编号列表格式错误")]
    InvalidAppCodes,
    #[error("文本包含非法字符")]
    InvalidText,
    #[error("系统名称不能为空")]
    InvalidHostname,
    #[error("扩展配置必须是合法 JSON 对象")]
    InvalidCustomJson,
    #[error("当前密码不正确")]
    InvalidCurrentPassword,
    #[error("Token 名称不能为空")]
    RemoteApiTokenNameRequired,
    #[error("远程 API token 不存在")]
    RemoteApiTokenInvalid,
    #[error("远程 API token 不存在")]
    RemoteApiAccessTokenInvalid,
    #[error("远程 API 签名请求头不完整")]
    RemoteApiHeaderMissing,
    #[error("远程 API token 已禁用")]
    RemoteApiTokenDisabled,
    #[error("远程 API token 已过期")]
    RemoteApiTokenExpired,
    #[error("远程 API 请求 IP 不在白名单")]
    RemoteApiIpDenied,
    #[error("远程 API 请求时间已过期")]
    RemoteApiStaleRequest,
    #[error("远程 API 随机串格式错误")]
    RemoteApiInvalidNonce,
    #[error("远程 API 请求签名错误")]
    RemoteApiBadSignature,
    #[error("远程 API 请求已被使用")]
    RemoteApiReplayRequest,
    #[error("远程 API 路由不存在")]
    RemoteApiRouteNotFound,
    #[error("Token 过期时间格式错误")]
    RemoteApiExpiresAtInvalid,
    #[error("IP 白名单格式错误")]
    RemoteApiIpRuleInvalid,
    #[error("远程 API accessKey 生成失败")]
    RemoteApiAccessKeyExhausted,
    #[error("远程 API accessKey 已存在")]
    RemoteApiAccessKeyExists,
    #[error("请确认清空远程 API 调用日志")]
    RemoteApiLogClearConfirmRequired,
    #[error("默认存储必须保持启用")]
    CloudStorageDefaultDisabled,
    #[error("请先刷新生成下载 Token")]
    CloudDownloadTokenMissing,
    #[error("下载 Token 未启用")]
    CloudDownloadTokenDisabled,
    #[error("下载 Token 无效")]
    CloudDownloadTokenInvalid,
    #[error("云存储来源不支持")]
    CloudStorageProviderInvalid,
    #[error("消息不存在")]
    MessageNotFound,
    #[error("消息状态不支持")]
    InvalidMessageStatus,
    #[error("安全处置动作不支持")]
    InvalidSecurityAction,
    #[error("安全风险等级不支持")]
    InvalidSecurityRiskLevel,
    #[error("安全事件类型不支持")]
    InvalidSecurityEventType,
    #[error("安全策略模式不支持")]
    InvalidSecurityPolicyMode,
    #[error("{0}")]
    InvalidSecurityPolicy(&'static str),
    #[error("{0}")]
    SecurityReportInvalid(&'static str),
    #[error("{0}")]
    SecurityReportTooLarge(&'static str),
    #[error("{0}")]
    RateLimited(&'static str),
    #[error("云存储凭证配置不完整")]
    CloudStorageConfigIncomplete,
    #[error("默认存储未启用")]
    CloudStorageDefaultMissing,
    #[error("存储配置不存在或未启用")]
    CloudStorageConfigMissing,
    #[error("文件存储配置不存在")]
    CloudFileStorageConfigMissing,
    #[error("{0}")]
    CloudStorageEndpointInvalid(&'static str),
    #[error("{0}")]
    CloudStorageConfigInvalid(&'static str),
    #[error("文件不存在")]
    CloudFileNotFound,
    #[error("文件不存在或已删除")]
    CloudFileUnavailable,
    #[error("文件不存在或不可读")]
    CloudFileUnreadable,
    #[error("文件 Key 格式错误")]
    CloudFileKeyInvalid,
    #[error("文件状态不支持")]
    CloudFileStatusInvalid,
    #[error("下载票据生成失败")]
    CloudDownloadTicketFailed,
    #[error("下载票据无效或已过期")]
    CloudDownloadTicketInvalid,
    #[error("本地云存储目录创建失败")]
    CloudStorageDirectoryFailed,
    #[error("本地云存储目录不可写")]
    CloudStorageLocalWriteFailed,
    #[error("本地文件删除失败")]
    CloudStorageDeleteFailed,
    #[error("{0}")]
    CloudStorageRemoteFailed(String),
    #[error("上传票据格式错误")]
    CloudUploadTicketInvalid,
    #[error("上传文件无效")]
    CloudUploadFileInvalid,
    #[error("上传文件 Base64 内容无效")]
    CloudUploadContentInvalid,
    #[error("上传文件大小与票据不一致")]
    CloudUploadSizeMismatch,
    #[error("上传文件 SHA256 与票据不一致")]
    CloudUploadHashMismatch,
    #[error("上传文件超过大小限制")]
    CloudUploadTooLarge,
    #[error("应用编号生成失败")]
    AppCodeExhausted,
    #[error("ID 列表格式错误")]
    InvalidIds,
    #[error("ID 列表不能为空")]
    EmptyIds,
    #[error("请求 Token 格式错误")]
    InvalidApiToken,
    #[error("接口配置格式错误")]
    InvalidApiRoutes,
    #[error("API 调用 ID 格式错误")]
    InvalidApiCallId,
    #[error("API 调用 ID 重复")]
    DuplicateApiCallId,
    #[error("接口不存在")]
    RouteNotFound,
    #[error("接口已关闭")]
    ApiDisabled,
    #[error("请求 Token 无效")]
    ApiTokenInvalid,
    #[error("API 调用 ID 无效")]
    ApiCallIdInvalid,
    #[error("网页卡密查询已关闭")]
    CardQueryDisabled,
    #[error("登录挑战生成失败")]
    LoginChallengeFailed,
    #[error("客户端加密算法不支持")]
    UnsupportedClientCrypto,
    #[error("客户端加密算法与应用配置不一致")]
    CryptoAlgorithmMismatch,
    #[error("应用客户端密钥对未生成")]
    AppKeyPairMissing,
    #[error("{0}")]
    BadDeviceSignature(&'static str),
    #[error("卡密解绑次数已用完")]
    UnbindLimitExceeded,
    #[error("卡密解绑冷却中")]
    UnbindCooldown,
    #[error("SDK 类型不支持")]
    InvalidSdkType,
    #[error("SDK 模板目录不存在或为空")]
    SdkTemplateMissing,
    #[error("SDK 打包失败")]
    SdkBuildFailed,
    #[error("后台会话来源变更")]
    AdminSessionIpChanged,
    #[error("后台签名请求头不完整")]
    MissingSignatureHeader,
    #[error("后台请求时间已过期")]
    StaleRequest,
    #[error("请求时间已过期")]
    ClientStaleRequest,
    #[error("后台随机串格式错误")]
    InvalidNonce,
    #[error("后台请求签名错误")]
    BadSignature,
    #[error("后台请求已被使用")]
    ReplayRequest,
    #[error("演示环境禁止修改数据")]
    DemoReadOnly,
    #[error("JSON 请求体格式错误")]
    RequestJsonInvalid,
    #[error("后台请求明文格式错误")]
    InvalidJson,
    #[error("接口路径格式错误")]
    InvalidRoute,
    #[error("请求方法不允许")]
    MethodNotAllowed,
    #[error("请求必须使用 application/json")]
    UnsupportedMediaType,
    #[error("静态文件不存在: {0}")]
    StaticFileMissing(&'static str),
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    code: u16,
    error: &'static str,
    message: String,
}

impl AppError {
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::ConfigMissing(_) => "CONFIG_MISSING",
            Self::ConfigReadFailed(_) => "CONFIG_READ_FAILED",
            Self::ConfigValueMissing(_) => "CONFIG_VALUE_MISSING",
            Self::DatabaseConnectFailed => "DATABASE_CONNECT_FAILED",
            Self::DatabaseQueryFailed(_) => "DATABASE_QUERY_FAILED",
            Self::CryptoError(_) | Self::CryptoMessage(_) => "CRYPTO_ERROR",
            Self::BadEncryptedPayloadFormat
            | Self::BadEncryptedSessionKeyDecryptFailed
            | Self::BadEncryptedSessionKeyLength
            | Self::BadEncryptedPayloadVerificationFailed => "BAD_ENCRYPTED_PAYLOAD",
            Self::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
            Self::AdminLoginRequired => "ADMIN_LOGIN_REQUIRED",
            Self::AdminUnauthorized => "ADMIN_UNAUTHORIZED",
            Self::AdminSessionInvalid => "ADMIN_SESSION_INVALID",
            Self::AdminNotFound => "ADMIN_NOT_FOUND",
            Self::InvalidInput(_) => "INVALID_INPUT",
            Self::InvalidNumber => "INVALID_NUMBER",
            Self::InvalidApiUrl => "INVALID_API_URL",
            Self::AppNotFound => "APP_NOT_FOUND",
            Self::AppDisabled => "APP_DISABLED",
            Self::CardNotFound => "CARD_NOT_FOUND",
            Self::CardInvalid => "CARD_INVALID",
            Self::CardExpired => "CARD_EXPIRED",
            Self::CardExhausted => "CARD_EXHAUSTED",
            Self::DevicePublicKeyInvalid(_) => "DEVICE_PUBLIC_KEY_INVALID",
            Self::DeviceKeyModeInvalid(_) | Self::DeviceKeyModeMismatch(_) => {
                "DEVICE_KEY_MODE_INVALID"
            }
            Self::PlainLoginModeInvalid => "PLAIN_LOGIN_MODE_INVALID",
            Self::PlainSessionModeInvalid => "PLAIN_SESSION_MODE_INVALID",
            Self::LoginChallengeInvalid(_) => "LOGIN_CHALLENGE_INVALID",
            Self::SessionInvalid(_) => "SESSION_INVALID",
            Self::SessionTicketMissing => "SESSION_TICKET_MISSING",
            Self::SessionTicketInvalid => "SESSION_TICKET_INVALID",
            Self::SessionTicketExpired => "SESSION_TICKET_EXPIRED",
            Self::DeviceKeyModeDowngrade => "DEVICE_KEY_MODE_DOWNGRADE",
            Self::DeviceKeyChanged => "DEVICE_KEY_CHANGED",
            Self::DeviceDisabled => "DEVICE_DISABLED",
            Self::LoginIpMismatch => "LOGIN_IP_MISMATCH",
            Self::IpRegionUnavailable => "IP_REGION_UNAVAILABLE",
            Self::DeviceLimit => "DEVICE_LIMIT",
            Self::CardInUse => "CARD_IN_USE",
            Self::ClientVersionOutdated => "CLIENT_VERSION_OUTDATED",
            Self::AccountNotFound => "ACCOUNT_NOT_FOUND",
            Self::DeviceNotFound => "DEVICE_NOT_FOUND",
            Self::VariableNotFound => "VARIABLE_NOT_FOUND",
            Self::DuplicateVariable(_) => "DUPLICATE_VARIABLE",
            Self::InvalidVariable => "INVALID_VARIABLE",
            Self::InvalidVariableIds => "INVALID_VARIABLE_IDS",
            Self::InvalidVariableApps => "INVALID_VARIABLE_APPS",
            Self::InvalidVariableScope => "INVALID_VARIABLE_SCOPE",
            Self::RemoteVariablesMoved => "REMOTE_VARIABLES_MOVED",
            Self::RemoteLuaSourceInvalid(_) => "REMOTE_LUA_SOURCE_INVALID",
            Self::RemoteLuaFunctionInvalid => "REMOTE_LUA_FUNCTION_INVALID",
            Self::InvalidId => "INVALID_ID",
            Self::InvalidAppCodes => "INVALID_APP_CODES",
            Self::InvalidText => "INVALID_TEXT",
            Self::InvalidHostname => "INVALID_HOSTNAME",
            Self::InvalidCustomJson => "INVALID_CUSTOM_JSON",
            Self::InvalidCurrentPassword => "INVALID_CURRENT_PASSWORD",
            Self::RemoteApiTokenNameRequired => "REMOTE_API_TOKEN_NAME_REQUIRED",
            Self::RemoteApiTokenInvalid | Self::RemoteApiAccessTokenInvalid => {
                "REMOTE_API_TOKEN_INVALID"
            }
            Self::RemoteApiHeaderMissing => "REMOTE_API_HEADER_MISSING",
            Self::RemoteApiTokenDisabled => "REMOTE_API_TOKEN_DISABLED",
            Self::RemoteApiTokenExpired => "REMOTE_API_TOKEN_EXPIRED",
            Self::RemoteApiIpDenied => "REMOTE_API_IP_DENIED",
            Self::RemoteApiStaleRequest => "REMOTE_API_STALE_REQUEST",
            Self::RemoteApiInvalidNonce => "REMOTE_API_INVALID_NONCE",
            Self::RemoteApiBadSignature => "REMOTE_API_BAD_SIGNATURE",
            Self::RemoteApiReplayRequest => "REMOTE_API_REPLAY_REQUEST",
            Self::RemoteApiRouteNotFound => "REMOTE_API_ROUTE_NOT_FOUND",
            Self::RemoteApiExpiresAtInvalid => "REMOTE_API_EXPIRES_AT_INVALID",
            Self::RemoteApiIpRuleInvalid => "REMOTE_API_IP_RULE_INVALID",
            Self::RemoteApiAccessKeyExhausted => "REMOTE_API_ACCESS_KEY_EXHAUSTED",
            Self::RemoteApiAccessKeyExists => "REMOTE_API_ACCESS_KEY_EXISTS",
            Self::RemoteApiLogClearConfirmRequired => "REMOTE_API_LOG_CLEAR_CONFIRM_REQUIRED",
            Self::CloudStorageDefaultDisabled => "CLOUD_STORAGE_DEFAULT_DISABLED",
            Self::CloudDownloadTokenMissing => "CLOUD_DOWNLOAD_TOKEN_MISSING",
            Self::CloudDownloadTokenDisabled => "CLOUD_DOWNLOAD_TOKEN_DISABLED",
            Self::CloudDownloadTokenInvalid => "CLOUD_DOWNLOAD_TOKEN_INVALID",
            Self::CloudStorageProviderInvalid => "CLOUD_STORAGE_PROVIDER_INVALID",
            Self::MessageNotFound => "MESSAGE_NOT_FOUND",
            Self::InvalidMessageStatus => "INVALID_MESSAGE_STATUS",
            Self::InvalidSecurityAction => "SECURITY_ACTION_INVALID",
            Self::InvalidSecurityRiskLevel => "INVALID_RISK_LEVEL",
            Self::InvalidSecurityEventType => "INVALID_SECURITY_EVENT_TYPE",
            Self::InvalidSecurityPolicyMode => "SECURITY_POLICY_MODE_INVALID",
            Self::InvalidSecurityPolicy(_) => "INVALID_SECURITY_POLICY",
            Self::SecurityReportInvalid(_) | Self::SecurityReportTooLarge(_) => {
                "SECURITY_REPORT_INVALID"
            }
            Self::RateLimited(_) => "RATE_LIMITED",
            Self::CloudStorageConfigIncomplete => "CLOUD_STORAGE_CONFIG_INCOMPLETE",
            Self::CloudStorageDefaultMissing => "CLOUD_STORAGE_DEFAULT_MISSING",
            Self::CloudStorageConfigMissing | Self::CloudFileStorageConfigMissing => {
                "CLOUD_STORAGE_CONFIG_MISSING"
            }
            Self::CloudStorageEndpointInvalid(_) => "CLOUD_STORAGE_ENDPOINT_INVALID",
            Self::CloudStorageConfigInvalid(_) => "CLOUD_STORAGE_CONFIG_INVALID",
            Self::CloudFileNotFound | Self::CloudFileUnavailable | Self::CloudFileUnreadable => {
                "CLOUD_FILE_NOT_FOUND"
            }
            Self::CloudFileKeyInvalid => "CLOUD_FILE_KEY_INVALID",
            Self::CloudFileStatusInvalid => "CLOUD_FILE_STATUS_INVALID",
            Self::CloudDownloadTicketFailed => "CLOUD_DOWNLOAD_TICKET_FAILED",
            Self::CloudDownloadTicketInvalid => "CLOUD_DOWNLOAD_TICKET_INVALID",
            Self::CloudStorageDirectoryFailed => "CLOUD_STORAGE_DIRECTORY_FAILED",
            Self::CloudStorageLocalWriteFailed => "CLOUD_STORAGE_LOCAL_WRITE_FAILED",
            Self::CloudStorageDeleteFailed => "CLOUD_STORAGE_DELETE_FAILED",
            Self::CloudStorageRemoteFailed(_) => "CLOUD_STORAGE_REMOTE_FAILED",
            Self::CloudUploadTicketInvalid => "CLOUD_UPLOAD_TICKET_INVALID",
            Self::CloudUploadFileInvalid => "CLOUD_UPLOAD_FILE_INVALID",
            Self::CloudUploadContentInvalid => "CLOUD_UPLOAD_CONTENT_INVALID",
            Self::CloudUploadSizeMismatch => "CLOUD_UPLOAD_SIZE_MISMATCH",
            Self::CloudUploadHashMismatch => "CLOUD_UPLOAD_HASH_MISMATCH",
            Self::CloudUploadTooLarge => "CLOUD_UPLOAD_TOO_LARGE",
            Self::AppCodeExhausted => "APP_CODE_EXHAUSTED",
            Self::InvalidIds | Self::EmptyIds => "INVALID_IDS",
            Self::InvalidApiToken => "INVALID_API_TOKEN",
            Self::InvalidApiRoutes => "INVALID_API_ROUTES",
            Self::InvalidApiCallId => "INVALID_API_CALL_ID",
            Self::DuplicateApiCallId => "DUPLICATE_API_CALL_ID",
            Self::RouteNotFound => "ROUTE_NOT_FOUND",
            Self::ApiDisabled => "API_DISABLED",
            Self::ApiTokenInvalid => "API_TOKEN_INVALID",
            Self::ApiCallIdInvalid => "API_CALL_ID_INVALID",
            Self::CardQueryDisabled => "CARD_QUERY_DISABLED",
            Self::LoginChallengeFailed => "LOGIN_CHALLENGE_FAILED",
            Self::UnsupportedClientCrypto => "UNSUPPORTED_CLIENT_CRYPTO",
            Self::CryptoAlgorithmMismatch => "CRYPTO_ALGORITHM_MISMATCH",
            Self::AppKeyPairMissing => "APP_KEYPAIR_MISSING",
            Self::BadDeviceSignature(_) => "BAD_DEVICE_SIGNATURE",
            Self::UnbindLimitExceeded => "UNBIND_LIMIT_EXCEEDED",
            Self::UnbindCooldown => "UNBIND_COOLDOWN",
            Self::InvalidSdkType => "INVALID_SDK_TYPE",
            Self::SdkTemplateMissing => "SDK_TEMPLATE_MISSING",
            Self::SdkBuildFailed => "SDK_BUILD_FAILED",
            Self::AdminSessionIpChanged => "ADMIN_SESSION_IP_CHANGED",
            Self::MissingSignatureHeader => "MISSING_SIGNATURE_HEADER",
            Self::StaleRequest | Self::ClientStaleRequest => "STALE_REQUEST",
            Self::InvalidNonce => "INVALID_NONCE",
            Self::BadSignature => "BAD_SIGNATURE",
            Self::ReplayRequest => "REPLAY_REQUEST",
            Self::DemoReadOnly => "DEMO_READ_ONLY",
            Self::RequestJsonInvalid | Self::InvalidJson => "INVALID_JSON",
            Self::InvalidRoute => "INVALID_ROUTE",
            Self::MethodNotAllowed => "METHOD_NOT_ALLOWED",
            Self::UnsupportedMediaType => "UNSUPPORTED_MEDIA_TYPE",
            Self::StaticFileMissing(_) => "STATIC_FILE_MISSING",
        }
    }

    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::AdminLoginRequired
            | Self::AdminUnauthorized
            | Self::AdminSessionInvalid
            | Self::AdminSessionIpChanged
            | Self::MissingSignatureHeader
            | Self::StaleRequest
            | Self::ClientStaleRequest
            | Self::InvalidNonce
            | Self::BadSignature
            | Self::ReplayRequest
            | Self::RemoteApiHeaderMissing
            | Self::ApiTokenInvalid
            | Self::ApiCallIdInvalid
            | Self::RemoteApiAccessTokenInvalid
            | Self::RemoteApiStaleRequest
            | Self::RemoteApiInvalidNonce
            | Self::RemoteApiBadSignature
            | Self::RemoteApiReplayRequest
            | Self::CloudDownloadTokenInvalid
            | Self::CloudDownloadTicketInvalid
            | Self::BadDeviceSignature(_)
            | Self::LoginChallengeInvalid(_)
            | Self::SessionInvalid(_)
            | Self::SessionTicketMissing
            | Self::SessionTicketInvalid
            | Self::SessionTicketExpired
            | Self::DeviceKeyModeMismatch(_)
            | Self::DeviceKeyModeDowngrade
            | Self::DeviceKeyChanged
            | Self::BadEncryptedSessionKeyDecryptFailed
            | Self::BadEncryptedSessionKeyLength
            | Self::BadEncryptedPayloadVerificationFailed => StatusCode::UNAUTHORIZED,
            Self::RequestJsonInvalid
            | Self::InvalidJson
            | Self::DevicePublicKeyInvalid(_)
            | Self::DeviceKeyModeInvalid(_)
            | Self::BadEncryptedPayloadFormat => StatusCode::BAD_REQUEST,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::DemoReadOnly
            | Self::AppDisabled
            | Self::CardInvalid
            | Self::CardExpired
            | Self::CardExhausted
            | Self::PlainLoginModeInvalid
            | Self::PlainSessionModeInvalid
            | Self::DeviceDisabled
            | Self::LoginIpMismatch
            | Self::DeviceLimit
            | Self::CardInUse
            | Self::UnbindLimitExceeded
            | Self::UnbindCooldown
            | Self::ApiDisabled
            | Self::CardQueryDisabled => StatusCode::FORBIDDEN,
            Self::InvalidInput(_)
            | Self::InvalidNumber
            | Self::InvalidApiUrl
            | Self::InvalidIds
            | Self::EmptyIds
            | Self::InvalidApiToken
            | Self::InvalidApiRoutes
            | Self::InvalidApiCallId
            | Self::DuplicateApiCallId
            | Self::UnsupportedClientCrypto
            | Self::InvalidSdkType
            | Self::DuplicateVariable(_)
            | Self::InvalidVariable
            | Self::InvalidVariableIds
            | Self::InvalidVariableApps
            | Self::InvalidVariableScope
            | Self::RemoteVariablesMoved
            | Self::RemoteLuaSourceInvalid(_)
            | Self::RemoteLuaFunctionInvalid
            | Self::InvalidId
            | Self::InvalidAppCodes
            | Self::InvalidText
            | Self::InvalidHostname
            | Self::InvalidCustomJson
            | Self::InvalidCurrentPassword
            | Self::RemoteApiTokenNameRequired
            | Self::RemoteApiExpiresAtInvalid
            | Self::RemoteApiIpRuleInvalid
            | Self::RemoteApiAccessKeyExists
            | Self::RemoteApiLogClearConfirmRequired
            | Self::CryptoAlgorithmMismatch
            | Self::InvalidMessageStatus
            | Self::InvalidSecurityAction
            | Self::InvalidSecurityRiskLevel
            | Self::InvalidSecurityEventType
            | Self::InvalidSecurityPolicyMode
            | Self::InvalidSecurityPolicy(_)
            | Self::SecurityReportInvalid(_)
            | Self::CloudStorageDefaultDisabled
            | Self::CloudStorageProviderInvalid
            | Self::CloudStorageConfigIncomplete
            | Self::CloudStorageDefaultMissing
            | Self::CloudStorageConfigMissing
            | Self::CloudStorageEndpointInvalid(_)
            | Self::CloudStorageConfigInvalid(_)
            | Self::CloudFileKeyInvalid
            | Self::CloudFileStatusInvalid
            | Self::CloudUploadFileInvalid
            | Self::CloudUploadContentInvalid
            | Self::CloudUploadSizeMismatch
            | Self::CloudUploadHashMismatch => StatusCode::BAD_REQUEST,
            Self::AppKeyPairMissing => StatusCode::FORBIDDEN,
            Self::CloudDownloadTokenMissing | Self::CloudDownloadTokenDisabled => {
                StatusCode::FORBIDDEN
            }
            Self::RemoteApiTokenDisabled
            | Self::RemoteApiTokenExpired
            | Self::RemoteApiIpDenied => StatusCode::FORBIDDEN,
            Self::ClientVersionOutdated => StatusCode::UPGRADE_REQUIRED,
            Self::CloudUploadTicketInvalid => StatusCode::UNAUTHORIZED,
            Self::AdminNotFound
            | Self::AppNotFound
            | Self::CardNotFound
            | Self::AccountNotFound
            | Self::DeviceNotFound
            | Self::VariableNotFound
            | Self::RemoteApiTokenInvalid
            | Self::MessageNotFound
            | Self::CloudFileNotFound
            | Self::CloudFileUnavailable
            | Self::CloudFileUnreadable
            | Self::CloudFileStorageConfigMissing
            | Self::RouteNotFound => StatusCode::NOT_FOUND,
            Self::CloudUploadTooLarge | Self::SecurityReportTooLarge(_) => {
                StatusCode::PAYLOAD_TOO_LARGE
            }
            Self::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,
            Self::CloudStorageRemoteFailed(_) => StatusCode::BAD_GATEWAY,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::AppCodeExhausted
            | Self::CloudDownloadTicketFailed
            | Self::RemoteApiAccessKeyExhausted
            | Self::LoginChallengeFailed
            | Self::CloudStorageDirectoryFailed
            | Self::CloudStorageLocalWriteFailed
            | Self::CloudStorageDeleteFailed
            | Self::SdkTemplateMissing
            | Self::SdkBuildFailed => StatusCode::INTERNAL_SERVER_ERROR,
            Self::IpRegionUnavailable => StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidRoute | Self::StaticFileMissing(_) | Self::RemoteApiRouteNotFound => {
                StatusCode::NOT_FOUND
            }
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let status = self.status_code();
        let body = ErrorBody {
            code: status.as_u16(),
            error: self.error_code(),
            message: self.to_string(),
        };
        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_client_crypto_payload_errors_like_php() {
        let cases = [
            (
                AppError::BadEncryptedPayloadFormat,
                StatusCode::BAD_REQUEST,
                "加密载荷格式错误",
            ),
            (
                AppError::BadEncryptedSessionKeyDecryptFailed,
                StatusCode::UNAUTHORIZED,
                "会话密钥解密失败",
            ),
            (
                AppError::BadEncryptedSessionKeyLength,
                StatusCode::UNAUTHORIZED,
                "会话密钥长度错误",
            ),
            (
                AppError::BadEncryptedPayloadVerificationFailed,
                StatusCode::UNAUTHORIZED,
                "加密载荷校验失败",
            ),
        ];

        for (error, status, message) in cases {
            assert_eq!("BAD_ENCRYPTED_PAYLOAD", error.error_code());
            assert_eq!(status, error.status_code());
            assert_eq!(message, error.to_string());
        }
    }

    #[test]
    fn maps_cloud_file_unavailable_like_php_client_download_ticket() {
        let error = AppError::CloudFileUnavailable;

        assert_eq!("CLOUD_FILE_NOT_FOUND", error.error_code());
        assert_eq!(StatusCode::NOT_FOUND, error.status_code());
        assert_eq!("文件不存在或已删除", error.to_string());
    }
}
