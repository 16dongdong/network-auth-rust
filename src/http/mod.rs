use std::{collections::HashMap, net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{ConnectInfo, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use chrono::Local;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use subtle::ConstantTimeEq;
use tokio::fs;
use tower_http::services::{ServeDir, ServeFile};

use crate::{
    crypto,
    error::AppError,
    install::{
        IdStrategy, InstallDatabaseConfig, InstallSystemPaths, id_strategy_from_name,
        id_strategy_from_php_config, normalize_admin_account, normalize_database_config,
        prepare_database_with_strategy, run_system_install_with_strategy,
    },
    repository::{AuthRepository, CloudFileRow, CloudStorageConfigRow},
    service::{
        admin::{
            AdminService, CloudUploadForm, download_token_hash, local_object_path,
            temporary_download_url,
        },
        admin_session::{AdminSessionContext, AdminSessionService, AdminSignedRequest},
        client::{ClientService, cloud_file_key, php_scalar_string},
        login::{LoginService, admin_cookie_name, login_state_cookie_name, remember_cookie_name},
        remote_api::{RemoteApiRequest, RemoteApiService},
    },
};

const CLOUD_DOWNLOAD_ROUTE: &str = "/cloud/download";
const CLOUD_UPLOAD_ROUTE: &str = "/admin/cloud-storage/files/upload";
const CARD_QUERY_ROUTE: &str = "/card/query";
const CLOUD_PROVIDER_LOCAL: &str = "local";
const CLOUD_FILE_STATUS_ACTIVE: &str = "active";
const CLOUD_DOWNLOAD_CRYPTO_FORMAT_MESSAGE: &str = "敏感数据密文格式错误";
const PHP_JSON_CONTENT_TYPE: &str = "application/json; charset=UTF-8";
const PHP_JSON_CACHE_CONTROL: &str = "no-store, no-cache, must-revalidate, max-age=0";
const PHP_JSON_PERMISSIONS_POLICY: &str =
    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()";
const PHP_JSON_CONTENT_SECURITY_POLICY: &str =
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
const INSTALL_SESSION_COOKIE: &str = "networkAuthInstallRustData";
const INSTALL_SESSION_TTL_SECONDS: i64 = 604_800;
const PHP_JSON_CORS_METHODS: &str = "POST, GET, OPTIONS";
const PHP_JSON_CORS_HEADERS: &str = "Content-Type, X-App-Code, X-Timestamp, X-Nonce, X-Signature, X-Admin-Token, X-Admin-Session, X-Api-Token, X-Api-Call-Id, X-Remote-Access-Key, X-Plain-Client, X-Demo-Admin";
const SKIP_PHP_JSON_HEADERS: &str = "x-network-auth-skip-php-json-headers";
const HTML_CONTENT_TYPE: &str = "text/html; charset=UTF-8";
const CSS_CONTENT_TYPE: &str = "text/css; charset=UTF-8";
const JAVASCRIPT_CONTENT_TYPE: &str = "application/javascript";
const ICON_CONTENT_TYPE: &str = "image/vnd.microsoft.icon";
const PHP_SESSION_CACHE_CONTROL: &str = "no-store, no-cache, must-revalidate";
const ADMIN_CONSOLE_CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://code.jquery.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; img-src 'self' data: https: blob:; font-src 'self' data: https://fonts.gstatic.com https://cdn.jsdelivr.net; connect-src 'self'; media-src 'self'; object-src 'none'; frame-src 'self'; frame-ancestors 'self'; form-action 'self'; base-uri 'self'; report-uri /api/csp-report.php;";
const LOGIN_CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
const INSTALL_REFERRER_POLICY: &str = "same-origin";
const LEGACY_ADMIN_FOOT_HTML: &str = r#"<link rel="stylesheet" href="/assets/layui/css/layui.css?v=2.13.7" /><link rel="stylesheet" type="text/css" href="/sub_admin/css/theme.css?v=20201111001" /><script src="/assets/layui/layui.js?v=2.13.7"></script>"#;
const CSP_REPORT_CONTENT_TYPE: &str = "application/json";
const CSP_REPORT_ALLOW_ORIGIN: &str = "*";
const CSP_REPORT_ALLOW_METHODS: &str = "POST";
const CSP_REPORT_ALLOW_HEADERS: &str = "Content-Type";
const CSP_REPORT_X_FRAME_OPTIONS: &str = "SAMEORIGIN";
const CSP_REPORT_X_XSS_PROTECTION: &str = "1; mode=block";
const CSP_REPORT_REFERRER_POLICY: &str = "strict-origin-when-cross-origin";
const CSP_REPORT_FEATURE_POLICY: &str = "accelerometer 'none'; camera 'none'; geolocation 'none'; gyroscope 'none'; magnetometer 'none'; microphone 'none'; payment 'none'; usb 'none'";
const CSP_REPORT_METHOD_ERROR_BODY: &str = r#"{"status":"error","message":"Method not allowed"}"#;
const CSP_REPORT_INVALID_BODY: &str = r#"{"status":"error","message":"Invalid report data"}"#;
const CLIENT_ROUTES: &[&str] = &[
    "/notice",
    "/login/challenge",
    "/login",
    "/unbind",
    "/heartbeat",
    "/config",
    "/variable",
    "/cloud/download-ticket",
    "/security/report",
    "/logout",
];
const PLAIN_CLIENT_ROUTES: &[&str] = &[
    "/notice",
    "/login/challenge",
    "/login",
    "/heartbeat",
    "/config",
    "/variable",
    "/cloud/download-ticket",
    "/security/report",
    "/logout",
];
const PLAIN_SESSION_ROUTES: &[&str] = &[
    "/heartbeat",
    "/config",
    "/variable",
    "/cloud/download-ticket",
    "/security/report",
    "/logout",
];
const REMOTE_ADMIN_ROUTES: &[(&str, RemoteAdminRoute)] = &[
    remote_admin_route_entry("/remote/apps/list", "/admin/apps/list"),
    remote_admin_route_entry("/remote/apps/create", "/admin/apps/create"),
    remote_admin_route_entry_with_transform(
        "/remote/apps/update",
        "/admin/apps/update",
        RemotePayloadTransform::AppId,
    ),
    remote_admin_route_entry_with_transform(
        "/remote/apps/status",
        "/admin/apps/status",
        RemotePayloadTransform::AppCode,
    ),
    remote_admin_route_entry_with_transform(
        "/remote/apps/delete",
        "/admin/apps/delete",
        RemotePayloadTransform::AppIds,
    ),
    remote_admin_route_entry_with_transform(
        "/remote/apps/generate-keypair",
        "/admin/apps/generate-keypair",
        RemotePayloadTransform::AppCode,
    ),
    remote_admin_route_entry_with_transform(
        "/remote/apps/api/update",
        "/admin/apps/api/update",
        RemotePayloadTransform::AppId,
    ),
    remote_admin_route_entry("/remote/cards/create", "/admin/cards/create"),
    remote_admin_route_entry("/remote/cards/list", "/admin/cards/list"),
    remote_admin_route_entry("/remote/cards/export", "/admin/cards/export"),
    remote_admin_route_entry("/remote/cards/status", "/admin/cards/status"),
    remote_admin_route_entry("/remote/cards/revoke", "/admin/cards/revoke"),
    remote_admin_route_entry("/remote/cards/delete", "/admin/cards/delete"),
    remote_admin_route_entry("/remote/config/get", "/admin/config/get"),
    remote_admin_route_entry("/remote/config/set", "/admin/config/set"),
    remote_admin_route_entry("/remote/variables/list", "/admin/variables/list"),
    (
        "/remote/cloud-storage/summary",
        RemoteAdminRoute::direct("/admin/cloud-storage/summary"),
    ),
    (
        "/remote/cloud-storage/files/list",
        RemoteAdminRoute::direct("/admin/cloud-storage/files/list"),
    ),
    (
        "/remote/cloud-storage/files/detail",
        RemoteAdminRoute::direct("/admin/cloud-storage/files/detail"),
    ),
    (
        "/remote/cloud-storage/files/delete",
        RemoteAdminRoute::direct("/admin/cloud-storage/files/delete"),
    ),
    (
        "/remote/cloud-storage/config/get",
        RemoteAdminRoute::direct("/admin/cloud-storage/config/get"),
    ),
    (
        "/remote/cloud-storage/config/save",
        RemoteAdminRoute::direct("/admin/cloud-storage/config/save"),
    ),
    (
        "/remote/cloud-storage/config/test",
        RemoteAdminRoute::direct("/admin/cloud-storage/config/test"),
    ),
    (
        "/remote/cloud-storage/download-token/get",
        RemoteAdminRoute::direct("/admin/cloud-storage/download-token/get"),
    ),
    (
        "/remote/cloud-storage/download-token/refresh",
        RemoteAdminRoute::direct("/admin/cloud-storage/download-token/refresh"),
    ),
    (
        "/remote/cloud-storage/download-token/status",
        RemoteAdminRoute::direct("/admin/cloud-storage/download-token/status"),
    ),
];
const REMOTE_SPECIAL_ROUTES: &[(&str, RemotePayloadTransform)] = &[
    ("/remote/apps/api/get", RemotePayloadTransform::None),
    (
        "/remote/variables/upsert",
        RemotePayloadTransform::AppIdsFromCodes,
    ),
    ("/remote/variables/status", RemotePayloadTransform::None),
    ("/remote/variables/delete", RemotePayloadTransform::None),
    (
        "/remote/variables/convert",
        RemotePayloadTransform::AppIdsFromCodes,
    ),
    (
        "/remote/variables/apps/set",
        RemotePayloadTransform::AppIdsFromCodes,
    ),
    (
        "/remote/cloud-storage/files/upload",
        RemotePayloadTransform::None,
    ),
];

#[derive(Clone, Copy)]
struct RemoteAdminRoute {
    admin_route: &'static str,
    transform: RemotePayloadTransform,
}

impl RemoteAdminRoute {
    const fn direct(admin_route: &'static str) -> Self {
        Self {
            admin_route,
            transform: RemotePayloadTransform::None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RemotePayloadTransform {
    None,
    AppId,
    AppCode,
    AppIds,
    AppIdsFromCodes,
}

const fn remote_admin_route_entry(
    remote_route: &'static str,
    admin_route: &'static str,
) -> (&'static str, RemoteAdminRoute) {
    (remote_route, RemoteAdminRoute::direct(admin_route))
}

const fn remote_admin_route_entry_with_transform(
    remote_route: &'static str,
    admin_route: &'static str,
    transform: RemotePayloadTransform,
) -> (&'static str, RemoteAdminRoute) {
    (
        remote_route,
        RemoteAdminRoute {
            admin_route,
            transform,
        },
    )
}
const DEMO_ADMIN_READ_ROUTES: &[&str] = &[
    "/admin/overview",
    "/admin/profile/get",
    "/admin/apps/list",
    "/admin/cards/list",
    "/admin/cards/export",
    "/admin/cards/devices",
    "/admin/accounts/list",
    "/admin/devices/list",
    "/admin/config/get",
    "/admin/variables/list",
    "/admin/audits/list",
    "/admin/messages/list",
    "/admin/messages/detail",
    "/admin/security/policy/get",
    "/admin/site/get",
    "/admin/remote-api/tokens/list",
    "/admin/remote-api/logs/list",
    "/admin/cloud-storage/summary",
    "/admin/cloud-storage/files/list",
    "/admin/cloud-storage/files/detail",
    "/admin/cloud-storage/config/get",
    "/admin/cloud-storage/download-token/get",
];

#[derive(Clone)]
pub struct AppState {
    repository: AuthRepository,
    admin_session_service: AdminSessionService,
    admin_service: AdminService,
    client_service: ClientService,
    login_service: LoginService,
    remote_api_service: RemoteApiService,
    system_key: Arc<String>,
    public_root: Arc<PathBuf>,
    config_file: Arc<PathBuf>,
    schema_file: Arc<PathBuf>,
    install_lock_file: Arc<PathBuf>,
    demo_mode: bool,
}

impl AppState {
    pub fn new(
        repository: AuthRepository,
        admin_session_service: AdminSessionService,
        admin_service: AdminService,
        client_service: ClientService,
        login_service: LoginService,
        remote_api_service: RemoteApiService,
        system_key: String,
        public_root: PathBuf,
        config_file: PathBuf,
        schema_file: PathBuf,
        install_lock_file: PathBuf,
        demo_mode: bool,
    ) -> Self {
        Self {
            repository,
            admin_session_service,
            admin_service,
            client_service,
            login_service,
            remote_api_service,
            system_key: Arc::new(system_key),
            public_root: Arc::new(public_root),
            config_file: Arc::new(config_file),
            schema_file: Arc::new(schema_file),
            install_lock_file: Arc::new(install_lock_file),
            demo_mode,
        }
    }
}

impl Default for InstallSession {
    fn default() -> Self {
        Self {
            csrf_token: String::new(),
            database: None,
            create_database: true,
            id_strategy: None,
            result: None,
        }
    }
}

impl From<&InstallDatabaseConfig> for InstallDatabaseSession {
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

impl InstallDatabaseSession {
    fn value(&self, key: &str) -> Option<String> {
        match key {
            "host" => Some(self.host.clone()),
            "port" => Some(self.port.to_string()),
            "user" => Some(self.username.clone()),
            "dbname" => Some(self.database_name.clone()),
            _ => None,
        }
    }
}

impl InstallForm {
    fn empty() -> Self {
        Self::default()
    }

    fn from_raw(action: &str, form: &HashMap<String, String>) -> Self {
        if action == "save_database" {
            return Self::database(form, form.contains_key("create_database"));
        }
        Self {
            submitted: true,
            action: action.to_string(),
            database: HashMap::new(),
            create_database: false,
        }
    }

    fn database(form: &HashMap<String, String>, create_database: bool) -> Self {
        let database = ["host", "port", "dbname", "user"]
            .into_iter()
            .filter_map(|key| form.get(key).map(|value| (key.to_string(), value.clone())))
            .collect::<HashMap<_, _>>();
        Self {
            submitted: true,
            action: "save_database".to_string(),
            database,
            create_database,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RouteQuery {
    route: Option<String>,
    ticket: Option<String>,
    file_key: Option<String>,
    download_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LoginQuery {
    slider: Option<String>,
    logout: Option<String>,
    forget_remember: Option<String>,
    image: Option<String>,
    version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct InstallQuery {
    step: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InstallSession {
    csrf_token: String,
    database: Option<InstallDatabaseSession>,
    create_database: bool,
    id_strategy: Option<String>,
    result: Option<InstallResultSession>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InstallDatabaseSession {
    host: String,
    port: u16,
    username: String,
    password: String,
    database_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InstallResultSession {
    config_file: String,
    statement_count: usize,
    admin_username: Option<String>,
    admin_token: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct InstallForm {
    submitted: bool,
    action: String,
    database: HashMap<String, String>,
    create_database: bool,
}

#[derive(Debug, Serialize)]
struct SuccessResponse<T: Serialize> {
    code: i64,
    message: &'static str,
    data: T,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdminCookieAuthentication {
    Authenticated,
    Missing,
    Invalid,
}

pub fn router(state: AppState) -> Router {
    let public_root = (*state.public_root).clone();
    Router::new()
        .route("/", get(admin_index_redirect))
        .route_service(
            "/favicon.ico",
            ServeFile::new(public_root.join("favicon.ico")),
        )
        .route_service("/404.html", ServeFile::new(public_root.join("404.html")))
        .route_service(
            "/install/disclaimer.html",
            ServeFile::new(public_root.join("install").join("disclaimer.html")),
        )
        .route_service(
            "/install/install.css",
            ServeFile::new(public_root.join("install").join("install.css")),
        )
        .route(
            "/api/v1/index.php",
            get(dispatch)
                .post(dispatch)
                .options(dispatch)
                .fallback(dispatch),
        )
        .route(
            "/api/v1/index.php/",
            get(dispatch)
                .post(dispatch)
                .options(dispatch)
                .fallback(dispatch),
        )
        .route(
            "/api/v1/index.php/{*path_info}",
            get(dispatch_path_info)
                .post(dispatch_path_info)
                .options(dispatch_path_info)
                .fallback(dispatch_path_info),
        )
        .route(
            "/cloud/download",
            get(cloud_download_entry)
                .post(cloud_download_entry)
                .options(cloud_download_entry)
                .fallback(cloud_download_entry),
        )
        .route(
            "/cloud/download/",
            get(cloud_download_entry)
                .post(cloud_download_entry)
                .options(cloud_download_entry)
                .fallback(cloud_download_entry),
        )
        .route(
            "/cloud/download/index.php",
            get(cloud_download_entry)
                .post(cloud_download_entry)
                .options(cloud_download_entry)
                .fallback(cloud_download_entry),
        )
        .route(
            "/api/csp-report.php",
            get(csp_report)
                .post(csp_report)
                .options(csp_report)
                .fallback(csp_report),
        )
        .route(
            "/install",
            get(install_entry)
                .post(install_entry)
                .options(install_entry)
                .fallback(install_entry),
        )
        .route(
            "/install/",
            get(install_entry)
                .post(install_entry)
                .options(install_entry)
                .fallback(install_entry),
        )
        .route(
            "/install/index.php",
            get(install_legacy_redirect)
                .post(install_entry)
                .options(install_entry)
                .fallback(install_entry),
        )
        .route("/admin", get(admin_index_redirect))
        .route("/admin/", get(admin_index_redirect))
        .route("/admin/index.php", get(admin_index_redirect))
        .route("/admin/login/", get(admin_login_get).post(admin_login_post))
        .route(
            "/admin/login/index.php",
            get(admin_login_get).post(admin_login_post),
        )
        .route("/admin/console/", get(admin_console))
        .route("/admin/console/index.php", get(admin_console))
        .route("/admin/remote-api/", get(admin_remote_api_redirect))
        .route(
            "/admin/remote-api/index.php",
            get(admin_remote_api_redirect),
        )
        .route(
            "/admin/remote-api/logs/",
            get(admin_remote_api_logs_redirect),
        )
        .route(
            "/admin/remote-api/logs/index.php",
            get(admin_remote_api_logs_redirect),
        )
        .route(
            "/sub_admin/login.php",
            get(legacy_admin_login_get).head(legacy_admin_login_head),
        )
        .route("/sub_admin/index.php", get(legacy_admin_index))
        .route("/sub_admin/console.php", get(legacy_admin_console))
        .route("/sub_admin/foot.php", get(legacy_admin_foot))
        .route(
            "/sub_admin/admin_session.php",
            post(create_admin_session)
                .options(admin_session_options)
                .fallback(admin_session_method_not_allowed),
        )
        .route("/health", get(health))
        .nest_service("/assets", ServeDir::new(public_root.join("assets")))
        .nest_service("/frontend", ServeDir::new(public_root.join("frontend")))
        .nest_service(
            "/sub_admin/css",
            ServeDir::new(public_root.join("sub_admin").join("css")),
        )
        .fallback(public_fallback)
        .layer(middleware::from_fn(php_json_headers_middleware))
        .with_state(state)
}

async fn php_json_headers_middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    normalize_static_content_type(&mut response);
    let skip_php_json_headers = response
        .headers_mut()
        .remove(SKIP_PHP_JSON_HEADERS)
        .is_some();
    if !skip_php_json_headers && is_json_response(&response) {
        apply_php_json_headers(&mut response);
    }
    response
}

fn normalize_static_content_type(response: &mut Response) {
    let Some(content_type) = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return;
    };
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let normalized = match media_type.as_str() {
        "text/html" => Some(HTML_CONTENT_TYPE),
        "text/css" => Some(CSS_CONTENT_TYPE),
        "text/javascript" => Some(JAVASCRIPT_CONTENT_TYPE),
        "image/x-icon" => Some(ICON_CONTENT_TYPE),
        _ => None,
    };
    if let Some(value) = normalized {
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static(value));
    }
}

fn is_json_response(response: &Response) -> bool {
    response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_ascii_lowercase().starts_with("application/json"))
}

fn apply_php_json_headers(response: &mut Response) {
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(PHP_JSON_CONTENT_TYPE),
    );
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
        .headers_mut()
        .insert("x-frame-options", HeaderValue::from_static("DENY"));
    response
        .headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    response.headers_mut().insert(
        "permissions-policy",
        HeaderValue::from_static(PHP_JSON_PERMISSIONS_POLICY),
    );
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(PHP_JSON_CONTENT_SECURITY_POLICY),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(PHP_JSON_CACHE_CONTROL),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response.headers_mut().insert(
        "access-control-allow-methods",
        HeaderValue::from_static(PHP_JSON_CORS_METHODS),
    );
    response.headers_mut().insert(
        "access-control-allow-headers",
        HeaderValue::from_static(PHP_JSON_CORS_HEADERS),
    );
}

async fn dispatch(
    State(state): State<AppState>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Query(query): Query<RouteQuery>,
    body: Bytes,
) -> Result<Response, AppError> {
    dispatch_api_request(state, address, method, headers, query, body, None).await
}

async fn dispatch_path_info(
    State(state): State<AppState>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Path(path_info): Path<String>,
    Query(query): Query<RouteQuery>,
    body: Bytes,
) -> Result<Response, AppError> {
    dispatch_api_request(
        state,
        address,
        method,
        headers,
        query,
        body,
        Some(path_info),
    )
    .await
}

async fn dispatch_api_request(
    state: AppState,
    address: SocketAddr,
    method: Method,
    headers: HeaderMap,
    query: RouteQuery,
    body: Bytes,
    path_info: Option<String>,
) -> Result<Response, AppError> {
    let route = resolved_api_route(query.route.as_deref(), path_info.as_deref());
    let response = match route.as_str() {
        "/health" => api_health().await.into_response(),
        CLOUD_DOWNLOAD_ROUTE => {
            return cloud_download_response(&state, &method, &query, address).await;
        }
        route if should_short_circuit_api_options(route, &method, &headers) => {
            api_options().await.into_response()
        }
        route if !valid_route(route) => return Err(AppError::InvalidRoute),
        CARD_QUERY_ROUTE => dispatch_card_query(state, method, headers, body)
            .await?
            .into_response(),
        CLOUD_UPLOAD_ROUTE => dispatch_admin_upload(state, method, headers, body, address)
            .await?
            .into_response(),
        route if route.starts_with("/admin/") => {
            dispatch_admin(state, route, method, headers, body, address)
                .await?
                .into_response()
        }
        route if route.starts_with("/remote/") => {
            dispatch_remote(state, route, method, headers, body, address)
                .await?
                .into_response()
        }
        route if CLIENT_ROUTES.contains(&route) => {
            dispatch_client(state, route, method, headers, body, address)
                .await?
                .into_response()
        }
        _ => return Err(AppError::InvalidRoute),
    };
    Ok(response)
}

fn should_short_circuit_api_options(route: &str, method: &Method, headers: &HeaderMap) -> bool {
    method == Method::OPTIONS
        && route != "/health"
        && route != CLOUD_DOWNLOAD_ROUTE
        && !is_plain_client_request(route, headers)
}

async fn cloud_download_entry(
    State(state): State<AppState>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    method: Method,
    Query(query): Query<RouteQuery>,
) -> Result<Response, AppError> {
    cloud_download_response(&state, &method, &query, address).await
}

async fn csp_report(method: Method, body: Bytes) -> Response {
    if method != Method::POST {
        return csp_report_json_response(
            StatusCode::METHOD_NOT_ALLOWED,
            CSP_REPORT_METHOD_ERROR_BODY,
        );
    }
    if !valid_csp_report_body(&body) {
        return csp_report_json_response(StatusCode::BAD_REQUEST, CSP_REPORT_INVALID_BODY);
    }
    tracing::warn!("CSP violation report accepted");
    csp_report_no_content_response()
}

fn valid_csp_report_body(body: &[u8]) -> bool {
    let Ok(Value::Object(payload)) = serde_json::from_slice::<Value>(body) else {
        return false;
    };
    matches!(payload.get("csp-report"), Some(Value::Object(_)))
}

fn csp_report_json_response(status: StatusCode, body: &'static str) -> Response {
    let mut response = (status, body).into_response();
    apply_csp_report_headers(&mut response);
    response
}

fn csp_report_no_content_response() -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    apply_csp_report_headers(&mut response);
    response
}

fn apply_csp_report_headers(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(CSP_REPORT_CONTENT_TYPE),
    );
    headers.insert(
        "access-control-allow-origin",
        HeaderValue::from_static(CSP_REPORT_ALLOW_ORIGIN),
    );
    headers.insert(
        "access-control-allow-methods",
        HeaderValue::from_static(CSP_REPORT_ALLOW_METHODS),
    );
    headers.insert(
        "access-control-allow-headers",
        HeaderValue::from_static(CSP_REPORT_ALLOW_HEADERS),
    );
    headers.insert(
        "x-frame-options",
        HeaderValue::from_static(CSP_REPORT_X_FRAME_OPTIONS),
    );
    headers.insert(
        "x-xss-protection",
        HeaderValue::from_static(CSP_REPORT_X_XSS_PROTECTION),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        "referrer-policy",
        HeaderValue::from_static(CSP_REPORT_REFERRER_POLICY),
    );
    headers.insert(
        "feature-policy",
        HeaderValue::from_static(CSP_REPORT_FEATURE_POLICY),
    );
    headers.insert(SKIP_PHP_JSON_HEADERS, HeaderValue::from_static("1"));
}

async fn cloud_download_response(
    state: &AppState,
    method: &Method,
    query: &RouteQuery,
    address: SocketAddr,
) -> Result<Response, AppError> {
    if !matches!(*method, Method::GET | Method::POST) {
        return Err(AppError::MethodNotAllowed);
    }
    let ip = address.ip().to_string();
    let file = cloud_download_file_from_query(state, query, &ip).await?;
    let config = cloud_config_for_file(state, &file).await?;
    state
        .repository
        .touch_cloud_file_download(file.id, &ip, Local::now().naive_local())
        .await?;
    if file.provider == CLOUD_PROVIDER_LOCAL {
        return local_cloud_download_response(&file).await;
    }
    let location = temporary_download_url(&config, &file.object_key, &state.system_key)?;
    Ok(redirect_found_response(&location, Vec::new()))
}

async fn cloud_download_file_from_query(
    state: &AppState,
    query: &RouteQuery,
    ip: &str,
) -> Result<CloudFileRow, AppError> {
    let ticket = query.ticket.as_deref().unwrap_or_default().trim();
    let file_key = if ticket.is_empty() {
        let file_key = cloud_file_key(query.file_key.as_deref().unwrap_or_default())?;
        assert_cloud_download_token(
            state,
            query.download_token.as_deref().unwrap_or_default(),
            ip,
        )
        .await?;
        file_key
    } else {
        cloud_file_key_from_download_ticket(ticket, &state.system_key)?
    };
    require_cloud_file_by_key(state, &file_key).await
}

async fn assert_cloud_download_token(
    state: &AppState,
    token: &str,
    ip: &str,
) -> Result<(), AppError> {
    let row = state
        .repository
        .find_cloud_download_token()
        .await?
        .ok_or(AppError::CloudDownloadTokenDisabled)?;
    if row.status != 1 || row.token_hash.trim().is_empty() {
        return Err(AppError::CloudDownloadTokenDisabled);
    }
    let token_hash = download_token_hash(token, &state.system_key)?;
    if !constant_eq(row.token_hash.trim(), &token_hash) {
        return Err(AppError::CloudDownloadTokenInvalid);
    }
    state
        .repository
        .touch_cloud_download_token(ip, Local::now().naive_local())
        .await
}

fn cloud_file_key_from_download_ticket(ticket: &str, system_key: &str) -> Result<String, AppError> {
    let json = crypto::decrypt_protected_text(ticket, system_key)
        .map_err(|_| AppError::CryptoMessage(CLOUD_DOWNLOAD_CRYPTO_FORMAT_MESSAGE))?;
    let payload: Value =
        serde_json::from_str(&json).map_err(|_| AppError::CloudDownloadTicketInvalid)?;
    let Value::Object(values) = payload else {
        return Err(AppError::CloudDownloadTicketInvalid);
    };
    let expires_at = values.get("exp").and_then(value_i64).unwrap_or_default();
    if expires_at < Local::now().timestamp() {
        return Err(AppError::CloudDownloadTicketInvalid);
    }
    let file_key = values
        .get("file_key")
        .map(php_scalar_string)
        .unwrap_or_default();
    cloud_file_key(&file_key)
}

fn value_i64(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => number.as_i64(),
        Value::String(text) => text.trim().parse::<i64>().ok(),
        _ => None,
    }
}

async fn require_cloud_file_by_key(
    state: &AppState,
    file_key: &str,
) -> Result<CloudFileRow, AppError> {
    state
        .repository
        .find_cloud_file_by_key(file_key)
        .await?
        .filter(|file| file.status == CLOUD_FILE_STATUS_ACTIVE)
        .ok_or(AppError::CloudFileUnavailable)
}

async fn cloud_config_for_file(
    state: &AppState,
    file: &CloudFileRow,
) -> Result<CloudStorageConfigRow, AppError> {
    let config = if let Some(config_id) = file.config_id {
        state
            .repository
            .find_cloud_storage_config_by_id(config_id)
            .await?
    } else {
        None
    };
    if let Some(config) = config {
        return Ok(config);
    }
    state
        .repository
        .find_cloud_storage_config_by_provider(&file.provider)
        .await?
        .ok_or(AppError::CloudFileStorageConfigMissing)
}

async fn local_cloud_download_response(file: &CloudFileRow) -> Result<Response, AppError> {
    let path = local_object_path(&file.object_key)?;
    if !path.is_file() {
        return Err(AppError::CloudFileUnreadable);
    }
    let content = fs::read(path)
        .await
        .map_err(|_| AppError::CloudFileUnreadable)?;
    let content_length = content.len().to_string();
    let mut response = Response::new(Body::from(content));
    *response.status_mut() = StatusCode::OK;
    let mime_type = local_cloud_download_content_type(&file.mime_type);
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&mime_type)
            .map_err(|_| AppError::InvalidInput("文件 MIME 格式错误"))?,
    );
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&content_length)
            .map_err(|_| AppError::InvalidInput("文件大小格式错误"))?,
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!(
            "attachment; filename*=UTF-8''{}",
            raw_url_encode(&file.original_name)
        ))
        .map_err(|_| AppError::InvalidInput("文件名格式错误"))?,
    );
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store, max-age=0"),
    );
    Ok(response)
}

fn constant_eq(left: &str, right: &str) -> bool {
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

fn raw_url_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn local_cloud_download_content_type(value: &str) -> String {
    let content_type = value.trim();
    if content_type.is_empty() {
        return "application/octet-stream".to_string();
    }
    let normalized = content_type.to_ascii_lowercase();
    if normalized.starts_with("text/") && !normalized.contains("charset=") {
        return format!("{content_type};charset=UTF-8");
    }
    content_type.to_string()
}

async fn api_health() -> Json<SuccessResponse<serde_json::Value>> {
    success(json!({
        "service": "auth-service",
        "status": "ok"
    }))
}

async fn health() -> Json<SuccessResponse<serde_json::Value>> {
    success(json!({
        "service": "auth-service",
        "status": "ok",
        "runtime": "rust"
    }))
}

async fn create_admin_session(
    State(state): State<AppState>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let secure = is_https_request(&headers);
    let Some(cookie) = cookie_value(&headers, admin_cookie_name()) else {
        return Err(AppError::AdminLoginRequired);
    };
    let mut session = match state
        .admin_session_service
        .create_trusted_from_cookie(cookie, &address.ip().to_string())
        .await
    {
        Ok(session) => session,
        Err(AppError::AdminLoginRequired) => {
            return Ok(error_with_cookies(
                AppError::AdminLoginRequired,
                expired_admin_cookie_headers(secure),
            ));
        }
        Err(error) => return Err(error),
    };
    session.demo_mode = state.demo_mode;
    Ok(success(session).into_response())
}

async fn install_entry(
    State(state): State<AppState>,
    method: Method,
    Query(query): Query<InstallQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    Ok(install_response(&state, &headers, &method, query.step.as_deref(), &body).await)
}

async fn install_legacy_redirect(uri: Uri) -> Response {
    let location = uri
        .query()
        .filter(|query| !query.is_empty())
        .map(|query| format!("/install/?{query}"))
        .unwrap_or_else(|| "/install/".to_string());
    redirect_found_response(&location, Vec::new())
}

async fn public_fallback(State(_state): State<AppState>, uri: Uri) -> Response {
    let path = uri.path();
    if path.starts_with("/install/") && !path_contains_extension(path) {
        return install_response(
            &_state,
            &HeaderMap::new(),
            &Method::GET,
            install_query_step(uri.query()).as_deref(),
            &[],
        )
        .await;
    }
    if should_redirect_unknown_public_path(path) {
        return redirect_found_response("/admin/console/", Vec::new());
    }
    fallback_not_found_response()
}

async fn install_response(
    state: &AppState,
    headers: &HeaderMap,
    method: &Method,
    query_step: Option<&str>,
    body: &[u8],
) -> Response {
    let secure = is_https_request(headers);
    let mut session = install_session_from_cookie(state, headers);
    ensure_install_csrf(&mut session);
    let form = parse_urlencoded_form(body);
    if *method == Method::POST {
        return install_post_response(state, secure, query_step, form, session).await;
    }
    install_page_response(
        query_step,
        InstallForm::empty(),
        Vec::new(),
        session,
        secure,
        &state.system_key,
    )
}

async fn install_post_response(
    state: &AppState,
    secure: bool,
    query_step: Option<&str>,
    form: HashMap<String, String>,
    session: InstallSession,
) -> Response {
    let action = form.get("action").map(String::as_str).unwrap_or("");
    let submitted_csrf = form.get("csrf_token").map(String::as_str).unwrap_or("");
    if submitted_csrf.is_empty()
        || session.csrf_token.is_empty()
        || !constant_eq(submitted_csrf, &session.csrf_token)
    {
        return install_page_response(
            query_step,
            InstallForm::from_raw(action, &form),
            vec!["请求验证失败，请刷新页面重试。".to_string()],
            session,
            secure,
            &state.system_key,
        );
    }

    if action == "save_database" {
        return install_save_database_response(state, query_step, form, session, secure).await;
    }
    if action == "install_system" {
        return install_system_response(state, query_step, form, session, secure).await;
    }
    install_page_response(
        query_step,
        InstallForm::from_raw(action, &form),
        vec!["安装动作无效。".to_string()],
        session,
        secure,
        &state.system_key,
    )
}

async fn install_system_response(
    state: &AppState,
    query_step: Option<&str>,
    form: HashMap<String, String>,
    mut session: InstallSession,
    secure: bool,
) -> Response {
    let database = match session.database.as_ref() {
        Some(database) => InstallDatabaseConfig {
            host: database.host.clone(),
            port: database.port,
            username: database.username.clone(),
            password: database.password.clone(),
            database_name: database.database_name.clone(),
        },
        None => {
            return install_page_response(
                query_step,
                InstallForm::from_raw("install_system", &form),
                vec!["请先完成数据库配置。".to_string()],
                session,
                secure,
                &state.system_key,
            );
        }
    };
    let admin = match normalize_admin_account(
        form.get("username").map(String::as_str).unwrap_or(""),
        form.get("password").map(String::as_str).unwrap_or(""),
        form.get("confirm_password")
            .map(String::as_str)
            .unwrap_or(""),
    ) {
        Ok(admin) => admin,
        Err(error) => {
            return install_page_response(
                query_step,
                InstallForm::from_raw("install_system", &form),
                vec![error.to_string()],
                session,
                secure,
                &state.system_key,
            );
        }
    };
    let paths = InstallSystemPaths {
        config_file: (*state.config_file).clone(),
        schema_file: (*state.schema_file).clone(),
        lock_file: (*state.install_lock_file).clone(),
    };
    let preferred_strategy = match session
        .id_strategy
        .as_deref()
        .map(id_strategy_from_name)
        .transpose()
    {
        Ok(strategy) => strategy,
        Err(error) => {
            return install_page_response(
                query_step,
                InstallForm::from_raw("install_system", &form),
                vec![error.to_string()],
                session,
                secure,
                &state.system_key,
            );
        }
    };
    let result = match run_system_install_with_strategy(
        &paths,
        &database,
        session.create_database,
        &admin,
        preferred_strategy,
    )
    .await
    {
        Ok(result) => result,
        Err(error) => {
            return install_page_response(
                query_step,
                InstallForm::from_raw("install_system", &form),
                vec![error.to_string()],
                session,
                secure,
                &state.system_key,
            );
        }
    };
    session.id_strategy = Some(id_strategy_name(result.id_strategy).to_string());
    session.result = Some(InstallResultSession {
        config_file: result.config_file,
        statement_count: result.statement_count,
        admin_username: result.admin_username,
        admin_token: result.admin_token,
    });
    redirect_see_other_response(
        "/install/?step=done",
        vec![install_session_cookie(&session, secure, &state.system_key)],
    )
}

async fn install_save_database_response(
    state: &AppState,
    query_step: Option<&str>,
    form: HashMap<String, String>,
    mut session: InstallSession,
    secure: bool,
) -> Response {
    let create_database = form.contains_key("create_database");
    let database = match install_database_from_form(&form) {
        Ok(database) => database,
        Err(error) => {
            return install_page_response(
                query_step,
                InstallForm::database(&form, create_database),
                vec![error.to_string()],
                session,
                secure,
                &state.system_key,
            );
        }
    };
    let preferred_strategy = match id_strategy_from_php_config(&state.config_file) {
        Ok(strategy) => strategy,
        Err(error) => {
            return install_page_response(
                query_step,
                InstallForm::database(&form, create_database),
                vec![error.to_string()],
                session,
                secure,
                &state.system_key,
            );
        }
    };
    let id_strategy = match prepare_database_with_strategy(
        &database,
        create_database,
        preferred_strategy,
    )
    .await
    {
        Ok(strategy) => strategy,
        Err(error) => {
            return install_page_response(
                query_step,
                InstallForm::database(&form, create_database),
                vec![error.to_string()],
                session,
                secure,
                &state.system_key,
            );
        }
    };
    session.database = Some(InstallDatabaseSession::from(&database));
    session.create_database = create_database;
    session.id_strategy = Some(id_strategy_name(id_strategy).to_string());
    session.result = None;
    redirect_see_other_response(
        "/install/?step=admin",
        vec![install_session_cookie(&session, secure, &state.system_key)],
    )
}

fn install_page_response(
    query_step: Option<&str>,
    form: InstallForm,
    errors: Vec<String>,
    mut session: InstallSession,
    secure: bool,
    system_key: &str,
) -> Response {
    ensure_install_csrf(&mut session);
    let html = render_install_page(query_step, form, &errors, &session);
    install_html_response(html_with_cookies(
        html,
        vec![install_session_cookie(&session, secure, system_key)],
    ))
}

fn render_install_page(
    query_step: Option<&str>,
    form: InstallForm,
    errors: &[String],
    session: &InstallSession,
) -> String {
    let step = install_current_step(query_step, &form, session);
    let mascot = install_mascot_scene(step, !errors.is_empty());
    format!(
        r#"<!doctype html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>安装向导 - 授权管理系统</title>
    <link rel="stylesheet" href="/install/install.css?v=20260608-beian-footer">
</head>
<body>
    <div class="install-shell">
        <aside class="install-side">
            {step_list}
            <div class="install-mascot" aria-hidden="true"><img src="{mascot_image}" alt="" class="mascot-img" fetchpriority="high"><span>{mascot_text}</span></div>
        </aside>
        <main class="install-main"><section class="install-card">{content}</section></main>
    </div>
</body>
</html>"#,
        step_list = render_install_step_list(step),
        mascot_image = mascot.image,
        mascot_text = mascot.text,
        content = render_install_step(step, &form, errors, session),
    )
}

fn install_query_step(query: Option<&str>) -> Option<String> {
    let query = query?;
    form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| key == "step")
        .map(|(_, value)| value.into_owned())
}

fn install_current_step(
    query_step: Option<&str>,
    form: &InstallForm,
    session: &InstallSession,
) -> &'static str {
    if form.submitted {
        return if form.action == "install_system" {
            "admin"
        } else {
            "database"
        };
    }
    match query_step.unwrap_or("env") {
        "database" => "database",
        "admin" => {
            if session.database.is_some() {
                "admin"
            } else {
                "database"
            }
        }
        "done" => {
            if session.result.is_some() {
                "done"
            } else {
                "env"
            }
        }
        "env" => "env",
        _ => "env",
    }
}

struct InstallMascotScene {
    image: &'static str,
    text: &'static str,
}

fn install_mascot_scene(step: &str, post_failed: bool) -> InstallMascotScene {
    if step == "database" && post_failed {
        return InstallMascotScene {
            image: "/frontend/admin-console/js/img/database-error.webp",
            text: "数据库连接还有点问题，检查一下配置再继续",
        };
    }
    match step {
        "database" => InstallMascotScene {
            image: "/frontend/admin-console/js/img/database-config.webp",
            text: "把数据库连好，后面的初始化就会顺很多",
        },
        "admin" => InstallMascotScene {
            image: "/frontend/admin-console/js/img/admin-account.webp",
            text: "设置第一个管理员账号，后台就能正式启用了",
        },
        "done" => InstallMascotScene {
            image: "/frontend/admin-console/js/img/install-complete.webp",
            text: "安装完成，准备进入你的后台管理端",
        },
        _ => InstallMascotScene {
            image: "/frontend/admin-console/js/img/install-welcome.webp",
            text: "先检查环境，我们一步一步把系统装好",
        },
    }
}

fn render_install_step_list(active_step: &str) -> String {
    [("env", "环境检查"), ("database", "数据库配置"), ("admin", "管理员账号"), ("done", "安装完成")]
        .iter()
        .enumerate()
        .map(|(index, (step, label))| {
            let active = if active_step == *step { " active" } else { "" };
            format!(
                r#"<div class="step-item{active}"><span class="step-index">{}</span><span>{}</span></div>"#,
                index + 1,
                label
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_install_step(
    step: &str,
    form: &InstallForm,
    errors: &[String],
    session: &InstallSession,
) -> String {
    match step {
        "database" => render_install_database_step(form, errors, session),
        "admin" => render_install_admin_step(errors, &session.csrf_token),
        "done" => render_install_done_step(session.result.as_ref()),
        _ => render_install_env_step(),
    }
}

fn render_install_errors(errors: &[String]) -> String {
    if errors.is_empty() {
        return String::new();
    }
    let items = errors
        .iter()
        .map(|error| format!("<div>{}</div>", escape_install_html(error)))
        .collect::<Vec<_>>()
        .join("");
    format!(r#"<div class="error-box">{items}</div>"#)
}

fn render_install_env_step() -> String {
    r#"<div class="card-head"><h1>环境检查</h1><p>安装向导会检查运行环境、写入配置文件、初始化数据库表，并创建第一个后台管理员。</p></div><div class="card-body"><div class="check-grid"><div class="check-item"><strong>Rust 后端</strong><span>可用</span></div><div class="check-item"><strong>配置读取</strong><span>可用</span></div></div><div class="action-row"><span></span><a class="layui-btn layui-btn-normal" href="/install/?step=database">开始安装</a></div></div>"#.to_string()
}

fn render_install_database_step(
    form: &InstallForm,
    errors: &[String],
    session: &InstallSession,
) -> String {
    let checked = if form.submitted {
        form.create_database
    } else {
        session.create_database
    };
    let checked = if checked { " checked" } else { "" };
    format!(
        r#"<div class="card-head"><h1>数据库配置</h1><p>填写 MySQL 连接信息，支持本机、内网和远程云数据库。连接测试超时时间为 5 秒。</p></div><div class="card-body">{errors}<form method="post" autocomplete="off">{hidden}<div class="form-grid"><label><span>数据库地址</span><input class="layui-input" name="host" value="{host}" required></label><label><span>端口</span><input class="layui-input" name="port" value="{port}" required inputmode="numeric"></label><label><span>数据库名</span><input class="layui-input" name="dbname" value="{dbname}" required></label><label><span>数据库用户</span><input class="layui-input" name="user" value="{user}" required autocomplete="username"></label><label class="wide"><span>数据库密码</span><input class="layui-input" type="password" name="pwd" autocomplete="new-password"></label><label class="wide"><input type="checkbox" name="create_database" value="1"{checked}> 数据库不存在时自动创建，需要当前数据库账号拥有 CREATE 权限</label></div><div class="action-row"><a class="layui-btn layui-btn-primary" href="/install/?step=env">上一步</a><button class="layui-btn layui-btn-normal" type="submit">测试并继续</button></div></form></div>"#,
        errors = render_install_errors(errors),
        hidden = render_install_hidden_fields("save_database", &session.csrf_token),
        host = install_database_value(form, session, "host", "127.0.0.1"),
        port = install_database_value(form, session, "port", "3306"),
        dbname = install_database_value(form, session, "dbname", ""),
        user = install_database_value(form, session, "user", ""),
        checked = checked,
    )
}

fn render_install_admin_step(errors: &[String], csrf_token: &str) -> String {
    format!(
        r#"<div class="card-head"><h1>管理员账号</h1><p>创建第一个后台管理员。系统密钥和后台维护令牌会在安装时自动生成，无需手动配置。</p></div><div class="card-body">{errors}<form method="post" autocomplete="off">{hidden}<div class="form-grid"><label class="wide"><span>管理员账号</span><input class="layui-input" name="username" value="admin" required autocomplete="username"></label><label><span>登录密码</span><input class="layui-input" type="password" name="password" required autocomplete="new-password"></label><label><span>确认密码</span><input class="layui-input" type="password" name="confirm_password" required autocomplete="new-password"></label></div><div class="action-row"><a class="layui-btn layui-btn-primary" href="/install/?step=database">上一步</a><button class="layui-btn layui-btn-normal" type="submit">安装系统</button></div></form></div>"#,
        errors = render_install_errors(errors),
        hidden = render_install_hidden_fields("install_system", csrf_token),
    )
}

fn render_install_done_step(result: Option<&InstallResultSession>) -> String {
    let Some(result) = result else {
        return render_install_env_step();
    };
    format!(
        r#"<div class="card-head"><h1>安装完成</h1><p>授权管理系统已经完成初始化。后台维护令牌只显示一次，前端管理端不会要求输入。</p></div><div class="card-body"><div class="result-list"><div class="result-row"><strong>配置文件</strong><code>{}</code></div><div class="result-row"><strong>数据库语句</strong><span>{} 条</span></div><div class="result-row"><strong>管理员账号</strong><span>{}</span></div><div class="result-row"><strong>后台维护令牌</strong><code>{}</code></div></div><div class="action-row"><a class="layui-btn layui-btn-primary" href="/admin/login/">进入后台登录</a><a class="layui-btn layui-btn-normal" href="/admin/console/">登录后进入管理端</a></div></div>"#,
        escape_install_html(&result.config_file),
        result.statement_count,
        escape_install_html(result.admin_username.as_deref().unwrap_or("已存在，未覆盖")),
        escape_install_html(
            result
                .admin_token
                .as_deref()
                .unwrap_or("已存在，未重新生成")
        ),
    )
}

fn render_install_hidden_fields(action: &str, csrf_token: &str) -> String {
    format!(
        r#"<input type="hidden" name="action" value="{}"><input type="hidden" name="csrf_token" value="{}">"#,
        escape_install_html(action),
        escape_install_html(csrf_token)
    )
}

fn install_database_value(
    form: &InstallForm,
    session: &InstallSession,
    key: &str,
    default_value: &str,
) -> String {
    if let Some(value) = form.database.get(key) {
        return escape_install_html(value);
    }
    let value = session
        .database
        .as_ref()
        .and_then(|database| database.value(key))
        .unwrap_or_else(|| default_value.to_string());
    escape_install_html(&value)
}

fn install_database_from_form(
    form: &HashMap<String, String>,
) -> Result<InstallDatabaseConfig, crate::install::InstallError> {
    normalize_database_config(
        form.get("host").map(String::as_str).unwrap_or("127.0.0.1"),
        form.get("port").map(String::as_str).unwrap_or("3306"),
        form.get("user").map(String::as_str).unwrap_or(""),
        form.get("pwd").map(String::as_str).unwrap_or(""),
        form.get("dbname").map(String::as_str).unwrap_or(""),
    )
}

fn install_session_from_cookie(state: &AppState, headers: &HeaderMap) -> InstallSession {
    let Some(cookie) = cookie_value(headers, INSTALL_SESSION_COOKIE) else {
        return InstallSession::default();
    };
    let Ok(plaintext) = crypto::decrypt_protected_text(cookie, &state.system_key) else {
        return InstallSession::default();
    };
    serde_json::from_str::<InstallSession>(&plaintext).unwrap_or_default()
}

fn ensure_install_csrf(session: &mut InstallSession) {
    if session.csrf_token.is_empty() {
        session.csrf_token = crypto::sha256_hex(&crypto::token(32));
    }
}

fn install_session_cookie(session: &InstallSession, secure: bool, system_key: &str) -> String {
    let plaintext = serde_json::to_string(session).expect("install session serialization");
    let value =
        crypto::encrypt_protected_text(&plaintext, system_key).expect("install session encryption");
    persistent_install_cookie(INSTALL_SESSION_COOKIE, &value, secure)
}

fn persistent_install_cookie(name: &str, value: &str, secure: bool) -> String {
    let mut cookie = format!(
        "{name}={value}; Path=/; Max-Age={INSTALL_SESSION_TTL_SECONDS}; HttpOnly; SameSite=Strict"
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

fn redirect_see_other_response(location: &str, cookies: Vec<String>) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::SEE_OTHER;
    response
        .headers_mut()
        .insert(header::LOCATION, location.parse().expect("valid redirect"));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(HTML_CONTENT_TYPE),
    );
    response_with_cookies(response, cookies)
}

fn id_strategy_name(strategy: IdStrategy) -> &'static str {
    match strategy {
        IdStrategy::AutoIncrement => "auto_increment",
        IdStrategy::UuidShortDefault => "uuid_short_default",
    }
}

fn escape_install_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#039;")
}

fn should_redirect_unknown_public_path(path: &str) -> bool {
    !path_contains_extension(path)
        && !path.starts_with("/api/")
        && !path.starts_with("/assets/")
        && !path.starts_with("/frontend/")
        && !path.starts_with("/sub_admin/")
}

fn path_contains_extension(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .is_some_and(|segment| segment.contains('.'))
}

fn fallback_not_found_response() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

async fn admin_index_redirect() -> Response {
    redirect_found_response("/admin/console/", Vec::new())
}

async fn admin_remote_api_redirect() -> Response {
    redirect_found_response("/admin/console/#remoteApi", Vec::new())
}

async fn admin_remote_api_logs_redirect() -> Response {
    redirect_found_response("/admin/console/#remoteApiLogs", Vec::new())
}

async fn admin_login_get(
    State(state): State<AppState>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    Query(query): Query<LoginQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let secure = is_https_request(&headers);
    let admin_cookie_state = admin_cookie_authentication(&state, &headers).await;
    let admin_cookie_expiration_headers =
        invalid_admin_cookie_expiration_headers(admin_cookie_state, secure);
    if query.logout.is_some() {
        let redirect = state
            .login_service
            .logout(cookie_value(&headers, admin_cookie_name()), secure)
            .await?;
        if wants_ajax_json(&headers) {
            return Ok(json_with_cookies(redirect.body, redirect.cookies));
        }
        return Ok(login_redirect_found_response(
            redirect.location,
            redirect.cookies,
        ));
    }
    if query.forget_remember.is_some() {
        let mut cookies = admin_cookie_expiration_headers;
        cookies.extend(
            state
                .login_service
                .forget_remember_login(cookie_value(&headers, remember_cookie_name()), secure)
                .await?,
        );
        return Ok(login_redirect_found_response("/admin/login/", cookies));
    }
    if query.slider.as_deref() == Some("image") {
        let image = state
            .login_service
            .slider_image(
                &state.public_root,
                query.image.as_deref(),
                query.version.as_deref(),
            )
            .await?;
        return Ok(response_with_cookies(
            slider_image_response(image),
            admin_cookie_expiration_headers,
        ));
    }
    if query.slider.as_deref() == Some("challenge") {
        let response = state
            .login_service
            .issue_slider_challenge(
                cookie_value(&headers, login_state_cookie_name()),
                secure,
                &state.public_root,
            )
            .await?;
        return Ok(json_with_cookies(
            response.body,
            [admin_cookie_expiration_headers, response.cookies].concat(),
        ));
    }
    if admin_cookie_state == AdminCookieAuthentication::Authenticated {
        return Ok(login_redirect_found_response("/admin/console/", Vec::new()));
    }
    let restored = state
        .login_service
        .restore_remembered_login(
            cookie_value(&headers, remember_cookie_name()),
            &address.ip().to_string(),
            secure,
        )
        .await?;
    if restored.restored {
        return Ok(login_redirect_found_response(
            "/admin/console/",
            [admin_cookie_expiration_headers, restored.cookies].concat(),
        ));
    }
    let page = state
        .login_service
        .render_login_page(cookie_value(&headers, login_state_cookie_name()), secure)
        .await?;
    Ok(login_html_with_cookies(
        page.html,
        [
            admin_cookie_expiration_headers,
            restored.cookies,
            page.cookies,
        ]
        .concat(),
    ))
}

async fn admin_login_post(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let secure = is_https_request(&headers);
    let form = parse_urlencoded_form(&body);
    let admin_cookie_state = admin_cookie_authentication(&state, &headers).await;
    let admin_cookie_expiration_headers =
        invalid_admin_cookie_expiration_headers(admin_cookie_state, secure);
    let response = if query.slider.as_deref() == Some("verify") {
        state.login_service.verify_slider(
            &form,
            cookie_value(&headers, login_state_cookie_name()),
            secure,
        )?
    } else {
        if admin_cookie_state == AdminCookieAuthentication::Authenticated {
            return Ok(login_redirect_found_response("/admin/console/", Vec::new()));
        }
        let restored = state
            .login_service
            .restore_remembered_login(
                cookie_value(&headers, remember_cookie_name()),
                &address.ip().to_string(),
                secure,
            )
            .await?;
        if restored.restored {
            return Ok(login_redirect_found_response(
                "/admin/console/",
                [admin_cookie_expiration_headers, restored.cookies].concat(),
            ));
        }
        if !has_login_credentials(&form) {
            let page = state
                .login_service
                .render_login_page(cookie_value(&headers, login_state_cookie_name()), secure)
                .await?;
            return Ok(login_html_with_cookies(
                page.html,
                [
                    admin_cookie_expiration_headers,
                    restored.cookies,
                    page.cookies,
                ]
                .concat(),
            ));
        }
        state
            .login_service
            .login(
                &form,
                cookie_value(&headers, login_state_cookie_name()),
                cookie_value(&headers, remember_cookie_name()),
                &address.ip().to_string(),
                secure,
            )
            .await?
    };
    Ok(json_with_cookies(
        response.body,
        [admin_cookie_expiration_headers, response.cookies].concat(),
    ))
}

async fn admin_console(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let admin_cookie_state = admin_cookie_authentication(&state, &headers).await;
    if admin_cookie_state != AdminCookieAuthentication::Authenticated {
        return Ok(admin_console_redirect_found_response(
            "/admin/login/",
            invalid_admin_cookie_expiration_headers(admin_cookie_state, is_https_request(&headers)),
        ));
    }
    let path = state
        .public_root
        .join("frontend")
        .join("admin-console")
        .join("index.html");
    let html = fs::read_to_string(path)
        .await
        .map_err(|_| AppError::StaticFileMissing("admin-console/index.html"))?;
    Ok(admin_console_html_response(Html(html).into_response()))
}

async fn legacy_admin_login_get(
    State(state): State<AppState>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    Query(query): Query<LoginQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if query.logout.is_some() {
        return admin_login_get(State(state), ConnectInfo(address), Query(query), headers).await;
    }
    Ok(login_redirect_found_response("/admin/login/", Vec::new()))
}

async fn legacy_admin_login_head(
    State(state): State<AppState>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    Query(query): Query<LoginQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    admin_login_get(State(state), ConnectInfo(address), Query(query), headers).await
}

async fn legacy_admin_index(State(state): State<AppState>, headers: HeaderMap) -> Response {
    legacy_admin_entry_redirect(&state, &headers).await
}

async fn legacy_admin_console(State(state): State<AppState>, headers: HeaderMap) -> Response {
    legacy_admin_entry_redirect(&state, &headers).await
}

async fn legacy_admin_foot() -> Response {
    let mut response = Html(LEGACY_ADMIN_FOOT_HTML).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(HTML_CONTENT_TYPE),
    );
    response
}

async fn legacy_admin_entry_redirect(state: &AppState, headers: &HeaderMap) -> Response {
    let admin_cookie_state = admin_cookie_authentication(state, headers).await;
    if admin_cookie_state == AdminCookieAuthentication::Authenticated {
        admin_console_redirect_found_response("/admin/console/", Vec::new())
    } else {
        admin_console_redirect_found_response(
            "/admin/login/",
            invalid_admin_cookie_expiration_headers(admin_cookie_state, is_https_request(headers)),
        )
    }
}

async fn admin_cookie_authentication(
    state: &AppState,
    headers: &HeaderMap,
) -> AdminCookieAuthentication {
    let Some(cookie) = cookie_value(headers, admin_cookie_name()) else {
        return AdminCookieAuthentication::Missing;
    };
    if state
        .admin_session_service
        .admin_username_from_cookie(cookie)
        .await
        .is_ok()
    {
        AdminCookieAuthentication::Authenticated
    } else {
        AdminCookieAuthentication::Invalid
    }
}

fn invalid_admin_cookie_expiration_headers(
    authentication: AdminCookieAuthentication,
    secure: bool,
) -> Vec<String> {
    if authentication == AdminCookieAuthentication::Invalid {
        return expired_admin_cookie_headers(secure);
    }
    Vec::new()
}

fn expired_admin_cookie_headers(secure: bool) -> Vec<String> {
    vec![
        expired_cookie_header(admin_cookie_name(), secure, "/"),
        expired_cookie_header(admin_cookie_name(), secure, "/sub_admin"),
    ]
}

fn expired_cookie_header(name: &str, secure: bool, path: &str) -> String {
    let secure_attribute = if secure { "; Secure" } else { "" };
    format!(
        "{name}=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:01 GMT; Path={path}; HttpOnly; SameSite=Strict{secure_attribute}"
    )
}

async fn admin_session_options() -> Json<SuccessResponse<serde_json::Value>> {
    success(json!({
        "allowed_methods": ["POST", "OPTIONS"]
    }))
}

async fn admin_session_method_not_allowed() -> Result<Response, AppError> {
    Err(AppError::MethodNotAllowed)
}

async fn api_options() -> Json<SuccessResponse<serde_json::Value>> {
    success(json!({
        "allowed_methods": ["GET", "POST", "OPTIONS"]
    }))
}

async fn dispatch_card_query(
    state: AppState,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<SuccessResponse<serde_json::Value>>, AppError> {
    assert_post_method(&method)?;
    assert_json_content_type(&headers)?;
    let payload = parse_client_payload(&body)?;
    let app_code = card_query_app_code(&payload, &headers);
    let app = state.client_service.load_app(&app_code).await?;
    let data = state.client_service.card_query(&app, &payload).await?;
    Ok(success(data))
}

async fn dispatch_client(
    state: AppState,
    route: &str,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
    address: SocketAddr,
) -> Result<Json<SuccessResponse<serde_json::Value>>, AppError> {
    assert_post_method(&method)?;
    assert_json_content_type(&headers)?;
    let app = state
        .client_service
        .load_app(optional_header(&headers, "x-app-code"))
        .await?;
    state.client_service.assert_api_access(
        &app,
        route,
        optional_header(&headers, "x-api-token"),
        optional_header(&headers, "x-api-call-id"),
    )?;
    let request_payload = parse_client_payload(&body)?;
    let is_plain_request = is_plain_client_request(route, &headers);
    let encrypted_context = if is_plain_request {
        assert_plain_client_payload(route, &request_payload)?;
        None
    } else {
        let (payload, context) = state.client_service.open_encrypted_request(
            &app,
            route,
            optional_header(&headers, "x-timestamp"),
            optional_header(&headers, "x-nonce"),
            &request_payload,
        )?;
        Some((payload, context))
    };
    let payload = encrypted_context
        .as_ref()
        .map(|(payload, _)| payload)
        .unwrap_or(&request_payload);
    let data = match route {
        "/login/challenge" => state.client_service.login_challenge(&app, payload)?,
        "/login" => {
            state
                .client_service
                .login(&app, payload, &address.ip().to_string())
                .await?
        }
        "/unbind" => {
            state
                .client_service
                .unbind(&app, payload, &address.ip().to_string())
                .await?
        }
        "/heartbeat" => state.client_service.heartbeat(&app, payload).await?,
        "/config" => state.client_service.config(&app, payload).await?,
        "/variable" => state.client_service.variable(&app, payload).await?,
        "/cloud/download-ticket" => {
            state
                .client_service
                .cloud_download_ticket(&app, payload)
                .await?
        }
        "/security/report" => {
            state
                .client_service
                .security_report(&app, payload, &address.ip().to_string())
                .await?
        }
        "/logout" => state.client_service.logout(&app, payload).await?,
        "/notice" => state.client_service.notice(&app).await?,
        _ => return Err(AppError::RouteNotFound),
    };
    let data = if let Some((_, context)) = encrypted_context.as_ref() {
        state.client_service.encrypt_client_response(
            route,
            optional_header(&headers, "x-timestamp"),
            optional_header(&headers, "x-nonce"),
            context,
            &data,
        )?
    } else {
        data
    };
    Ok(success_with_code(
        data,
        state.client_service.client_success_code(&app),
    ))
}

async fn dispatch_admin(
    state: AppState,
    route: &str,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
    address: SocketAddr,
) -> Result<Json<SuccessResponse<serde_json::Value>>, AppError> {
    assert_post_method(&method)?;
    assert_json_content_type(&headers)?;
    if route == "/admin/session/create" {
        let mut session = state
            .admin_session_service
            .create(
                optional_header(&headers, "x-admin-token"),
                &address.ip().to_string(),
            )
            .await?;
        session.demo_mode = state.demo_mode;
        return Ok(success(json!(session)));
    }
    if is_plain_demo_admin_request(&state, &headers) {
        assert_demo_admin_route_allowed(&state, route)?;
        let cookie =
            cookie_value(&headers, admin_cookie_name()).ok_or(AppError::AdminLoginRequired)?;
        let admin_username = state
            .admin_session_service
            .admin_username_from_cookie(cookie)
            .await?;
        let payload = parse_plain_admin_payload(&body)?;
        let context = AdminSessionContext {
            session_id: 0,
            key: Vec::new(),
            route: route.to_string(),
            nonce: String::new(),
            ip: address.ip().to_string(),
            admin_username,
            session_expires_at: String::new(),
            payload,
        };
        let data = state.admin_service.dispatch(route, &context).await?;
        return Ok(success(data));
    }
    let request = AdminSignedRequest {
        method: method.as_str(),
        route,
        session_token: required_header(&headers, "x-admin-session")?,
        timestamp: required_header(&headers, "x-timestamp")?,
        nonce: required_header(&headers, "x-nonce")?,
        signature: required_header(&headers, "x-signature")?,
        body: &body,
        ip: &address.ip().to_string(),
    };
    let context = state.admin_session_service.open(&request).await?;
    assert_demo_admin_route_allowed(&state, route)?;
    let data = state.admin_service.dispatch(route, &context).await?;
    let encrypted = state
        .admin_session_service
        .encrypt_response(&context, data)?;
    Ok(success(encrypted))
}

async fn dispatch_admin_upload(
    state: AppState,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
    address: SocketAddr,
) -> Result<Json<SuccessResponse<serde_json::Value>>, AppError> {
    assert_demo_admin_route_allowed(&state, CLOUD_UPLOAD_ROUTE)?;
    let session = state
        .admin_session_service
        .open_upload(
            admin_upload_session_token(&headers),
            &address.ip().to_string(),
        )
        .await?;
    assert_post_method(&method)?;
    let upload = parse_cloud_upload(&headers, body).await?;
    Ok(success(
        state
            .admin_service
            .upload_cloud_file(&session, upload)
            .await?,
    ))
}

async fn dispatch_remote(
    state: AppState,
    route: &str,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
    address: SocketAddr,
) -> Result<Json<SuccessResponse<serde_json::Value>>, AppError> {
    assert_post_method(&method)?;
    assert_json_content_type(&headers)?;
    let ip = address.ip().to_string();
    let request = RemoteApiRequest {
        method: method.as_str(),
        route,
        headers: &headers,
        body: body.as_ref(),
        ip: &ip,
    };
    let context = state.remote_api_service.authenticate(&request).await?;
    let payload = match parse_remote_payload(&body) {
        Ok(payload) => payload,
        Err(error) => {
            state
                .remote_api_service
                .record_context_failure(&context, &request, None, &error)
                .await;
            return Err(error);
        }
    };
    let target_app_id = match state.remote_api_service.target_app_id(&payload).await {
        Ok(target_app_id) => target_app_id,
        Err(error) => {
            state
                .remote_api_service
                .record_context_failure(&context, &request, None, &error)
                .await;
            return Err(error);
        }
    };
    let payload = remote_payload(payload, &context, &ip, target_app_id);
    let mut admin_context = AdminSessionContext {
        session_id: 0,
        key: Vec::new(),
        route: route.to_string(),
        nonce: String::new(),
        ip: ip.clone(),
        admin_username: context.actor_name.clone(),
        session_expires_at: String::new(),
        payload,
    };
    let data = if let Some(admin_route) = remote_admin_route(route) {
        if let Err(error) = apply_remote_payload_transform(
            &mut admin_context.payload,
            admin_route.transform,
            &state.remote_api_service,
        )
        .await
        {
            state
                .remote_api_service
                .record_context_failure(&context, &request, target_app_id, &error)
                .await;
            return Err(error);
        }
        admin_context.route = admin_route.admin_route.to_string();
        state
            .admin_service
            .dispatch(admin_route.admin_route, &admin_context)
            .await
    } else if let Some(transform) = remote_special_payload_transform(route) {
        if let Err(error) = apply_remote_payload_transform(
            &mut admin_context.payload,
            transform,
            &state.remote_api_service,
        )
        .await
        {
            state
                .remote_api_service
                .record_context_failure(&context, &request, target_app_id, &error)
                .await;
            return Err(error);
        }
        match state
            .admin_service
            .dispatch_remote_special(route, &admin_context)
            .await
        {
            Ok(Some(data)) => Ok(data),
            Ok(None) => Err(AppError::RemoteApiRouteNotFound),
            Err(error) => Err(error),
        }
    } else {
        state
            .remote_api_service
            .record_route_not_found(&context, &request)
            .await;
        return Err(AppError::RemoteApiRouteNotFound);
    };
    match data {
        Ok(data) => {
            state
                .remote_api_service
                .record_high_risk_audit(route, &context, target_app_id, &ip)
                .await;
            state
                .remote_api_service
                .record_success(&context, &request, target_app_id)
                .await;
            Ok(success(data))
        }
        Err(error) => {
            state
                .remote_api_service
                .record_context_failure(&context, &request, target_app_id, &error)
                .await;
            Err(error)
        }
    }
}

fn remote_admin_route(route: &str) -> Option<RemoteAdminRoute> {
    REMOTE_ADMIN_ROUTES
        .iter()
        .find_map(|(remote_route, admin_route)| (*remote_route == route).then_some(*admin_route))
}

fn remote_special_payload_transform(route: &str) -> Option<RemotePayloadTransform> {
    REMOTE_SPECIAL_ROUTES
        .iter()
        .find_map(|(remote_route, transform)| (*remote_route == route).then_some(*transform))
}

fn parse_remote_payload(body: &[u8]) -> Result<Value, AppError> {
    if body.is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    let value: Value = serde_json::from_slice(body).map_err(|_| AppError::RequestJsonInvalid)?;
    match value {
        Value::Object(_) => Ok(value),
        _ => Err(AppError::RequestJsonInvalid),
    }
}

fn parse_client_payload(body: &[u8]) -> Result<Value, AppError> {
    if body.len() > 65_536 {
        return Err(AppError::PayloadTooLarge);
    }
    if body.is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    match serde_json::from_slice::<Value>(body).map_err(|_| AppError::RequestJsonInvalid)? {
        Value::Object(values) => Ok(Value::Object(values)),
        Value::Array(values) => Ok(Value::Array(values)),
        _ => Err(AppError::RequestJsonInvalid),
    }
}

fn remote_payload(
    payload: Value,
    context: &crate::service::remote_api::RemoteApiContext,
    ip: &str,
    target_app_id: Option<u64>,
) -> Value {
    let Value::Object(mut values) = payload else {
        return Value::Object(Map::new());
    };
    insert_remote_payload_default(&mut values, "_client_ip", Value::String(ip.to_string()));
    insert_remote_payload_default(
        &mut values,
        "_admin_username",
        Value::String(context.actor_name.clone()),
    );
    insert_remote_payload_default(
        &mut values,
        "_remote_api_token_id",
        Value::Number(context.token_id.into()),
    );
    insert_remote_payload_default(
        &mut values,
        "_remote_api_access_key",
        Value::String(context.access_key.clone()),
    );
    values.insert(
        "_remote_target_app_id".to_string(),
        target_app_id
            .map(|app_id| Value::Number(app_id.into()))
            .unwrap_or(Value::Null),
    );
    Value::Object(values)
}

fn insert_remote_payload_default(values: &mut Map<String, Value>, key: &str, value: Value) {
    values.entry(key.to_string()).or_insert(value);
}

async fn apply_remote_payload_transform(
    payload: &mut Value,
    transform: RemotePayloadTransform,
    remote_api_service: &RemoteApiService,
) -> Result<(), AppError> {
    match transform {
        RemotePayloadTransform::None => Ok(()),
        RemotePayloadTransform::AppId => {
            if remote_payload_positive_id(payload, "app_id").is_none() {
                let app_id = remote_api_service.require_app_id(payload).await?;
                remote_payload_insert(payload, "app_id", Value::Number(app_id.into()));
            }
            Ok(())
        }
        RemotePayloadTransform::AppCode => {
            if remote_payload_text(payload, "app_code").is_empty() {
                let app_code = remote_api_service.require_app_code(payload).await?;
                remote_payload_insert(payload, "app_code", Value::String(app_code));
            }
            Ok(())
        }
        RemotePayloadTransform::AppIds | RemotePayloadTransform::AppIdsFromCodes => {
            if let Some(app_codes) = payload.get("app_codes").cloned() {
                let app_ids = remote_api_service.app_ids_from_codes(&app_codes).await?;
                remote_payload_insert(
                    payload,
                    "app_ids",
                    Value::Array(
                        app_ids
                            .into_iter()
                            .map(|app_id| Value::Number(app_id.into()))
                            .collect(),
                    ),
                );
            }
            Ok(())
        }
    }
}

fn remote_payload_insert(payload: &mut Value, key: &str, value: Value) {
    if let Value::Object(values) = payload {
        values.insert(key.to_string(), value);
    }
}

fn remote_payload_positive_id(payload: &Value, key: &str) -> Option<u64> {
    payload
        .get(key)
        .and_then(|value| match value {
            Value::Number(number) => number.as_u64(),
            Value::String(text) => text.trim().parse::<u64>().ok(),
            _ => None,
        })
        .filter(|value| *value > 0)
}

fn remote_payload_text(payload: &Value, key: &str) -> String {
    payload
        .get(key)
        .and_then(|value| match value {
            Value::String(text) => Some(text.trim().to_string()),
            Value::Number(number) => Some(number.to_string()),
            _ => None,
        })
        .unwrap_or_default()
}

async fn parse_cloud_upload(headers: &HeaderMap, body: Bytes) -> Result<CloudUploadForm, AppError> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::CloudUploadFileInvalid)?;
    let boundary = multipart_boundary(content_type)?;
    let mut ticket = String::new();
    let mut file_name = String::new();
    let mut mime_type = String::new();
    let mut content = Vec::new();

    for part in multipart_parts(&body, &boundary)? {
        let headers =
            String::from_utf8(part.headers).map_err(|_| AppError::CloudUploadFileInvalid)?;
        let disposition = multipart_header(&headers, "content-disposition").unwrap_or_default();
        let Some(name) = disposition_parameter(&disposition, "name") else {
            continue;
        };
        if name == "ticket" {
            ticket = String::from_utf8(part.content)
                .map_err(|_| AppError::CloudUploadTicketInvalid)?
                .trim()
                .to_string();
            continue;
        }
        if name == "file" {
            file_name = disposition_parameter(&disposition, "filename").unwrap_or_default();
            mime_type = multipart_header(&headers, "content-type")
                .unwrap_or_else(|| "application/octet-stream".to_string());
            content = part.content;
        }
    }
    if ticket.is_empty() || file_name.is_empty() || content.is_empty() {
        return Err(AppError::CloudUploadFileInvalid);
    }
    Ok(CloudUploadForm {
        ticket,
        file_name,
        mime_type,
        content,
    })
}

struct MultipartPart {
    headers: Vec<u8>,
    content: Vec<u8>,
}

fn multipart_boundary(content_type: &str) -> Result<Vec<u8>, AppError> {
    for part in content_type.split(';') {
        let Some((key, value)) = part.trim().split_once('=') else {
            continue;
        };
        if key.eq_ignore_ascii_case("boundary") {
            let boundary = value.trim().trim_matches('"');
            if !boundary.is_empty() {
                return Ok(format!("--{boundary}").into_bytes());
            }
        }
    }
    Err(AppError::CloudUploadFileInvalid)
}

fn multipart_parts(body: &[u8], boundary: &[u8]) -> Result<Vec<MultipartPart>, AppError> {
    if !body.starts_with(boundary) {
        return Err(AppError::CloudUploadFileInvalid);
    }
    let mut parts = Vec::new();
    let mut cursor = boundary.len();
    loop {
        if body[cursor..].starts_with(b"--") {
            return Ok(parts);
        }
        if !body[cursor..].starts_with(b"\r\n") {
            return Err(AppError::CloudUploadFileInvalid);
        }
        let section_start = cursor + 2;
        let section_end = find_next_boundary(body, boundary, section_start)
            .ok_or(AppError::CloudUploadFileInvalid)?;
        let section = trim_trailing_crlf(&body[section_start..section_end]);
        let Some(header_end) = find_bytes(section, b"\r\n\r\n") else {
            return Err(AppError::CloudUploadFileInvalid);
        };
        parts.push(MultipartPart {
            headers: section[..header_end].to_vec(),
            content: trim_trailing_crlf(&section[header_end + 4..]).to_vec(),
        });
        cursor = section_end + boundary.len();
    }
}

fn multipart_header(headers: &str, name: &str) -> Option<String> {
    headers.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

fn disposition_parameter(disposition: &str, name: &str) -> Option<String> {
    disposition.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key.trim() == name).then(|| value.trim().trim_matches('"').to_string())
    })
}

fn find_next_boundary(body: &[u8], boundary: &[u8], start: usize) -> Option<usize> {
    let mut cursor = start;
    while let Some(offset) = find_bytes(&body[cursor..], boundary) {
        let index = cursor + offset;
        if is_boundary_line(body, boundary, index) {
            return Some(index);
        }
        cursor = index + 1;
    }
    None
}

fn is_boundary_line(body: &[u8], boundary: &[u8], index: usize) -> bool {
    let starts_line = index == 0 || (index >= 2 && &body[index - 2..index] == b"\r\n");
    if !starts_line {
        return false;
    }
    let suffix = &body[index + boundary.len()..];
    suffix.is_empty() || suffix.starts_with(b"\r\n") || suffix.starts_with(b"--")
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn trim_trailing_crlf(value: &[u8]) -> &[u8] {
    value.strip_suffix(b"\r\n").unwrap_or(value)
}

fn success<T: Serialize>(data: T) -> Json<SuccessResponse<T>> {
    success_with_code(data, 0)
}

fn success_with_code<T: Serialize>(data: T, code: i64) -> Json<SuccessResponse<T>> {
    Json(SuccessResponse {
        code,
        message: "ok",
        data,
    })
}

fn json_with_cookies<T: Serialize>(body: T, cookies: Vec<String>) -> Response {
    let mut response = Json(body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/json; charset=UTF-8"
            .parse()
            .expect("valid JSON content type"),
    );
    response_with_cookies(response, cookies)
}

fn error_with_cookies(error: AppError, cookies: Vec<String>) -> Response {
    response_with_cookies(error.into_response(), cookies)
}

fn html_with_cookies(html: String, cookies: Vec<String>) -> Response {
    response_with_cookies(Html(html).into_response(), cookies)
}

fn login_html_with_cookies(html: String, cookies: Vec<String>) -> Response {
    login_security_headers(html_session_cache_response(html_with_cookies(
        html, cookies,
    )))
}

fn redirect_found_response(location: &str, cookies: Vec<String>) -> Response {
    let mut response = Response::new(axum::body::Body::empty());
    *response.status_mut() = StatusCode::FOUND;
    response
        .headers_mut()
        .insert(header::LOCATION, location.parse().expect("valid redirect"));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(HTML_CONTENT_TYPE),
    );
    response_with_cookies(response, cookies)
}

fn login_redirect_found_response(location: &'static str, cookies: Vec<String>) -> Response {
    login_security_headers(html_session_cache_response(redirect_found_response(
        location, cookies,
    )))
}

fn admin_console_redirect_found_response(location: &'static str, cookies: Vec<String>) -> Response {
    admin_console_security_headers(html_session_cache_response(redirect_found_response(
        location, cookies,
    )))
}

fn admin_console_html_response(response: Response) -> Response {
    admin_console_security_headers(no_store_response(response))
}

fn install_html_response(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(HTML_CONTENT_TYPE),
    );
    response
        .headers_mut()
        .insert("x-frame-options", HeaderValue::from_static("DENY"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        "referrer-policy",
        HeaderValue::from_static(INSTALL_REFERRER_POLICY),
    );
    response
}

fn no_store_response(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "no-store, no-cache, must-revalidate, max-age=0"
            .parse()
            .expect("valid cache header"),
    );
    response
}

fn html_session_cache_response(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(PHP_SESSION_CACHE_CONTROL),
    );
    response
}

fn admin_console_security_headers(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert("x-frame-options", HeaderValue::from_static("SAMEORIGIN"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(ADMIN_CONSOLE_CONTENT_SECURITY_POLICY),
    );
    response
}

fn login_security_headers(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert("x-frame-options", HeaderValue::from_static("DENY"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(LOGIN_CONTENT_SECURITY_POLICY),
    );
    response
}

fn slider_image_response(image: crate::service::login::SliderImage) -> Response {
    let mut response = Response::new(axum::body::Body::from(image.bytes));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        image.content_type.parse().expect("valid content type"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "public, max-age=600, immutable"
            .parse()
            .expect("valid cache header"),
    );
    response.headers_mut().insert(
        "x-content-type-options",
        "nosniff".parse().expect("valid header"),
    );
    response
}

fn response_with_cookies(mut response: Response, cookies: Vec<String>) -> Response {
    for cookie in cookies {
        if let Ok(value) = cookie.parse() {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    response
}

fn required_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, AppError> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .ok_or(AppError::MissingSignatureHeader)
}

fn assert_post_method(method: &Method) -> Result<(), AppError> {
    if method != Method::POST {
        return Err(AppError::MethodNotAllowed);
    }
    Ok(())
}

fn assert_json_content_type(headers: &HeaderMap) -> Result<(), AppError> {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_ascii_lowercase().contains("application/json"))
    {
        return Ok(());
    }
    Err(AppError::UnsupportedMediaType)
}

fn card_query_app_code(payload: &Value, headers: &HeaderMap) -> String {
    match payload.get("app_code") {
        Some(Value::Null) | None => optional_header(headers, "x-app-code").to_string(),
        Some(value) => php_scalar_string(value),
    }
}

fn is_plain_client_request(route: &str, headers: &HeaderMap) -> bool {
    PLAIN_CLIENT_ROUTES.contains(&route)
        && (optional_header(headers, "x-plain-client") == "1"
            || optional_header(headers, "x-plain-notice") == "1")
}

fn assert_plain_client_payload(route: &str, payload: &Value) -> Result<(), AppError> {
    if route != "/login" {
        if PLAIN_SESSION_ROUTES.contains(&route) {
            return assert_plain_session_payload(payload);
        }
        return Ok(());
    }
    let mode = payload
        .get("device_key_mode")
        .map(php_scalar_string)
        .unwrap_or_default()
        .trim()
        .to_string();
    let challenge_id = payload
        .get("challenge_id")
        .map(php_scalar_string)
        .unwrap_or_default()
        .trim()
        .to_string();
    if mode == "ephemeral_ticket_v1" && challenge_id.starts_with("ephemeral.") {
        return Ok(());
    }
    Err(AppError::PlainLoginModeInvalid)
}

fn assert_plain_session_payload(payload: &Value) -> Result<(), AppError> {
    let session_ticket = payload
        .get("session_ticket")
        .map(php_scalar_string)
        .unwrap_or_default()
        .trim()
        .to_string();
    let signature = payload
        .get("signature")
        .map(php_scalar_string)
        .unwrap_or_default()
        .trim()
        .to_string();
    if !session_ticket.is_empty() && signature.is_empty() {
        return Ok(());
    }
    Err(AppError::PlainSessionModeInvalid)
}

fn optional_header<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
}

fn admin_upload_session_token(headers: &HeaderMap) -> &str {
    optional_header(headers, "x-admin-session")
}

fn is_https_request(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("https"))
}

fn wants_ajax_json(headers: &HeaderMap) -> bool {
    headers
        .get("x-requested-with")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("xmlhttprequest"))
}

fn has_login_credentials(form: &HashMap<String, String>) -> bool {
    form.contains_key("username") && form.contains_key("password")
}

fn parse_urlencoded_form(body: &[u8]) -> HashMap<String, String> {
    form_urlencoded::parse(body).into_owned().collect()
}

fn is_plain_demo_admin_request(state: &AppState, headers: &HeaderMap) -> bool {
    state.demo_mode
        && headers
            .get("x-demo-admin")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value == "1")
}

fn assert_demo_admin_route_allowed(state: &AppState, route: &str) -> Result<(), AppError> {
    if !demo_admin_route_allowed(state.demo_mode, route) {
        return Err(AppError::DemoReadOnly);
    }
    Ok(())
}

fn demo_admin_route_allowed(demo_mode: bool, route: &str) -> bool {
    !demo_mode || DEMO_ADMIN_READ_ROUTES.contains(&route)
}

fn parse_plain_admin_payload(body: &[u8]) -> Result<serde_json::Value, AppError> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| AppError::RequestJsonInvalid)?;
    match value {
        serde_json::Value::Object(_) => Ok(value),
        _ => Err(AppError::RequestJsonInvalid),
    }
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let header_value = headers.get(header::COOKIE)?.to_str().ok()?;
    header_value.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key.trim() == name).then_some(value.trim())
    })
}

fn valid_route(route: &str) -> bool {
    if route.len() < 2 || route.len() > 97 || !route.starts_with('/') {
        return false;
    }
    route
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-'))
}

fn normalized_route(route: Option<&str>) -> String {
    let normalized = route.unwrap_or("/health").trim_matches('/');
    if normalized.is_empty() {
        return "/health".to_string();
    }
    format!("/{normalized}")
}

fn resolved_api_route(query_route: Option<&str>, path_info: Option<&str>) -> String {
    normalized_route(query_route.or(path_info))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_compatible_routes() {
        assert!(valid_route("/health"));
        assert!(valid_route("/login/challenge"));
        assert!(valid_route("/admin/cloud-storage/files/list"));
        assert!(valid_route("/remote/variables/upsert"));
    }

    #[test]
    fn rejects_invalid_routes() {
        assert!(!valid_route("health"));
        assert!(!valid_route("/../config"));
        assert!(!valid_route("/bad?route=/health"));
    }

    #[test]
    fn normalizes_query_routes_like_php_request() {
        assert_eq!("/health", normalized_route(None));
        assert_eq!("/health", normalized_route(Some("")));
        assert_eq!("/health", normalized_route(Some("/")));
        assert_eq!("/health", normalized_route(Some("health")));
        assert_eq!("/health", normalized_route(Some("/health/")));
        assert_eq!("/notice", normalized_route(Some("//notice//")));
    }

    #[test]
    fn resolves_path_info_like_php_request() {
        assert_eq!("/health", resolved_api_route(None, Some("health")));
        assert_eq!("/notice", resolved_api_route(None, Some("/notice/")));
        assert_eq!(
            "/notice",
            resolved_api_route(Some("/notice"), Some("/health"))
        );
        assert_eq!("/health", resolved_api_route(Some(""), Some("/notice")));
    }

    #[tokio::test]
    async fn api_health_matches_php_body() {
        let Json(body) = api_health().await;

        assert_eq!(0, body.code);
        assert_eq!("ok", body.message);
        assert_eq!(
            json!({"service": "auth-service", "status": "ok"}),
            body.data
        );
    }

    #[tokio::test]
    async fn csp_report_matches_php_method_error() {
        let response = csp_report(Method::GET, Bytes::new()).await;

        assert_eq!(StatusCode::METHOD_NOT_ALLOWED, response.status());
        assert_eq!(
            CSP_REPORT_CONTENT_TYPE,
            response.headers()[header::CONTENT_TYPE]
        );
        assert_eq!(
            CSP_REPORT_ALLOW_ORIGIN,
            response.headers()["access-control-allow-origin"]
        );
        assert_eq!(
            CSP_REPORT_METHOD_ERROR_BODY,
            response_body_text(response).await
        );
    }

    #[tokio::test]
    async fn csp_report_matches_php_invalid_body_error() {
        let response = csp_report(Method::POST, Bytes::from_static(b"{}")).await;

        assert_eq!(StatusCode::BAD_REQUEST, response.status());
        assert_eq!(CSP_REPORT_INVALID_BODY, response_body_text(response).await);
    }

    #[tokio::test]
    async fn csp_report_matches_php_valid_no_content() {
        let response = csp_report(
            Method::POST,
            Bytes::from_static(
                br#"{"csp-report":{"document-uri":"http://localhost/admin/console/","violated-directive":"script-src"}}"#,
            ),
        )
        .await;

        assert_eq!(StatusCode::NO_CONTENT, response.status());
        assert_eq!(
            CSP_REPORT_CONTENT_TYPE,
            response.headers()[header::CONTENT_TYPE]
        );
        assert_eq!("", response_body_text(response).await);
    }

    #[tokio::test]
    async fn install_legacy_index_redirects_like_php() {
        let response = install_legacy_redirect(
            "/install/index.php?step=database"
                .parse::<Uri>()
                .expect("uri"),
        )
        .await;

        assert_eq!(StatusCode::FOUND, response.status());
        assert_eq!(
            "/install/?step=database",
            response.headers()[header::LOCATION]
        );
        assert_eq!(HTML_CONTENT_TYPE, response.headers()[header::CONTENT_TYPE]);
    }

    #[tokio::test]
    async fn legacy_admin_foot_matches_php_fragment() {
        let response = legacy_admin_foot().await;

        assert_eq!(StatusCode::OK, response.status());
        assert_eq!(HTML_CONTENT_TYPE, response.headers()[header::CONTENT_TYPE]);
        assert_eq!(LEGACY_ADMIN_FOOT_HTML, response_body_text(response).await);
    }

    #[test]
    fn install_page_response_matches_php_security_headers() {
        let response = install_html_response(Html("<!doctype html>").into_response());

        assert_eq!(HTML_CONTENT_TYPE, response.headers()[header::CONTENT_TYPE]);
        assert_eq!("DENY", response.headers()["x-frame-options"]);
        assert_eq!("nosniff", response.headers()["x-content-type-options"]);
        assert_eq!(
            INSTALL_REFERRER_POLICY,
            response.headers()["referrer-policy"]
        );
    }

    #[test]
    fn install_database_step_matches_php_default_form() {
        let html = render_install_page_for_test(&Method::GET, Some("database"), &[]);

        assert!(html.contains("<h1>数据库配置</h1>"));
        assert!(html.contains(r#"<span>数据库配置</span>"#));
        assert!(html.contains(r#"name="action" value="save_database""#));
        assert!(html.contains(r#"name="csrf_token" value=""#));
        assert!(html.contains(r#"name="host" value="127.0.0.1""#));
        assert!(html.contains(r#"name="port" value="3306""#));
        assert!(html.contains(r#"name="create_database" value="1" checked"#));
        assert!(html.contains("/frontend/admin-console/js/img/database-config.webp"));
    }

    #[test]
    fn install_admin_without_database_session_returns_database_step() {
        let html = render_install_page_for_test(&Method::GET, Some("admin"), &[]);

        assert!(html.contains("<h1>数据库配置</h1>"));
        assert!(html.contains(r#"name="action" value="save_database""#));
        assert!(!html.contains(r#"name="action" value="install_system""#));
    }

    #[test]
    fn install_database_post_without_csrf_preserves_raw_input() {
        let html = render_install_page_for_test(
            &Method::POST,
            Some("database"),
            b"action=save_database&host=bad.example.test&port=3307&dbname=bad_db&user=bad_user",
        );

        assert!(html.contains("请求验证失败，请刷新页面重试。"));
        assert!(html.contains("<h1>数据库配置</h1>"));
        assert!(html.contains(r#"name="host" value="bad.example.test""#));
        assert!(html.contains(r#"name="port" value="3307""#));
        assert!(html.contains(r#"name="dbname" value="bad_db""#));
        assert!(html.contains(r#"name="user" value="bad_user""#));
        assert!(!html.contains(r#"name="create_database" value="1" checked"#));
        assert!(html.contains("/frontend/admin-console/js/img/database-error.webp"));
    }

    #[test]
    fn install_admin_post_without_csrf_returns_admin_error_form() {
        let html = render_install_page_for_test(
            &Method::POST,
            Some("admin"),
            b"action=install_system&username=bad_admin",
        );

        assert!(html.contains("请求验证失败，请刷新页面重试。"));
        assert!(html.contains("<h1>管理员账号</h1>"));
        assert!(html.contains(r#"name="action" value="install_system""#));
        assert!(html.contains("/frontend/admin-console/js/img/admin-account.webp"));
    }

    #[test]
    fn install_admin_with_database_session_returns_admin_step() {
        let mut session = InstallSession::default();
        ensure_install_csrf(&mut session);
        session.database = Some(InstallDatabaseSession {
            host: "127.0.0.1".to_string(),
            port: 3306,
            username: "user".to_string(),
            password: "password".to_string(),
            database_name: "network_auth".to_string(),
        });
        let html = render_install_page(Some("admin"), InstallForm::empty(), &[], &session);

        assert!(html.contains("<h1>管理员账号</h1>"));
        assert!(html.contains(r#"name="action" value="install_system""#));
        assert!(html.contains(r#"name="csrf_token" value=""#));
    }

    fn render_install_page_for_test(
        method: &Method,
        query_step: Option<&str>,
        body: &[u8],
    ) -> String {
        let mut session = InstallSession::default();
        ensure_install_csrf(&mut session);
        let form = parse_urlencoded_form(body);
        if *method == Method::POST {
            let action = form.get("action").map(String::as_str).unwrap_or("");
            return render_install_page(
                query_step,
                InstallForm::from_raw(action, &form),
                &["请求验证失败，请刷新页面重试。".to_string()],
                &session,
            );
        }
        render_install_page(query_step, InstallForm::empty(), &[], &session)
    }

    #[test]
    fn redirects_only_unknown_page_paths_like_php_root_entry() {
        assert!(should_redirect_unknown_public_path("/missing-page"));
        assert!(should_redirect_unknown_public_path("/admin/missing"));
        assert!(!should_redirect_unknown_public_path("/missing.css"));
        assert!(!should_redirect_unknown_public_path("/api/not-real"));
        assert!(!should_redirect_unknown_public_path("/assets/not-real.css"));
        assert!(!should_redirect_unknown_public_path(
            "/frontend/not-real.js"
        ));
        assert!(!should_redirect_unknown_public_path(
            "/sub_admin/not-real.php"
        ));
    }

    #[test]
    fn normalizes_static_content_types_like_php() {
        let mut javascript = Response::builder()
            .header(header::CONTENT_TYPE, "text/javascript")
            .body(Body::empty())
            .expect("response");
        normalize_static_content_type(&mut javascript);
        assert_eq!(
            JAVASCRIPT_CONTENT_TYPE,
            javascript.headers()[header::CONTENT_TYPE]
        );

        let mut icon = Response::builder()
            .header(header::CONTENT_TYPE, "image/x-icon")
            .body(Body::empty())
            .expect("response");
        normalize_static_content_type(&mut icon);
        assert_eq!(ICON_CONTENT_TYPE, icon.headers()[header::CONTENT_TYPE]);
    }

    #[test]
    fn reads_exact_cookie_value() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "theme=dark; sub_admin_token=token-value; sub_admin=wrong"
                .parse()
                .expect("valid cookie header"),
        );

        assert_eq!(
            Some("token-value"),
            cookie_value(&headers, "sub_admin_token")
        );
        assert_eq!(None, cookie_value(&headers, "missing"));
    }

    #[test]
    fn expires_invalid_admin_cookie_like_php_paths() {
        assert!(
            invalid_admin_cookie_expiration_headers(AdminCookieAuthentication::Missing, false)
                .is_empty()
        );
        assert!(
            invalid_admin_cookie_expiration_headers(
                AdminCookieAuthentication::Authenticated,
                false
            )
            .is_empty()
        );

        let cookies =
            invalid_admin_cookie_expiration_headers(AdminCookieAuthentication::Invalid, false);

        assert_eq!(2, cookies.len());
        assert!(cookies[0].contains("sub_admin_token="));
        assert!(cookies[0].contains("Path=/"));
        assert!(cookies[0].contains("Max-Age=0"));
        assert!(cookies[1].contains("Path=/sub_admin"));
    }

    #[test]
    fn attaches_cookie_expiration_to_admin_session_error() {
        let response = error_with_cookies(
            AppError::AdminLoginRequired,
            expired_admin_cookie_headers(false),
        );

        assert_eq!(StatusCode::UNAUTHORIZED, response.status());
        assert_eq!(
            2,
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .count()
        );
    }

    async fn response_body_text(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        String::from_utf8(bytes.to_vec()).expect("utf8 body")
    }

    #[test]
    fn matches_php_login_post_isset_guard() {
        let mut form = HashMap::new();
        assert!(!has_login_credentials(&form));

        form.insert("username".to_string(), String::new());
        assert!(!has_login_credentials(&form));

        form.insert("password".to_string(), String::new());
        assert!(has_login_credentials(&form));
    }

    #[test]
    fn parses_empty_login_post_body_like_php_form() {
        let form = parse_urlencoded_form(b"");

        assert!(form.is_empty());
        assert!(!has_login_credentials(&form));
    }

    #[test]
    fn parses_login_post_form_values_like_php_request() {
        let form = parse_urlencoded_form(b"username=admin%40local&password=&remember_login=1");

        assert_eq!("admin@local", form.get("username").expect("username"));
        assert_eq!("", form.get("password").expect("password"));
        assert_eq!("1", form.get("remember_login").expect("remember flag"));
        assert!(has_login_credentials(&form));
    }

    #[test]
    fn requires_signature_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-admin-session", "session".parse().expect("valid header"));

        assert_eq!(
            "session",
            required_header(&headers, "x-admin-session").expect("header should exist")
        );
        assert!(matches!(
            required_header(&headers, "x-signature"),
            Err(AppError::MissingSignatureHeader)
        ));
    }

    #[test]
    fn matches_php_upload_session_header_semantics() {
        let mut headers = HeaderMap::new();
        assert_eq!("", admin_upload_session_token(&headers));

        headers.insert("x-admin-session", "session".parse().expect("valid header"));
        assert_eq!("session", admin_upload_session_token(&headers));
    }

    #[test]
    fn matches_php_post_and_json_guards() {
        assert!(matches!(
            assert_post_method(&Method::GET),
            Err(AppError::MethodNotAllowed)
        ));
        assert!(assert_post_method(&Method::POST).is_ok());

        let mut headers = HeaderMap::new();
        assert!(matches!(
            assert_json_content_type(&headers),
            Err(AppError::UnsupportedMediaType)
        ));
        headers.insert(
            header::CONTENT_TYPE,
            "application/json; charset=UTF-8"
                .parse()
                .expect("content type"),
        );
        assert!(assert_json_content_type(&headers).is_ok());
    }

    #[test]
    fn matches_php_api_options_entry_order() {
        let empty_headers = HeaderMap::new();
        assert!(!should_short_circuit_api_options(
            "/health",
            &Method::OPTIONS,
            &empty_headers
        ));
        assert!(should_short_circuit_api_options(
            "/notice",
            &Method::OPTIONS,
            &empty_headers
        ));

        let mut plain_headers = HeaderMap::new();
        plain_headers.insert("x-plain-notice", "1".parse().expect("header"));
        assert!(!should_short_circuit_api_options(
            "/notice",
            &Method::OPTIONS,
            &plain_headers
        ));

        let mut plain_client_headers = HeaderMap::new();
        plain_client_headers.insert("x-plain-client", "1".parse().expect("header"));
        assert!(!should_short_circuit_api_options(
            "/login",
            &Method::OPTIONS,
            &plain_client_headers
        ));
        assert!(should_short_circuit_api_options(
            "/unbind",
            &Method::OPTIONS,
            &plain_client_headers
        ));
    }

    #[test]
    fn applies_php_json_response_headers() {
        let mut response = Json(json!({"code": 0, "message": "ok", "data": {}})).into_response();

        assert!(is_json_response(&response));
        apply_php_json_headers(&mut response);

        let headers = response.headers();
        assert_eq!(
            PHP_JSON_CONTENT_TYPE,
            headers.get(header::CONTENT_TYPE).unwrap().to_str().unwrap()
        );
        assert_eq!(
            PHP_JSON_CACHE_CONTROL,
            headers
                .get(header::CACHE_CONTROL)
                .unwrap()
                .to_str()
                .unwrap()
        );
        assert_eq!(
            PHP_JSON_CORS_METHODS,
            headers
                .get("access-control-allow-methods")
                .unwrap()
                .to_str()
                .unwrap()
        );
        assert_eq!(
            PHP_JSON_CORS_HEADERS,
            headers
                .get("access-control-allow-headers")
                .unwrap()
                .to_str()
                .unwrap()
        );
    }

    #[test]
    fn keeps_html_out_of_php_json_response_headers() {
        let response = Html("<!doctype html>").into_response();

        assert!(!is_json_response(&response));
    }

    #[test]
    fn redirect_response_matches_php_default_content_type() {
        let response = redirect_found_response("/admin/console/", Vec::new());
        let headers = response.headers();

        assert_eq!(StatusCode::FOUND, response.status());
        assert_eq!(
            HTML_CONTENT_TYPE,
            headers.get(header::CONTENT_TYPE).unwrap().to_str().unwrap()
        );
        assert_eq!(
            "/admin/console/",
            headers.get(header::LOCATION).unwrap().to_str().unwrap()
        );
    }

    #[test]
    fn local_cloud_download_content_type_matches_php_text_charset() {
        assert_eq!(
            "text/plain;charset=UTF-8",
            local_cloud_download_content_type("text/plain")
        );
        assert_eq!(
            "text/plain; charset=utf-8",
            local_cloud_download_content_type(" text/plain; charset=utf-8 ")
        );
        assert_eq!(
            "application/octet-stream",
            local_cloud_download_content_type("")
        );
    }

    #[test]
    fn login_redirect_response_matches_php_headers() {
        let response = login_redirect_found_response("/admin/login/", Vec::new());
        let headers = response.headers();

        assert_eq!(
            PHP_SESSION_CACHE_CONTROL,
            headers
                .get(header::CACHE_CONTROL)
                .unwrap()
                .to_str()
                .unwrap()
        );
        assert_eq!(
            "DENY",
            headers.get("x-frame-options").unwrap().to_str().unwrap()
        );
        assert_eq!(
            LOGIN_CONTENT_SECURITY_POLICY,
            headers
                .get(header::CONTENT_SECURITY_POLICY)
                .unwrap()
                .to_str()
                .unwrap()
        );
    }

    #[test]
    fn admin_console_redirect_response_matches_php_headers() {
        let response = admin_console_redirect_found_response("/admin/login/", Vec::new());
        let headers = response.headers();

        assert_eq!(
            PHP_SESSION_CACHE_CONTROL,
            headers
                .get(header::CACHE_CONTROL)
                .unwrap()
                .to_str()
                .unwrap()
        );
        assert_eq!(
            "SAMEORIGIN",
            headers.get("x-frame-options").unwrap().to_str().unwrap()
        );
        assert_eq!(
            ADMIN_CONSOLE_CONTENT_SECURITY_POLICY,
            headers
                .get(header::CONTENT_SECURITY_POLICY)
                .unwrap()
                .to_str()
                .unwrap()
        );
    }

    #[test]
    fn matches_php_demo_admin_read_only_routes() {
        assert!(demo_admin_route_allowed(true, "/admin/overview"));
        assert!(demo_admin_route_allowed(true, "/admin/profile/get"));
        assert!(demo_admin_route_allowed(
            true,
            "/admin/cloud-storage/files/list"
        ));
        assert!(!demo_admin_route_allowed(true, "/admin/site/update"));
        assert!(!demo_admin_route_allowed(
            true,
            "/admin/cloud-storage/files/upload"
        ));
        assert!(demo_admin_route_allowed(false, "/admin/site/update"));
    }

    #[test]
    fn parses_plain_demo_admin_json_objects_only() {
        let payload = parse_plain_admin_payload(br#"{"page":1}"#).expect("object payload");

        assert_eq!(json!({"page": 1}), payload);
        assert!(matches!(
            parse_plain_admin_payload(br#"[]"#),
            Err(AppError::RequestJsonInvalid)
        ));
    }

    #[test]
    fn maps_remote_read_routes_to_admin_routes() {
        assert_eq!(
            Some("/admin/apps/list"),
            remote_admin_route("/remote/apps/list").map(|route| route.admin_route)
        );
        assert_eq!(
            Some("/admin/cloud-storage/files/detail"),
            remote_admin_route("/remote/cloud-storage/files/detail").map(|route| route.admin_route)
        );
        assert_eq!(
            Some("/admin/apps/delete"),
            remote_admin_route("/remote/apps/delete").map(|route| route.admin_route)
        );
        assert!(remote_admin_route("/remote/unknown").is_none());
    }

    #[test]
    fn maps_remote_app_routes_with_php_payload_transforms() {
        assert!(matches!(
            remote_admin_route("/remote/apps/update").map(|route| route.transform),
            Some(RemotePayloadTransform::AppId)
        ));
        assert!(matches!(
            remote_admin_route("/remote/apps/status").map(|route| route.transform),
            Some(RemotePayloadTransform::AppCode)
        ));
        assert!(matches!(
            remote_admin_route("/remote/apps/delete").map(|route| route.transform),
            Some(RemotePayloadTransform::AppIds)
        ));
    }

    #[test]
    fn maps_remote_special_routes_with_php_payload_transforms() {
        assert!(matches!(
            remote_special_payload_transform("/remote/variables/upsert"),
            Some(RemotePayloadTransform::AppIdsFromCodes)
        ));
        assert!(matches!(
            remote_special_payload_transform("/remote/apps/api/get"),
            Some(RemotePayloadTransform::None)
        ));
        assert!(matches!(
            remote_special_payload_transform("/remote/cloud-storage/files/upload"),
            Some(RemotePayloadTransform::None)
        ));
        assert!(remote_special_payload_transform("/remote/missing").is_none());
    }

    #[test]
    fn parses_empty_remote_body_like_php_request_json() {
        assert_eq!(
            json!({}),
            parse_remote_payload(b"").expect("empty body is empty object")
        );
        assert!(matches!(
            parse_remote_payload(br#"[]"#),
            Err(AppError::RequestJsonInvalid)
        ));
    }

    #[test]
    fn request_json_invalid_uses_php_request_message() {
        let error = parse_client_payload(b"{bad json").expect_err("invalid JSON should fail");

        assert_eq!("INVALID_JSON", error.error_code());
        assert_eq!("JSON 请求体格式错误", error.to_string());
    }

    #[test]
    fn injects_remote_payload_metadata_like_php_array_union() {
        let context = crate::service::remote_api::RemoteApiContext {
            token_id: 7,
            access_key: "access-key".to_string(),
            actor_name: "token-name".to_string(),
        };
        let payload = remote_payload(
            json!({
                "app_code": "ace",
                "_client_ip": "submitted-ip",
                "_remote_target_app_id": 99
            }),
            &context,
            "203.0.113.8",
            Some(12),
        );

        assert_eq!("submitted-ip", payload["_client_ip"]);
        assert_eq!("token-name", payload["_admin_username"]);
        assert_eq!(7, payload["_remote_api_token_id"]);
        assert_eq!("access-key", payload["_remote_api_access_key"]);
        assert_eq!(12, payload["_remote_target_app_id"]);
    }

    #[tokio::test]
    async fn parses_cloud_upload_multipart_form() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            "multipart/form-data; boundary=----ace"
                .parse()
                .expect("header"),
        );
        let body = Bytes::from_static(
            b"------ace\r\nContent-Disposition: form-data; name=\"ticket\"\r\n\r\nticket-token\r\n------ace\r\nContent-Disposition: form-data; name=\"file\"; filename=\"app.zip\"\r\nContent-Type: application/zip\r\n\r\nzip-bytes\r\n------ace--\r\n",
        );

        let upload = parse_cloud_upload(&headers, body).await.expect("upload");

        assert_eq!("ticket-token", upload.ticket);
        assert_eq!("app.zip", upload.file_name);
        assert_eq!("application/zip", upload.mime_type);
        assert_eq!(b"zip-bytes", upload.content.as_slice());
    }

    #[tokio::test]
    async fn preserves_cloud_upload_content_containing_boundary_text() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            "multipart/form-data; boundary=----ace"
                .parse()
                .expect("header"),
        );
        let body = Bytes::from_static(
            b"------ace\r\nContent-Disposition: form-data; name=\"ticket\"\r\n\r\nticket-token\r\n------ace\r\nContent-Disposition: form-data; name=\"file\"; filename=\"app.zip\"\r\nContent-Type: application/zip\r\n\r\nzip------ace-bytes\r\n------ace--\r\n",
        );

        let upload = parse_cloud_upload(&headers, body).await.expect("upload");

        assert_eq!(b"zip------ace-bytes", upload.content.as_slice());
    }
}
