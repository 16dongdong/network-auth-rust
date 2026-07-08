use std::{
    collections::{HashMap, HashSet},
    fmt::Write,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::{Duration as StdDuration, UNIX_EPOCH},
};

use bcrypt::verify;
use chrono::{Duration, Local};
use hmac::{Hmac, Mac};
use image::{
    codecs::jpeg::JpegEncoder,
    imageops::{FilterType, crop_imm, resize},
};
use rand::{RngCore, rngs::OsRng, seq::SliceRandom};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use tokio::fs;

use crate::{
    crypto,
    error::AppError,
    repository::{AdminRow, AuthRepository},
    service::admin_session::admin_cookie_session,
};

type HmacSha256 = Hmac<Sha256>;

const LOGIN_STATE_COOKIE: &str = "network_auth_admin_login_state";
const ADMIN_COOKIE: &str = "sub_admin_token";
const REMEMBER_COOKIE: &str = "sub_admin_remember";
const LOGIN_COOKIE_TTL_SECONDS: i64 = 604_800;
const LOGIN_STATE_TTL_SECONDS: i64 = 600;
const SLIDER_CHALLENGE_TTL_SECONDS: i64 = 180;
const SLIDER_PROOF_TTL_SECONDS: i64 = 300;
const SLIDER_MAX_ATTEMPTS: u8 = 5;
const SLIDER_WIDTH: i32 = 300;
const SLIDER_HEIGHT: i32 = 170;
const SLIDER_PIECE_WIDTH: i32 = 34;
const SLIDER_PIECE_RADIUS: i32 = 7;
const SLIDER_OFFSET: i32 = 8;
const SLIDER_IMAGE_HTTP_TIMEOUT_SECONDS: u64 = 8;
const SLIDER_IMAGE_HTTP_CONNECT_TIMEOUT_SECONDS: u64 = 4;
const SLIDER_IMAGE_MAX_BYTES: u64 = 8_388_608;
const SLIDER_IMAGE_JPEG_QUALITY: u8 = 84;
const SLIDER_IMAGE_POOL_SIZE: usize = 20;
const SLIDER_IMAGE_POOL_ROTATION_SECONDS: i64 = 600;
const SLIDER_IMAGE_POOL_REFRESH_LEAD_SECONDS: i64 = 360;
const SLIDER_IMAGE_POOL_MAX_ATTEMPTS: usize = 120;
const SLIDER_IMAGE_POOL_BATCH_SIZE: usize = 30;
const SLIDER_IMAGE_CACHE_RETENTION_SECONDS: i64 = 1_800;

static SLIDER_IMAGE_POOL_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

#[derive(Clone)]
pub struct LoginService {
    repository: AuthRepository,
    system_key: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoginJsonBody {
    pub code: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub msg: String,
    #[serde(flatten)]
    pub data: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct LoginResponse {
    pub body: LoginJsonBody,
    pub cookies: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RenderedLoginPage {
    pub html: String,
    pub cookies: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct LoginRedirect {
    pub location: &'static str,
    pub body: LoginJsonBody,
    pub cookies: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RememberedLoginRestore {
    pub restored: bool,
    pub cookies: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SliderImage {
    pub bytes: Vec<u8>,
    pub content_type: String,
}

pub async fn prewarm_slider_images(public_root: &Path, force: bool) -> Result<Value, String> {
    let paths = slider_image_cache_paths(public_root);
    ensure_slider_image_pool_paths(&paths).await?;
    let current_pool = read_slider_image_pool(&paths).await?;
    if let Some(pool) = current_pool
        && !force
        && !slider_image_pool_refresh_due(&pool)
    {
        let removed_count = prune_slider_image_cache(&paths, &pool).await?;
        return Ok(slider_image_pool_status(&pool, "cached", removed_count));
    }

    let _guard = slider_image_pool_lock().lock().await;
    let pool = match read_slider_image_pool(&paths).await? {
        Some(pool) if !slider_image_pool_refresh_due(&pool) => pool,
        Some(pool) => refresh_slider_image_pool_or_current_pool(&paths, pool).await,
        None => refresh_slider_image_pool(&paths).await?,
    };
    let removed_count = prune_slider_image_cache(&paths, &pool).await?;
    Ok(slider_image_pool_status(&pool, "ready", removed_count))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LoginState {
    csrf_token: String,
    issued_at: i64,
    nonce: String,
    puzzle_x: i32,
    puzzle_y: i32,
    challenge_issued_at: i64,
    attempts: u8,
    proof: String,
    verified_at: i64,
}

impl LoginService {
    pub fn new(repository: AuthRepository, system_key: String) -> Self {
        Self {
            repository,
            system_key,
        }
    }

    pub async fn render_login_page(
        &self,
        state_cookie: Option<&str>,
        secure: bool,
    ) -> Result<RenderedLoginPage, AppError> {
        let state = self.login_state_from_cookie(state_cookie);
        let settings = self
            .repository
            .get_site_settings()
            .await?
            .unwrap_or_else(|| crate::repository::SiteSettingsRow {
                hostname: "授权管理系统".to_string(),
                site_subtitle: "后台管理入口".to_string(),
                siteurl: String::new(),
                logo_url: String::new(),
                announcement: String::new(),
                contact: String::new(),
                footer_text: String::new(),
                custom_json: json!({}),
            });
        let view = LoginPageView::from_settings(&settings, &state.csrf_token, None);
        Ok(RenderedLoginPage {
            html: render_login_html(&view)?,
            cookies: vec![self.state_cookie(&state, LOGIN_STATE_TTL_SECONDS, secure)?],
        })
    }

    pub async fn issue_slider_challenge(
        &self,
        state_cookie: Option<&str>,
        secure: bool,
        public_root: &Path,
    ) -> Result<LoginResponse, AppError> {
        let mut state = self.login_state_from_cookie(state_cookie);
        if active_slider_proof(&state) {
            return Ok(LoginResponse {
                body: login_body(
                    "1",
                    "",
                    json!({
                        "verified": true,
                        "proof": state.proof,
                        "expires_in": remaining_seconds(state.verified_at, SLIDER_PROOF_TTL_SECONDS),
                    }),
                ),
                cookies: vec![self.state_cookie(&state, LOGIN_STATE_TTL_SECONDS, secure)?],
            });
        }
        let image = match resolve_slider_image(public_root).await {
            Ok(image) => image,
            Err(message) => {
                return self.login_error_resetting_slider(&state, secure, &message);
            }
        };

        state.nonce = slider_random_hex_token();
        state.challenge_issued_at = now_timestamp();
        state.attempts = 0;
        state.proof.clear();
        state.verified_at = 0;
        state.puzzle_x = random_slider_x();
        state.puzzle_y = random_slider_y();
        Ok(LoginResponse {
            body: login_body(
                "1",
                "",
                json!({
                        "nonce": state.nonce,
                        "expires_in": SLIDER_CHALLENGE_TTL_SECONDS,
                        "image_url": image.url,
                        "width": SLIDER_WIDTH,
                        "height": SLIDER_HEIGHT,
                        "offset": SLIDER_OFFSET,
                    "puzzle_x": state.puzzle_x,
                    "puzzle_y": state.puzzle_y,
                }),
            ),
            cookies: vec![self.state_cookie(&state, LOGIN_STATE_TTL_SECONDS, secure)?],
        })
    }

    pub fn verify_slider(
        &self,
        form: &HashMap<String, String>,
        state_cookie: Option<&str>,
        secure: bool,
    ) -> Result<LoginResponse, AppError> {
        let mut state = self.login_state_from_cookie(state_cookie);
        let token = form_value(form, "token");
        if token.is_empty() || token != state.csrf_token {
            return self.login_error_resetting_slider(
                &state,
                secure,
                "请求验证失败，请刷新页面重试",
            );
        }
        if let Some(message) = slider_nonce_error(&state, form_value(form, "nonce")) {
            return self.login_error_resetting_slider(&state, secure, message);
        }
        if expired(state.challenge_issued_at, SLIDER_CHALLENGE_TTL_SECONDS) {
            return self.login_error_resetting_slider(&state, secure, "拼图验证已过期，请重新滑动");
        }
        state.attempts = state.attempts.saturating_add(1);
        if state.attempts > SLIDER_MAX_ATTEMPTS {
            return self.login_error_resetting_slider(
                &state,
                secure,
                "拼图验证失败次数过多，请刷新后重试",
            );
        }
        let left = match parse_slider_left(form_value(form, "left")) {
            Ok(left) => left,
            Err(message) => {
                return self.login_error_resetting_slider(&state, secure, message);
            }
        };
        let trail = match parse_slider_trail(form_value(form, "trail")) {
            Ok(trail) => trail,
            Err(message) => {
                return self.login_error_resetting_slider(&state, secure, message);
            }
        };
        if (left - state.puzzle_x).abs() > SLIDER_OFFSET || !valid_trail(&trail) {
            return self.login_error_resetting_slider(
                &state,
                secure,
                if (left - state.puzzle_x).abs() > SLIDER_OFFSET {
                    "拼图位置不正确，请重试"
                } else {
                    "拼图轨迹验证失败，请重试"
                },
            );
        }
        state.verified_at = now_timestamp();
        state.proof = slider_random_hex_token();
        Ok(LoginResponse {
            body: login_body(
                "1",
                "",
                json!({
                    "proof": state.proof,
                    "expires_in": SLIDER_PROOF_TTL_SECONDS,
                }),
            ),
            cookies: vec![self.state_cookie(&state, LOGIN_STATE_TTL_SECONDS, secure)?],
        })
    }

    pub async fn login(
        &self,
        form: &HashMap<String, String>,
        state_cookie: Option<&str>,
        remember_cookie: Option<&str>,
        ip: &str,
        secure: bool,
    ) -> Result<LoginResponse, AppError> {
        let state = self.login_state_from_cookie(state_cookie);
        let username = form_value(form, "username").trim().to_string();
        let password = form_value(form, "password").trim();
        let token = form_value(form, "token");
        let slider_proof = form_value(form, "slider_proof");
        if token.is_empty() || token != state.csrf_token {
            return self.login_error_resetting_slider(
                &state,
                secure,
                "请求验证失败，请刷新页面重试！！！",
            );
        }
        let slider_error = require_slider_proof(&state, slider_proof);
        if let Some(message) = slider_error {
            return self.login_error_resetting_slider(&state, secure, message);
        }
        let admin = if form_value(form, "use_remembered_login").trim() == "1" {
            match self.remembered_admin(remember_cookie).await? {
                Some(admin) => admin,
                None => match self
                    .password_login_admin(&state, secure, &username, password, ip)
                    .await?
                {
                    Ok(admin) => admin,
                    Err(response) => return Ok(response),
                },
            }
        } else {
            match self
                .password_login_admin(&state, secure, &username, password, ip)
                .await?
            {
                Ok(admin) => admin,
                Err(response) => return Ok(response),
            }
        };

        let admin_cookie = self.admin_cookie_value(&admin)?;
        self.repository
            .update_admin_cookie(&admin.username, &admin_cookie)
            .await?;
        let mut cookies = vec![
            self.clear_state_cookie(secure),
            persistent_cookie(
                ADMIN_COOKIE,
                &admin_cookie,
                LOGIN_COOKIE_TTL_SECONDS,
                secure,
                "/",
            ),
        ];
        if form_value(form, "remember_login") == "1" {
            cookies.push(self.issue_remember_cookie(&admin, secure).await?);
        } else {
            self.repository
                .clear_admin_remember_login(&admin.username)
                .await?;
            cookies.push(expired_cookie(REMEMBER_COOKIE, secure, "/"));
        }
        self.repository
            .write_log("登录日志", "登录成功", &admin.username, ip)
            .await?;
        Ok(LoginResponse {
            body: login_body("1", "登录成功,欢迎您使用本系统！", json!({})),
            cookies,
        })
    }

    async fn password_login_admin(
        &self,
        state: &LoginState,
        secure: bool,
        username: &str,
        password: &str,
        ip: &str,
    ) -> Result<Result<AdminRow, LoginResponse>, AppError> {
        if username.len() < 3 {
            return Ok(Err(self.login_error_resetting_slider(
                state,
                secure,
                "用户名不能为空且长度不能小于3个字符！",
            )?));
        }
        if password.len() < 6 {
            return Ok(Err(self.login_error_resetting_slider(
                state,
                secure,
                "密码不能为空且长度不能小于6个字符！",
            )?));
        }
        let Some(admin) = self.repository.find_admin_by_username(username).await? else {
            self.write_login_failure(username, "用户名或密码不正确！", ip)
                .await?;
            return Ok(Err(self.login_error_resetting_slider(
                state,
                secure,
                "用户名或密码不正确！",
            )?));
        };
        if !verify_php_password(password, &admin.password) {
            self.write_login_failure(username, "用户名或密码不正确！", ip)
                .await?;
            return Ok(Err(self.login_error_resetting_slider(
                state,
                secure,
                "用户名或密码不正确！",
            )?));
        }
        Ok(Ok(admin))
    }

    pub async fn logout(
        &self,
        admin_cookie: Option<&str>,
        secure: bool,
    ) -> Result<LoginRedirect, AppError> {
        if let Some(cookie) = admin_cookie
            && let Ok(username) = self.admin_username_from_cookie(cookie).await
        {
            self.repository.update_admin_cookie(&username, "").await?;
            self.repository
                .clear_admin_remember_login(&username)
                .await?;
        }
        Ok(LoginRedirect {
            location: "/admin/login/",
            body: login_body("0", "您已成功注销本次登录！", json!({})),
            cookies: vec![
                expired_cookie(ADMIN_COOKIE, secure, "/"),
                expired_cookie(ADMIN_COOKIE, secure, "/sub_admin"),
                expired_cookie(REMEMBER_COOKIE, secure, "/"),
                self.clear_state_cookie(secure),
            ],
        })
    }

    pub async fn forget_remember_login(
        &self,
        remember_cookie: Option<&str>,
        secure: bool,
    ) -> Result<Vec<String>, AppError> {
        if let Some(admin) = self.remembered_admin(remember_cookie).await? {
            self.repository
                .clear_admin_remember_login(&admin.username)
                .await?;
        }
        Ok(vec![
            expired_cookie(REMEMBER_COOKIE, secure, "/"),
            expired_cookie(REMEMBER_COOKIE, secure, "/sub_admin"),
        ])
    }

    pub async fn restore_remembered_login(
        &self,
        remember_cookie: Option<&str>,
        ip: &str,
        secure: bool,
    ) -> Result<RememberedLoginRestore, AppError> {
        let Some(admin) = self.remembered_admin(remember_cookie).await? else {
            return Ok(RememberedLoginRestore {
                restored: false,
                cookies: Vec::new(),
            });
        };
        let admin_cookie = self.admin_cookie_value(&admin)?;
        self.repository
            .update_admin_cookie(&admin.username, &admin_cookie)
            .await?;
        self.repository
            .write_log("登录日志", "记住登录自动恢复", &admin.username, ip)
            .await?;
        Ok(RememberedLoginRestore {
            restored: true,
            cookies: vec![persistent_cookie(
                ADMIN_COOKIE,
                &admin_cookie,
                LOGIN_COOKIE_TTL_SECONDS,
                secure,
                "/",
            )],
        })
    }

    pub async fn slider_image(
        &self,
        public_root: &Path,
        image_id: Option<&str>,
        version: Option<&str>,
    ) -> Result<SliderImage, AppError> {
        let image_id = slider_image_id(image_id.unwrap_or_default())?;
        if version.map(str::trim) != Some(image_id.as_str()) {
            return Err(AppError::InvalidInput("拼图图片版本无效"));
        }
        let cache = slider_image_cache_paths(public_root);
        let bytes = fs::read(cache.image_path(&image_id))
            .await
            .map_err(|_| AppError::StaticFileMissing("slider-image"))?;
        if crypto::sha256_hex_bytes(&bytes) != image_id {
            return Err(AppError::StaticFileMissing("slider-image"));
        }
        Ok(SliderImage {
            bytes,
            content_type: "image/jpeg".to_string(),
        })
    }

    pub async fn admin_username_from_cookie(&self, cookie_value: &str) -> Result<String, AppError> {
        let decoded = crypto::decrypt_protected_text(cookie_value, &self.system_key)
            .map_err(|_| AppError::AdminLoginRequired)?;
        let (username, session) = decoded
            .split_once('\t')
            .ok_or(AppError::AdminLoginRequired)?;
        let admin = self
            .repository
            .find_admin_by_username(username.trim())
            .await?
            .ok_or(AppError::AdminLoginRequired)?;
        let expected = admin_cookie_session(&admin.username, &admin.password, &self.system_key);
        if expected != session {
            return Err(AppError::AdminLoginRequired);
        }
        Ok(admin.username)
    }

    fn admin_cookie_value(&self, admin: &AdminRow) -> Result<String, AppError> {
        let session = admin_cookie_session(&admin.username, &admin.password, &self.system_key);
        crypto::encrypt_protected_text(
            &format!("{}\t{}", admin.username, session),
            &self.system_key,
        )
    }

    async fn issue_remember_cookie(
        &self,
        admin: &AdminRow,
        secure: bool,
    ) -> Result<String, AppError> {
        let token = crypto::token(32);
        let token_hash = hmac_sha256_hex(&self.system_key, &token)?;
        let expires_at = Local::now().naive_local() + Duration::seconds(LOGIN_COOKIE_TTL_SECONDS);
        self.repository
            .set_admin_remember_login(&admin.username, &token_hash, expires_at)
            .await?;
        let cookie_value = crypto::encrypt_protected_text(
            &format!("{}\t{}", admin.username, token),
            &self.system_key,
        )?;
        Ok(persistent_cookie(
            REMEMBER_COOKIE,
            &cookie_value,
            LOGIN_COOKIE_TTL_SECONDS,
            secure,
            "/",
        ))
    }

    async fn remembered_admin(
        &self,
        remember_cookie: Option<&str>,
    ) -> Result<Option<AdminRow>, AppError> {
        let Some(cookie_value) = remember_cookie
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };
        let Ok(decoded) = crypto::decrypt_protected_text(cookie_value, &self.system_key) else {
            return Ok(None);
        };
        let Some((username, token)) = decoded.split_once('\t') else {
            return Ok(None);
        };
        let username = username.trim();
        let token = token.trim();
        if username.is_empty() || token.is_empty() {
            return Ok(None);
        }
        let Some(admin) = self.repository.find_admin_by_username(username).await? else {
            return Ok(None);
        };
        if !remember_login_active(&admin) {
            return Ok(None);
        }
        let token_hash = hmac_sha256_hex(&self.system_key, token)?;
        if token_hash != admin.remember_login_token_hash {
            self.repository
                .clear_admin_remember_login(&admin.username)
                .await?;
            return Ok(None);
        }
        Ok(Some(admin))
    }

    fn login_state_from_cookie(&self, cookie_value: Option<&str>) -> LoginState {
        cookie_value
            .and_then(|value| crypto::decrypt_protected_text(value, &self.system_key).ok())
            .and_then(|value| serde_json::from_str::<LoginState>(&value).ok())
            .filter(|state| !expired(state.issued_at, LOGIN_STATE_TTL_SECONDS))
            .unwrap_or_else(new_login_state)
    }

    fn state_cookie(
        &self,
        state: &LoginState,
        ttl_seconds: i64,
        secure: bool,
    ) -> Result<String, AppError> {
        let state_json = serde_json::to_string(state)
            .map_err(|_| AppError::CryptoError("登录状态序列化失败"))?;
        let encrypted = crypto::encrypt_protected_text(&state_json, &self.system_key)?;
        Ok(persistent_cookie(
            LOGIN_STATE_COOKIE,
            &encrypted,
            ttl_seconds,
            secure,
            "/admin/login/",
        ))
    }

    fn clear_state_cookie(&self, secure: bool) -> String {
        expired_cookie(LOGIN_STATE_COOKIE, secure, "/admin/login/")
    }

    fn reset_slider_cookie(&self, state: &LoginState, secure: bool) -> Result<String, AppError> {
        let mut next_state = state.clone();
        reset_slider_challenge(&mut next_state);
        self.state_cookie(&next_state, LOGIN_STATE_TTL_SECONDS, secure)
    }

    fn login_error_resetting_slider(
        &self,
        state: &LoginState,
        secure: bool,
        message: &str,
    ) -> Result<LoginResponse, AppError> {
        Ok(login_error_with_cookie(
            message,
            self.reset_slider_cookie(state, secure)?,
        ))
    }

    async fn write_login_failure(
        &self,
        username: &str,
        reason: &str,
        ip: &str,
    ) -> Result<(), AppError> {
        self.repository
            .write_log("登录日志", &format!("验证失败: {reason}"), username, ip)
            .await
    }
}

pub fn login_state_cookie_name() -> &'static str {
    LOGIN_STATE_COOKIE
}

pub fn admin_cookie_name() -> &'static str {
    ADMIN_COOKIE
}

pub fn remember_cookie_name() -> &'static str {
    REMEMBER_COOKIE
}

pub fn verify_php_password(password: &str, stored_hash: &str) -> bool {
    let normalized_hash = normalize_php_bcrypt_hash(stored_hash);
    verify(password, &normalized_hash).unwrap_or(false)
}

fn normalize_php_bcrypt_hash(stored_hash: &str) -> String {
    if stored_hash.starts_with("$2y$") || stored_hash.starts_with("$2a$") {
        format!("$2b${}", &stored_hash[4..])
    } else {
        stored_hash.to_string()
    }
}

fn new_login_state() -> LoginState {
    LoginState {
        csrf_token: random_hex_token(32),
        issued_at: now_timestamp(),
        nonce: String::new(),
        puzzle_x: 0,
        puzzle_y: 0,
        challenge_issued_at: 0,
        attempts: 0,
        proof: String::new(),
        verified_at: 0,
    }
}

fn reset_slider_challenge(state: &mut LoginState) {
    state.nonce.clear();
    state.puzzle_x = 0;
    state.puzzle_y = 0;
    state.challenge_issued_at = 0;
    state.attempts = 0;
    state.proof.clear();
    state.verified_at = 0;
}

#[derive(Debug, Clone)]
struct LoginPageView {
    csrf_token: String,
    site_name: String,
    site_subtitle: String,
    site_title: String,
    login_title: String,
    login_subtitle: String,
    login_badge: String,
    login_notice: String,
    contact_text: String,
    footer_text: String,
    logo_url: String,
    remembered_login_ready: bool,
    remembered_username: String,
    mascot_scenes_json: String,
}

impl LoginPageView {
    fn from_settings(
        settings: &crate::repository::SiteSettingsRow,
        csrf_token: &str,
        remembered_admin: Option<&AdminRow>,
    ) -> Self {
        let web_config = site_web_config(&settings.custom_json);
        let site_name = site_text(&settings.hostname, "授权管理系统");
        let site_subtitle = site_text(&settings.site_subtitle, "后台管理入口");
        let login_title = site_text(
            web_config
                .get("login_title")
                .and_then(Value::as_str)
                .unwrap_or(""),
            "后台登录",
        );
        let login_subtitle = site_text(
            web_config
                .get("login_subtitle")
                .and_then(Value::as_str)
                .unwrap_or(""),
            "LOGIN",
        );
        let login_badge = site_text(
            web_config
                .get("login_badge")
                .and_then(Value::as_str)
                .unwrap_or(""),
            "Welcome back",
        );
        let login_notice = site_text(
            web_config
                .get("login_notice")
                .and_then(Value::as_str)
                .unwrap_or(""),
            &settings.announcement,
        );
        let logo_url = site_image_url(
            &settings.logo_url,
            "/frontend/admin-console/js/img/brand-avatar.webp",
        );
        let mascot_scenes = json!({
            "idle": {"image": "/frontend/admin-console/js/img/login-idle.webp", "tag": login_badge},
            "privacy": {"image": "/frontend/admin-console/js/img/login-privacy.webp", "tag": "放心输入，我不会偷看密码"},
            "slider": {"image": "/frontend/admin-console/js/img/login-slider.webp", "tag": "完成一次安全验证后即可登录"},
            "verified": {"image": "/frontend/admin-console/js/img/login-verified.webp", "tag": "验证通过，可以继续登录啦"},
            "success": {"image": "/frontend/admin-console/js/img/login-success.webp", "tag": "登录成功，正在进入后台"},
            "error": {"image": "/frontend/admin-console/js/img/login-error.webp", "tag": "别急，再检查一下输入内容"}
        });
        Self {
            csrf_token: csrf_token.to_string(),
            site_title: format!("{site_name}{login_title}"),
            site_name,
            site_subtitle,
            login_title,
            login_subtitle,
            login_badge,
            login_notice,
            contact_text: site_text(&settings.contact, ""),
            footer_text: site_text(&settings.footer_text, ""),
            logo_url,
            remembered_login_ready: remembered_admin.is_some(),
            remembered_username: remembered_admin
                .map(|admin| admin.username.clone())
                .unwrap_or_default(),
            mascot_scenes_json: serde_json::to_string(&mascot_scenes)
                .unwrap_or_else(|_| "{}".to_string()),
        }
    }
}

fn render_login_html(view: &LoginPageView) -> Result<String, AppError> {
    let remembered_login_ready = if view.remembered_login_ready {
        "true"
    } else {
        "false"
    };
    let remembered_username_json = serde_json::to_string(&view.remembered_username)
        .map_err(|_| AppError::CryptoError("登录页账号序列化失败"))?;
    let notice_html = if view.login_notice.is_empty() {
        String::new()
    } else {
        format!(
            r#"<div class="login-notice">{}</div>"#,
            escape_html(&view.login_notice)
        )
    };
    let remember_checked = if view.remembered_login_ready {
        " checked"
    } else {
        ""
    };
    let remember_switch = if view.remembered_login_ready {
        r#"<a class="remember-switch" href="/admin/login/?forget_remember=1">切换账号</a>"#
    } else {
        ""
    };
    let password_placeholder = if view.remembered_login_ready {
        "已记住，无需输入"
    } else {
        "请输入密码"
    };
    let password_verify = if view.remembered_login_ready {
        r#" readonly"#
    } else {
        r#" lay-verify="required|password" lay-reqtext="密码是必填项，岂能为空？""#
    };
    Ok(format!(
        r##"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
  <title>{site_title}</title>
  <link rel="stylesheet" href="/assets/layui/css/layui.css?v=2.13.7" />
  <link rel="stylesheet" type="text/css" href="/sub_admin/css/theme.css?v=20201111001" />
  <script src="/assets/layui/layui.js?v=2.13.7"></script>
  <link rel="stylesheet" href="/assets/vendor/sliderCaptcha/slidercaptcha.css?v=20260604-slider-keyboard">
  <link rel="stylesheet" href="/sub_admin/css/login.css?v=20260608-beian-footer">
  <script src="/assets/js/mascot-breathing.js?v=20260602-breathing-algorithm" defer></script>
</head>
<body>
  <div class="login-page-decor" aria-hidden="true"></div>
  <main class="layout-main" aria-label="后台登录">
    <section class="login-visual" aria-hidden="true">
      <div class="login-brand"><div class="login-brand-mark"><img src="{logo_url}" alt="" class="login-brand-avatar"></div><div><strong>{site_name}</strong><span>{site_subtitle}</span></div></div>
      <div class="login-mascot-stage"><img src="/frontend/admin-console/js/img/login-idle.webp" alt="" class="login-mascot" id="login-scene-mascot" data-mascot-breath data-mascot-breath-amplitude="2" data-mascot-breath-period="8800"></div>
      <div class="login-visual-tag" id="login-scene-tag">{login_badge}</div>
    </section>
    <section class="login-panel">
      <div class="layout-title">{login_title}</div>
      <div class="layout-explain">{login_subtitle}</div>
      {notice_html}
      <form class="layout-content layui-form layui-form-pane" action="/admin/login/" method="post" novalidate>
        <div class="layui-form-item" style="display:none;"><input type="hidden" name="token" value="{csrf_token}"><input type="hidden" name="slider_proof" value=""><input type="hidden" name="use_remembered_login" value="{use_remembered_login}"></div>
        <div class="layui-form-item"><label class="layui-form-label"><i class="layui-icon layui-icon-username"></i></label><div class="layui-input-block"><input type="text" name="username" lay-verify="required|username" lay-reqtext="用户名是必填项，岂能为空？" class="layui-input" placeholder="请输入用户名" title="用户名" autocomplete="username" value="{remembered_username}"{username_readonly}></div></div>
        <div class="layui-form-item"><label class="layui-form-label"><i class="layui-icon layui-icon-password"></i></label><div class="layui-input-block"><input type="password" name="password" class="layui-input" placeholder="{password_placeholder}" title="登录密码" autocomplete="current-password"{password_verify}></div></div>
        <div class="login-options"><label class="remember-option" for="remember-login"><input class="remember-option-input" type="checkbox" id="remember-login" name="remember_login" value="1" lay-ignore{remember_checked}><span class="remember-option-visual"><span class="remember-option-indicator" aria-hidden="true"></span><span class="remember-option-copy"><strong>7天内记住此设备登录</strong><small>下次仍需完成安全验证</small></span></span></label>{remember_switch}</div>
        <div class="layui-form-item slider-form-item"><label class="layui-form-label"><i class="layui-icon layui-icon-vercode"></i></label><div class="layui-input-block"><div class="slider-captcha-row"><button type="button" class="slider-trigger" aria-expanded="false" aria-controls="slider-captcha-dialog"><span class="slider-trigger-text">点击完成安全验证</span><i class="layui-icon layui-icon-right slider-trigger-arrow" aria-hidden="true"></i></button></div></div></div>
        <div class="layui-form-item nob"><button class="layui-btn layui-btn-fluid layui-btn-normal" lay-submit lay-filter="submit"><i class="layui-icon layui-icon-release"></i><span>登录</span></button></div>
        <div class="extend"></div>
      </form>
      <div class="login-meta">{contact_html}{footer_html}<span>Open-source preview build</span></div>
    </section>
  </main>
  <div class="slider-dialog" id="slider-captcha-dialog" hidden>
    <div class="slider-dialog-backdrop" data-slider-close="1"></div>
    <div class="slider-dialog-panel" role="dialog" aria-modal="true" aria-labelledby="slider-dialog-title">
      <button type="button" class="slider-dialog-close" data-slider-close="1" aria-label="关闭验证弹窗"><i class="layui-icon layui-icon-close"></i></button>
      <div class="slider-dialog-header"><div class="slider-dialog-title" id="slider-dialog-title">安全验证</div><div class="slider-dialog-subtitle">拖动拼图完成一次验证后即可登录</div></div>
      <div class="slider-captcha-shell" id="slider-captcha-shell" aria-live="polite"></div>
    </div>
  </div>
<script src="/assets/vendor/sliderCaptcha/longbow.slidercaptcha.js?v=20260604-slider-keyboard"></script>
<script>
layui.use(["jquery", "form", "layer"], function() {{
  var $ = layui.$, form = layui.form, layer = layui.layer;
  window.$ = $; window.jQuery = $;
  var rememberedLoginReady = {remembered_login_ready};
  var rememberedUsername = {remembered_username_json};
  var $loginBtn = $(".layui-btn.layui-btn-fluid");
  var $tokenInput = $('input[name="token"]');
  var $usernameInput = $('input[name="username"]');
  var $passwordInput = $('input[name="password"]');
  var $rememberLoginInput = $('input[name="remember_login"]');
  var $sliderProofInput = $('input[name="slider_proof"]');
  var $useRememberedLoginInput = $('input[name="use_remembered_login"]');
  var $sliderItem = $('.slider-form-item');
  var $sliderTrigger = $('.slider-trigger');
  var $sliderTriggerText = $('.slider-trigger-text');
  var $sliderTriggerArrow = $('.slider-trigger-arrow');
  var $sliderDialog = $('.slider-dialog');
  var $sliderShell = $('.slider-captcha-shell');
  var $layoutContent = $('.layout-content');
  var $loginMascot = $('#login-scene-mascot');
  var $loginSceneTag = $('#login-scene-tag');
  var loginMascotScenes = {mascot_scenes_json};
  var sliderDialogFocusSelector = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';
  var currentLoginScene = 'idle';
  var isSubmitting = false, isSliderVerifying = false, isSliderPrefetching = false;
  var sliderNonce = '', prefetchedChallenge = null, pendingSliderChallengeRequest = null, sliderRequestVersion = 0;

  $(document).on('keydown', function(e) {{
    var keyCode = e.keyCode || e.which || e.charCode;
    if (keyCode == 27 && $sliderDialog.is(':visible') && !isSliderVerifying) {{ closeSliderDialog(true); return; }}
    if (keyCode == 9 && $sliderDialog.is(':visible')) {{ trapSliderDialogFocus(e); return; }}
    if (keyCode == 13 && $sliderDialog.is(':visible') && $(e.target).closest('#slider-captcha-dialog').length) {{ return; }}
    if (keyCode == 13 && !isSubmitting) {{ $loginBtn.trigger("click"); }}
  }});
  $('.layui-input').focus(function() {{ $(this).parent().parent().addClass('focused'); }}).blur(function() {{ $(this).parent().parent().removeClass('focused'); }});
  $loginBtn.on('mousedown', function() {{ $(this).css('transform', 'scale(0.95)'); }}).on('mouseup mouseleave', function() {{ $(this).css('transform', ''); }});

  function isRememberLoginSelected() {{ return $rememberLoginInput.prop('checked'); }}
  function syncRememberedLoginMode() {{
    var useRememberedLogin = rememberedLoginReady && isRememberLoginSelected();
    $useRememberedLoginInput.val(useRememberedLogin ? '1' : '0');
    $usernameInput.prop('readonly', useRememberedLogin);
    $passwordInput.prop('readonly', useRememberedLogin);
    $passwordInput.attr('placeholder', useRememberedLogin ? '已记住，无需输入' : '请输入密码');
    if (useRememberedLogin) {{
      $usernameInput.val(rememberedUsername);
      $passwordInput.val('');
      $passwordInput.removeAttr('lay-verify').removeAttr('lay-reqtext');
    }} else {{
      $passwordInput.attr('lay-verify', 'required|password').attr('lay-reqtext', '密码是必填项，岂能为空？');
    }}
    updateLoginMascotScene();
  }}
  function loginScene(name) {{ return loginMascotScenes[name] || loginMascotScenes.idle; }}
  function setLoginMascotScene(name) {{
    var scene = loginScene(name);
    if (currentLoginScene === name && $loginMascot.attr('src') === scene.image) {{ return; }}
    currentLoginScene = name;
    $loginMascot.attr('src', scene.image);
    $loginSceneTag.text(scene.tag || '');
  }}
  function updateLoginMascotScene() {{
    if ($sliderProofInput.val()) {{ setLoginMascotScene('verified'); return; }}
    if ($sliderDialog.is(':visible') || isSliderVerifying) {{ setLoginMascotScene('slider'); return; }}
    if ($useRememberedLoginInput.val() !== '1' && ($.trim($usernameInput.val()) !== '' || $.trim($passwordInput.val()) !== '')) {{ setLoginMascotScene('privacy'); return; }}
    setLoginMascotScene('idle');
  }}
  function sliderMessage(xhr, fallbackMessage) {{ return xhr && xhr.responseJSON && xhr.responseJSON.msg ? xhr.responseJSON.msg : fallbackMessage; }}
  function showSliderPlaceholder(message, isError) {{ $sliderShell.removeClass('is-verified').addClass('is-loading').html('<div class="slider-captcha-placeholder' + (isError ? ' slider-captcha-error' : '') + '">' + message + '</div>'); }}
  function isChallengeReady(challenge) {{
    if (!challenge || !challenge.nonce || !challenge.fetchedAt) {{ return false; }}
    var expiresIn = Number(challenge.expires_in || 0);
    return Date.now() - challenge.fetchedAt < Math.max((expiresIn - 15) * 1000, 30000);
  }}
  function isActiveSliderRequest(requestVersion) {{ return requestVersion === sliderRequestVersion; }}
  function abortPendingSliderChallenge() {{ if (pendingSliderChallengeRequest && typeof pendingSliderChallengeRequest.abort === 'function') {{ pendingSliderChallengeRequest.abort(); }} pendingSliderChallengeRequest = null; isSliderPrefetching = false; }}
  function applyVerifiedSliderProof(response) {{
    if (!response || !response.verified || !response.proof) {{ return false; }}
    sliderRequestVersion++; abortPendingSliderChallenge(); $sliderProofInput.val(response.proof);
    $sliderShell.addClass('is-verified'); $sliderItem.addClass('slider-verified'); isSliderVerifying = false;
    setSliderTriggerState('verified'); closeSliderDialog(true); updateLoginMascotScene(); return true;
  }}
  function rememberChallenge(challenge) {{
    if (!challenge) {{ prefetchedChallenge = null; return; }}
    challenge.fetchedAt = Date.now(); prefetchedChallenge = challenge;
    if (challenge.image_url) {{ var img = new Image(); img.src = challenge.image_url; }}
  }}
  function consumePrefetchedChallenge() {{ if (!isChallengeReady(prefetchedChallenge)) {{ prefetchedChallenge = null; return null; }} var challenge = prefetchedChallenge; prefetchedChallenge = null; return challenge; }}
  function openSliderDialog() {{ $sliderDialog.removeAttr('hidden').addClass('is-open'); $('body').addClass('slider-dialog-open'); $sliderTrigger.attr('aria-expanded', 'true'); updateLoginMascotScene(); }}
  function focusSliderHandle() {{ setTimeout(function() {{ var sliderHandle = $sliderShell.find('.slider').get(0); if (sliderHandle) {{ sliderHandle.focus(); }} }}, 0); }}
  function sliderDialogFocusableElements() {{ return $sliderDialog.find(sliderDialogFocusSelector).filter(function() {{ return $(this).is(':visible') && !this.disabled; }}); }}
  function trapSliderDialogFocus(e) {{
    var focusableElements = sliderDialogFocusableElements(); if (!focusableElements.length) {{ return; }}
    var firstElement = focusableElements.get(0), lastElement = focusableElements.get(focusableElements.length - 1);
    if (!$.contains($sliderDialog.get(0), document.activeElement)) {{ e.preventDefault(); firstElement.focus(); return; }}
    if (e.shiftKey && document.activeElement === firstElement) {{ e.preventDefault(); lastElement.focus(); return; }}
    if (!e.shiftKey && document.activeElement === lastElement) {{ e.preventDefault(); firstElement.focus(); }}
  }}
  function closeSliderDialog(focusTrigger) {{
    if (isSliderVerifying) {{ return; }}
    $sliderDialog.attr('hidden', 'hidden').removeClass('is-open'); $('body').removeClass('slider-dialog-open');
    $sliderTrigger.attr('aria-expanded', 'false'); $sliderShell.removeClass('is-loading is-verified').empty(); $sliderItem.removeClass('slider-open');
    updateLoginMascotScene(); if (focusTrigger) {{ $sliderTrigger.trigger('focus'); }}
  }}
  function setSliderTriggerState(state) {{
    $sliderTrigger.removeClass('is-open is-loading is-verified').prop('disabled', false);
    $sliderTrigger.attr('aria-expanded', $sliderDialog.is(':visible') ? 'true' : 'false'); $sliderTriggerArrow.removeClass('is-hidden');
    if (state === 'loading') {{ $sliderTrigger.addClass('is-open is-loading'); $sliderTriggerText.text('正在准备验证'); return; }}
    if (state === 'verifying') {{ $sliderTrigger.addClass('is-open is-loading').prop('disabled', true); $sliderTriggerText.text('正在校验拼图验证'); return; }}
    if (state === 'open') {{ $sliderTrigger.addClass('is-open'); $sliderTriggerText.text('请完成拼图验证'); return; }}
    if (state === 'verified') {{ $sliderTrigger.addClass('is-verified'); $sliderTriggerArrow.addClass('is-hidden'); $sliderTriggerText.text('验证成功'); return; }}
    $sliderTriggerText.text('点击完成安全验证');
  }}
  function setPuzzleText(text) {{ $sliderShell.find('.sliderText').text(text); }}
  function renderSliderCaptcha(challenge) {{
    $sliderItem.removeClass('slider-verified').addClass('slider-open'); openSliderDialog();
    $sliderShell.removeClass('is-loading is-verified').html('<div id="admin-slider-puzzle" class="slider-captcha-widget" role="group" aria-label="拼图滑块验证"></div>');
    sliderCaptcha({{
      id: 'admin-slider-puzzle', width: challenge.width || 300, height: challenge.height || 170, sliderL: 34, sliderR: 7, offset: challenge.offset || 8, maxLoadCount: 1,
      loadingText: '正在加载拼图...', failedText: '拼图未对齐，请重试', barText: '向右拖动拼图完成验证',
      imageUrl: challenge.image_url, puzzleX: challenge.puzzle_x, puzzleY: challenge.puzzle_y,
      onRefresh: function() {{ requestSliderChallenge(true, function(nextChallenge) {{ sliderNonce = nextChallenge.nonce; setSliderTriggerState('open'); renderSliderCaptcha(nextChallenge); }}); }},
      onSuccess: function(result) {{ verifySliderChallenge(result); }}
    }});
    focusSliderHandle();
  }}
  function resetSliderState(focusTrigger) {{ sliderRequestVersion++; abortPendingSliderChallenge(); sliderNonce = ''; isSliderVerifying = false; $sliderProofInput.val(''); $sliderItem.removeClass('slider-verified'); closeSliderDialog(focusTrigger); setSliderTriggerState('idle'); }}
  function requestSliderChallenge(silent, callback) {{
    if ($sliderProofInput.val()) {{ setSliderTriggerState('verified'); closeSliderDialog(false); return; }}
    var requestVersion = sliderRequestVersion;
    if (pendingSliderChallengeRequest) {{
      setSliderTriggerState('loading'); openSliderDialog(); showSliderPlaceholder('正在准备拼图验证...', false);
      pendingSliderChallengeRequest.then(function(res) {{ handleChallengeResponse(res, requestVersion, callback); }}).fail(function(xhr) {{ handleChallengeError(xhr, requestVersion, silent); }});
      return;
    }}
    setSliderTriggerState('loading'); openSliderDialog(); showSliderPlaceholder('正在准备拼图验证...', false);
    pendingSliderChallengeRequest = $.ajax({{ url: '/admin/login/?slider=challenge', type: 'GET', dataType: 'json', cache: false,
      success: function(res) {{ handleChallengeResponse(res, requestVersion, callback); }},
      error: function(xhr) {{ handleChallengeError(xhr, requestVersion, silent); }},
      complete: function() {{ if (isActiveSliderRequest(requestVersion)) {{ pendingSliderChallengeRequest = null; }} }}
    }});
  }}
  function handleChallengeResponse(res, requestVersion, callback) {{
    if (!isActiveSliderRequest(requestVersion)) {{ return; }}
    if (applyVerifiedSliderProof(res)) {{ return; }}
    if (res.code != "1" || !res.nonce) {{ layer.msg(res.msg || '拼图验证初始化失败，请刷新页面重试', {{icon: 5}}); showSliderPlaceholder('拼图验证加载失败', true); setSliderTriggerState('idle'); return; }}
    res.fetchedAt = Date.now();
    if (typeof callback === 'function') {{ callback(res); return; }}
    rememberChallenge(res); setSliderTriggerState('idle'); closeSliderDialog(false);
  }}
  function handleChallengeError(xhr, requestVersion, silent) {{
    if (!isActiveSliderRequest(requestVersion)) {{ return; }}
    if (!silent) {{ layer.msg(sliderMessage(xhr, '拼图验证初始化失败，请刷新页面重试'), {{icon: 5}}); }}
    showSliderPlaceholder('拼图验证加载失败', true); setSliderTriggerState('idle');
  }}
  function preloadSliderChallenge() {{
    if (isSliderPrefetching || pendingSliderChallengeRequest || isChallengeReady(prefetchedChallenge) || $sliderProofInput.val()) {{ return; }}
    var requestVersion = sliderRequestVersion; isSliderPrefetching = true;
    pendingSliderChallengeRequest = $.ajax({{ url: '/admin/login/?slider=challenge', type: 'GET', dataType: 'json', cache: false,
      success: function(res) {{ if (!isActiveSliderRequest(requestVersion)) {{ return; }} if (applyVerifiedSliderProof(res)) {{ return; }} if (res.code == "1" && res.nonce) {{ rememberChallenge(res); }} }},
      complete: function() {{ if (isActiveSliderRequest(requestVersion)) {{ isSliderPrefetching = false; pendingSliderChallengeRequest = null; }} }}
    }});
  }}
  function openSliderVerification() {{
    if (isSliderVerifying || $sliderTrigger.hasClass('is-verified')) {{ return; }}
    var challenge = consumePrefetchedChallenge();
    if (challenge) {{ sliderNonce = challenge.nonce; setSliderTriggerState('open'); renderSliderCaptcha(challenge); return; }}
    sliderNonce = ''; requestSliderChallenge(false, function(res) {{ sliderNonce = res.nonce; setSliderTriggerState('open'); renderSliderCaptcha(res); }});
  }}
  function verifySliderChallenge(result) {{
    if (isSliderVerifying) {{ return; }}
    if (!sliderNonce) {{ openSliderVerification(); return; }}
    isSliderVerifying = true; setSliderTriggerState('verifying'); setPuzzleText('正在校验...');
    $.ajax({{ url: '/admin/login/?slider=verify', type: 'POST', dataType: 'json',
      data: {{ token: $tokenInput.val(), nonce: sliderNonce, left: result && typeof result.left !== 'undefined' ? result.left : '', trail: JSON.stringify(result && result.trail ? result.trail : []) }},
      success: function(res) {{
        if (res.code == "1" && res.proof) {{ sliderRequestVersion++; abortPendingSliderChallenge(); $sliderProofInput.val(res.proof); $sliderShell.addClass('is-verified'); $sliderItem.addClass('slider-verified'); setPuzzleText('验证通过'); isSliderVerifying = false; setSliderTriggerState('verified'); updateLoginMascotScene(); setTimeout(function() {{ closeSliderDialog(true); }}, 420); return; }}
        setLoginMascotScene('error'); layer.msg(res.msg || '拼图验证失败，请重试', {{icon: 5}}); isSliderVerifying = false; requestSliderChallenge(true, function(nextChallenge) {{ sliderNonce = nextChallenge.nonce; setSliderTriggerState('open'); renderSliderCaptcha(nextChallenge); }});
      }},
      error: function(xhr) {{ setLoginMascotScene('error'); layer.msg(sliderMessage(xhr, '拼图验证失败，请重试'), {{icon: 5}}); isSliderVerifying = false; requestSliderChallenge(true, function(nextChallenge) {{ sliderNonce = nextChallenge.nonce; setSliderTriggerState('open'); renderSliderCaptcha(nextChallenge); }}); }}
    }});
  }}
  $sliderTrigger.on('click', openSliderVerification);
  $rememberLoginInput.on('change', syncRememberedLoginMode);
  $usernameInput.on('input change', updateLoginMascotScene); $passwordInput.on('input change', updateLoginMascotScene);
  $sliderDialog.on('click', '[data-slider-close="1"]', function() {{ if ($sliderTrigger.hasClass('is-verified')) {{ closeSliderDialog(true); return; }} resetSliderState(true); preloadSliderChallenge(); }});
  form.verify({{ username: function(value) {{ if ($useRememberedLoginInput.val() !== '1' && value.length < 3) {{ return '用户名长度不能小于3个字符'; }} }}, password: function(value) {{ if ($useRememberedLoginInput.val() !== '1' && value.length < 6) {{ return '密码长度不能小于6个字符'; }} }} }});
  form.on("submit(submit)", function(data) {{
    if (isSubmitting) return false; isSubmitting = true;
    if (!$tokenInput.val()) {{ layer.msg("验证信息缺失，请刷新页面重试", {{icon: 5}}); isSubmitting = false; return false; }}
    if (!$sliderProofInput.val()) {{ layer.msg("请先点击验证按钮完成安全验证", {{icon: 5}}); $sliderTrigger.trigger('click'); isSubmitting = false; return false; }}
    var username = $usernameInput.val(), password = $passwordInput.val(), usingRememberedLogin = rememberedLoginReady && $useRememberedLoginInput.val() === '1';
    if (!usingRememberedLogin && username.length < 3) {{ layer.msg("用户名长度不能小于3个字符", {{icon: 5}}); isSubmitting = false; return false; }}
    if (!usingRememberedLogin && password.length < 6) {{ layer.msg("密码长度不能小于6个字符", {{icon: 5}}); isSubmitting = false; return false; }}
    data.field.token = $tokenInput.val(); data.field.slider_proof = $sliderProofInput.val(); $layoutContent.css('opacity', '0.8');
    $.ajax({{ url: "/admin/login/", type: "POST", dataType: "json", data: data.field, timeout: 10000, cache: false,
      beforeSend: function() {{ layer.msg("正在登录", {{icon: 16, shade: 0.05, time: false}}); }},
      success: function(res) {{ if (res.code == "1") {{ setLoginMascotScene('success'); layer.msg(res.msg, {{icon: 1}}); setTimeout(function() {{ window.location.href = "/admin/console/"; }}, 650); }} else {{ setLoginMascotScene('error'); layer.msg(res.msg || "登录失败，请重试", {{icon: 5}}); resetSliderState(); preloadSliderChallenge(); }} }},
      error: function(xhr, status) {{ var errorMsg = "登录请求失败，请检查验证码后重试"; if (xhr.responseJSON && xhr.responseJSON.msg) {{ errorMsg = xhr.responseJSON.msg; }} else if (status === "timeout") {{ errorMsg = "登录请求超时，请稍后重试"; }} setLoginMascotScene('error'); layer.msg(errorMsg, {{icon: 5}}); resetSliderState(); preloadSliderChallenge(); }},
      complete: function() {{ isSubmitting = false; $layoutContent.css('opacity', '1'); }}
    }});
    return false;
  }});
  syncRememberedLoginMode(); setSliderTriggerState('idle'); preloadSliderChallenge(); updateLoginMascotScene();
}});
</script>
</body>
</html>"##,
        site_title = escape_html(&view.site_title),
        logo_url = escape_html(&view.logo_url),
        site_name = escape_html(&view.site_name),
        site_subtitle = escape_html(&view.site_subtitle),
        login_badge = escape_html(&view.login_badge),
        login_title = escape_html(&view.login_title),
        login_subtitle = escape_html(&view.login_subtitle),
        notice_html = notice_html,
        csrf_token = escape_html(&view.csrf_token),
        use_remembered_login = if view.remembered_login_ready {
            "1"
        } else {
            "0"
        },
        remembered_username = escape_html(&view.remembered_username),
        username_readonly = if view.remembered_login_ready {
            " readonly"
        } else {
            ""
        },
        password_placeholder = password_placeholder,
        password_verify = password_verify,
        remember_checked = remember_checked,
        remember_switch = remember_switch,
        contact_html = optional_meta_span(&view.contact_text),
        footer_html = optional_meta_span(&view.footer_text),
        remembered_login_ready = remembered_login_ready,
        remembered_username_json = remembered_username_json,
        mascot_scenes_json = view.mascot_scenes_json,
    ))
}

fn login_body(code: &str, message: &str, data: serde_json::Value) -> LoginJsonBody {
    let data = match data {
        serde_json::Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    LoginJsonBody {
        code: code.to_string(),
        msg: message.to_string(),
        data,
    }
}

fn login_error_with_cookie(message: &str, cookie: String) -> LoginResponse {
    LoginResponse {
        body: login_body("-1", message, json!({})),
        cookies: vec![cookie],
    }
}

fn active_slider_proof(state: &LoginState) -> bool {
    !state.proof.is_empty() && !expired(state.verified_at, SLIDER_PROOF_TTL_SECONDS)
}

fn remember_login_active(admin: &AdminRow) -> bool {
    !admin.remember_login_token_hash.trim().is_empty()
        && admin
            .remember_login_expires_at
            .is_some_and(|expires_at| expires_at > Local::now().naive_local())
}

#[derive(Debug, Clone, Copy)]
struct SliderImageSource {
    id: &'static str,
    name: &'static str,
    api_url: &'static str,
    json_path: &'static [&'static str],
    allowed_hosts: &'static [&'static str],
}

#[derive(Debug, Clone)]
struct ResolvedSliderImage {
    url: String,
}

#[derive(Debug, Clone)]
struct SliderImageCachePaths {
    cache_file: PathBuf,
    image_directory: PathBuf,
}

impl SliderImageCachePaths {
    fn image_path(&self, image_id: &str) -> PathBuf {
        self.image_directory.join(format!("{image_id}.jpg"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SliderImagePool {
    generated_at: i64,
    expires_at: i64,
    rotation_seconds: i64,
    items: Vec<SliderImagePoolItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SliderImagePoolItem {
    source_id: String,
    source_name: String,
    image_id: String,
    image_version: String,
    image_url: String,
}

async fn resolve_slider_image(public_root: &Path) -> Result<ResolvedSliderImage, String> {
    let paths = slider_image_cache_paths(public_root);
    ensure_slider_image_pool_paths(&paths).await?;
    if let Some(pool) = read_slider_image_pool(&paths).await? {
        return pick_slider_image_pool_item(&pool);
    }

    Err("拼图图片池正在后台预热，请稍后重试".to_string())
}

fn slider_image_pool_lock() -> &'static tokio::sync::Mutex<()> {
    SLIDER_IMAGE_POOL_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

async fn refresh_slider_image_pool_or_current_pool(
    paths: &SliderImageCachePaths,
    current_pool: SliderImagePool,
) -> SliderImagePool {
    match refresh_slider_image_pool(paths).await {
        Ok(pool) => pool,
        Err(error) => {
            tracing::warn!(%error, "admin slider image pool refresh failed");
            current_pool
        }
    }
}

async fn refresh_slider_image_pool(
    paths: &SliderImageCachePaths,
) -> Result<SliderImagePool, String> {
    let client = slider_image_http_client()?;
    let pool = create_slider_image_pool(paths, &client).await?;
    write_slider_image_pool(paths, &pool).await?;
    Ok(pool)
}

fn slider_image_pool_refresh_due(pool: &SliderImagePool) -> bool {
    pool.expires_at <= now_timestamp() + SLIDER_IMAGE_POOL_REFRESH_LEAD_SECONDS
}

fn slider_image_http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(StdDuration::from_secs(SLIDER_IMAGE_HTTP_TIMEOUT_SECONDS))
        .connect_timeout(StdDuration::from_secs(
            SLIDER_IMAGE_HTTP_CONNECT_TIMEOUT_SECONDS,
        ))
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
        .map_err(|_| "拼图图片源初始化失败".to_string())
}

async fn read_slider_image_pool(
    paths: &SliderImageCachePaths,
) -> Result<Option<SliderImagePool>, String> {
    let pool_json = match fs::read_to_string(&paths.cache_file).await {
        Ok(pool_json) => pool_json,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("拼图图片池读取失败".to_string()),
    };
    let pool = serde_json::from_str::<SliderImagePool>(&pool_json)
        .map_err(|_| "拼图图片池格式错误".to_string())?;
    let original_count = pool.items.len();
    let normalized_pool = normalize_slider_image_pool(paths, pool).await;
    if let Some(pool) = &normalized_pool
        && pool.items.len() != original_count
    {
        write_slider_image_pool(paths, pool).await?;
    }
    Ok(normalized_pool)
}

async fn normalize_slider_image_pool(
    paths: &SliderImageCachePaths,
    pool: SliderImagePool,
) -> Option<SliderImagePool> {
    if pool.generated_at <= 0
        || pool.expires_at <= pool.generated_at
        || pool.rotation_seconds <= 0
        || pool.items.is_empty()
    {
        return None;
    }

    let mut items = Vec::new();
    for item in pool.items {
        if let Some(item) = normalize_slider_image_pool_item(paths, item).await {
            items.push(item);
            if items.len() >= SLIDER_IMAGE_POOL_SIZE {
                break;
            }
        }
    }
    if items.is_empty() {
        return None;
    }

    Some(SliderImagePool {
        generated_at: pool.generated_at,
        expires_at: pool.expires_at,
        rotation_seconds: pool.rotation_seconds,
        items,
    })
}

async fn normalize_slider_image_pool_item(
    paths: &SliderImageCachePaths,
    item: SliderImagePoolItem,
) -> Option<SliderImagePoolItem> {
    let source_id = item.source_id.trim();
    let source_name = item.source_name.trim();
    let image_id = slider_image_id(&item.image_id).ok()?;
    let image_version = slider_image_id(&item.image_version).ok()?;
    if source_id.is_empty()
        || source_name.is_empty()
        || image_version != image_id
        || !slider_image_cache_ready(paths, &image_id).await
    {
        return None;
    }

    Some(SliderImagePoolItem {
        source_id: source_id.to_string(),
        source_name: source_name.to_string(),
        image_id: image_id.clone(),
        image_version: image_version.clone(),
        image_url: slider_image_api_url(source_id, &image_id),
    })
}

async fn create_slider_image_pool(
    paths: &SliderImageCachePaths,
    client: &reqwest::Client,
) -> Result<SliderImagePool, String> {
    let sources = slider_image_sources();
    if sources.is_empty() {
        return Err("拼图图片源配置不能为空".to_string());
    }

    let mut items = Vec::new();
    let mut image_ids = HashSet::new();
    let mut attempts = 0;
    let mut last_error = "所有拼图图片源都不可用".to_string();
    while items.len() < SLIDER_IMAGE_POOL_SIZE && attempts < SLIDER_IMAGE_POOL_MAX_ATTEMPTS {
        let remaining_attempts = SLIDER_IMAGE_POOL_MAX_ATTEMPTS - attempts;
        let remaining_items = SLIDER_IMAGE_POOL_SIZE - items.len();
        let batch_size =
            slider_image_pool_batch_size(remaining_items, sources.len()).min(remaining_attempts);
        let batch_sources = slider_image_source_batch(&sources, batch_size);
        attempts += batch_sources.len();
        collect_slider_image_pool_results(
            &mut items,
            &mut image_ids,
            fetch_slider_image_pool_batch(paths, client, batch_sources).await,
            &mut last_error,
        );
    }
    finalize_slider_image_pool(items, &last_error)
}

fn finalize_slider_image_pool(
    items: Vec<SliderImagePoolItem>,
    last_error: &str,
) -> Result<SliderImagePool, String> {
    if items.len() != SLIDER_IMAGE_POOL_SIZE {
        return Err(format!(
            "拼图图片池构建失败，仅成功缓存 {}/{} 张图片：{}",
            items.len(),
            SLIDER_IMAGE_POOL_SIZE,
            last_error
        ));
    }

    let generated_at = now_timestamp();
    Ok(SliderImagePool {
        generated_at,
        expires_at: generated_at + SLIDER_IMAGE_POOL_ROTATION_SECONDS,
        rotation_seconds: SLIDER_IMAGE_POOL_ROTATION_SECONDS,
        items,
    })
}

fn slider_image_pool_batch_size(remaining_items: usize, source_count: usize) -> usize {
    source_count
        .max(remaining_items + 6)
        .min(SLIDER_IMAGE_POOL_BATCH_SIZE)
}

fn slider_image_source_batch(
    sources: &[SliderImageSource],
    batch_size: usize,
) -> Vec<SliderImageSource> {
    let mut plan = Vec::with_capacity(batch_size);
    let mut pool = sources.to_vec();
    while plan.len() < batch_size {
        pool.shuffle(&mut rand::thread_rng());
        for source in pool.iter().copied() {
            plan.push(source);
            if plan.len() >= batch_size {
                break;
            }
        }
    }
    plan
}

async fn fetch_slider_image_pool_batch(
    paths: &SliderImageCachePaths,
    client: &reqwest::Client,
    sources: Vec<SliderImageSource>,
) -> Vec<Result<SliderImagePoolItem, String>> {
    let mut tasks = tokio::task::JoinSet::new();
    for source in sources {
        let paths = paths.clone();
        let client = client.clone();
        tasks.spawn(async move { create_slider_image_pool_item(&paths, &client, source).await });
    }

    let mut results = Vec::new();
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(item) => results.push(item),
            Err(_) => results.push(Err("拼图图片任务执行失败".to_string())),
        }
    }
    results
}

fn collect_slider_image_pool_results(
    items: &mut Vec<SliderImagePoolItem>,
    image_ids: &mut HashSet<String>,
    results: Vec<Result<SliderImagePoolItem, String>>,
    last_error: &mut String,
) {
    for result in results {
        if items.len() >= SLIDER_IMAGE_POOL_SIZE {
            break;
        }
        match result {
            Ok(item) if image_ids.insert(item.image_id.clone()) => items.push(item),
            Ok(_) => {}
            Err(message) => *last_error = message,
        }
    }
}

async fn create_slider_image_pool_item(
    paths: &SliderImageCachePaths,
    client: &reqwest::Client,
    source: SliderImageSource,
) -> Result<SliderImagePoolItem, String> {
    let payload = fetch_slider_image_index(client, source).await?;
    let image_url = json_path_string(&payload, source.json_path)
        .ok_or_else(|| "远程拼图图片索引缺少图片地址".to_string())?;
    assert_slider_image_url(&image_url, source.allowed_hosts)?;
    let raw_bytes = fetch_slider_image(client, &image_url).await?;
    let bytes = build_slider_captcha_image_jpeg(&raw_bytes)?;
    let image_id = crypto::sha256_hex_bytes(&bytes);
    if !slider_image_cache_ready(paths, &image_id).await {
        fs::write(paths.image_path(&image_id), &bytes)
            .await
            .map_err(|_| "拼图图片缓存写入失败".to_string())?;
    }
    Ok(SliderImagePoolItem {
        source_id: source.id.to_string(),
        source_name: source.name.to_string(),
        image_id: image_id.clone(),
        image_version: image_id.clone(),
        image_url: slider_image_api_url(source.id, &image_id),
    })
}

async fn fetch_slider_image_index(
    client: &reqwest::Client,
    source: SliderImageSource,
) -> Result<Value, String> {
    client
        .get(source.api_url)
        .header(
            reqwest::header::ACCEPT,
            "application/json,text/json,text/plain;q=0.9",
        )
        .send()
        .await
        .map_err(|_| "远程拼图图片索引连接失败".to_string())?
        .error_for_status()
        .map_err(|_| "远程拼图图片索引状态异常".to_string())?
        .json::<Value>()
        .await
        .map_err(|_| "远程拼图图片索引格式错误".to_string())
}

fn pick_slider_image_pool_item(pool: &SliderImagePool) -> Result<ResolvedSliderImage, String> {
    pool.items
        .choose(&mut rand::thread_rng())
        .map(|item| ResolvedSliderImage {
            url: item.image_url.clone(),
        })
        .ok_or_else(|| "拼图图片池为空".to_string())
}

async fn write_slider_image_pool(
    paths: &SliderImageCachePaths,
    pool: &SliderImagePool,
) -> Result<(), String> {
    let pool_json = serde_json::to_vec(pool).map_err(|_| "拼图图片池序列化失败".to_string())?;
    fs::write(&paths.cache_file, pool_json)
        .await
        .map_err(|_| "拼图图片池写入失败".to_string())
}

async fn ensure_slider_image_pool_paths(paths: &SliderImageCachePaths) -> Result<(), String> {
    if let Some(cache_directory) = paths.cache_file.parent() {
        fs::create_dir_all(cache_directory)
            .await
            .map_err(|_| "拼图图片池目录创建失败".to_string())?;
    }
    fs::create_dir_all(&paths.image_directory)
        .await
        .map_err(|_| "拼图图片缓存目录创建失败".to_string())
}

async fn slider_image_cache_ready(paths: &SliderImageCachePaths, image_id: &str) -> bool {
    let Ok(bytes) = fs::read(paths.image_path(image_id)).await else {
        return false;
    };
    !bytes.is_empty() && crypto::sha256_hex_bytes(&bytes) == image_id
}

async fn prune_slider_image_cache(
    paths: &SliderImageCachePaths,
    pool: &SliderImagePool,
) -> Result<usize, String> {
    let active_image_ids = pool
        .items
        .iter()
        .map(|item| item.image_id.as_str())
        .collect::<HashSet<_>>();
    let expired_before = now_timestamp() - SLIDER_IMAGE_CACHE_RETENTION_SECONDS;
    let mut removed_count = 0;
    let mut entries = fs::read_dir(&paths.image_directory)
        .await
        .map_err(|_| "拼图图片缓存目录读取失败".to_string())?;
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|_| "拼图图片缓存目录读取失败".to_string())?
    {
        let Ok(file_type) = entry.file_type().await else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }
        let file_name = entry.file_name().to_string_lossy().to_string();
        let Some(image_id) = cached_slider_image_id(&file_name) else {
            continue;
        };
        if active_image_ids.contains(image_id.as_str()) {
            continue;
        }
        let Ok(metadata) = entry.metadata().await else {
            continue;
        };
        if modified_timestamp(&metadata) >= expired_before {
            continue;
        }
        fs::remove_file(entry.path())
            .await
            .map_err(|_| "过期拼图图片缓存清理失败".to_string())?;
        removed_count += 1;
    }
    Ok(removed_count)
}

fn cached_slider_image_id(file_name: &str) -> Option<String> {
    let image_id = file_name.strip_suffix(".jpg")?;
    slider_image_id(image_id).ok()
}

fn modified_timestamp(metadata: &std::fs::Metadata) -> i64 {
    metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

async fn fetch_slider_image(client: &reqwest::Client, image_url: &str) -> Result<Vec<u8>, String> {
    let response = client
        .get(image_url)
        .header(
            reqwest::header::ACCEPT,
            "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
        )
        .send()
        .await
        .map_err(|_| "远程拼图图片连接失败".to_string())?
        .error_for_status()
        .map_err(|_| "远程拼图图片状态异常".to_string())?;
    response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(normalize_content_type)
        .filter(|value| valid_image_content_type(value))
        .ok_or_else(|| "远程拼图图片类型不支持".to_string())?;
    let bytes = response
        .bytes()
        .await
        .map_err(|_| "远程拼图图片读取失败".to_string())?;
    if bytes.is_empty() || bytes.len() as u64 > SLIDER_IMAGE_MAX_BYTES {
        return Err("远程拼图图片大小无效".to_string());
    }
    Ok(bytes.to_vec())
}

fn build_slider_captcha_image_jpeg(binary: &[u8]) -> Result<Vec<u8>, String> {
    let source = image::load_from_memory(binary)
        .map_err(|_| "拼图图片解码失败".to_string())?
        .to_rgb8();
    let source_width = source.width();
    let source_height = source.height();
    if source_width == 0 || source_height == 0 {
        return Err("拼图图片尺寸无效".to_string());
    }

    let target_width = SLIDER_WIDTH as u32;
    let target_height = SLIDER_HEIGHT as u32;
    let scale = f64::max(
        target_width as f64 / source_width as f64,
        target_height as f64 / source_height as f64,
    );
    let scaled_width = (source_width as f64 * scale).ceil() as u32;
    let scaled_height = (source_height as f64 * scale).ceil() as u32;
    let resized = resize(
        &source,
        scaled_width.max(target_width),
        scaled_height.max(target_height),
        FilterType::Lanczos3,
    );
    let crop_x = (resized.width() - target_width) / 2;
    let crop_y = (resized.height() - target_height) / 2;
    let cropped = crop_imm(&resized, crop_x, crop_y, target_width, target_height).to_image();
    let mut jpeg = Vec::new();
    JpegEncoder::new_with_quality(&mut jpeg, SLIDER_IMAGE_JPEG_QUALITY)
        .encode_image(&cropped)
        .map_err(|_| "拼图图片编码失败".to_string())?;
    if jpeg.is_empty() {
        return Err("拼图图片编码失败".to_string());
    }
    Ok(jpeg)
}

fn slider_image_cache_paths(public_root: &Path) -> SliderImageCachePaths {
    let project_root = public_root
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let directory = project_root
        .join("storage")
        .join("cache")
        .join("admin-slider-image-pool");
    SliderImageCachePaths {
        cache_file: directory.join("pool.json"),
        image_directory: directory.join("images"),
    }
}

fn slider_image_api_url(source_id: &str, image_id: &str) -> String {
    format!(
        "/admin/login/?slider=image&source={source_id}&image={image_id}&version={image_id}&name={source_id}.jpg"
    )
}

fn slider_image_pool_status(pool: &SliderImagePool, status: &str, removed_count: usize) -> Value {
    let sources = slider_image_sources();
    json!({
        "status": status,
        "source_count": sources.len(),
        "cached_count": pool.items.len(),
        "removed_count": removed_count,
        "source_ids": sources.iter().map(|source| source.id).collect::<Vec<_>>(),
        "generated_at": pool.generated_at,
        "expires_at": pool.expires_at,
    })
}

fn slider_image_id(value: &str) -> Result<String, AppError> {
    let image_id = value.trim();
    if image_id.len() == 64
        && image_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Ok(image_id.to_string());
    }
    Err(AppError::InvalidInput("拼图图片标识无效"))
}

fn json_path_string(payload: &Value, path: &[&str]) -> Option<String> {
    let mut current = payload;
    for key in path {
        current = if let Ok(index) = key.parse::<usize>() {
            current.get(index)?
        } else {
            current.get(*key)?
        };
    }
    current
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn assert_slider_image_url(url: &str, allowed_hosts: &[&str]) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url).map_err(|_| "远程拼图图片地址格式错误".to_string())?;
    if parsed.scheme() != "https" {
        return Err("远程拼图图片地址必须使用 HTTPS".to_string());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "远程拼图图片地址缺少主机名".to_string())?;
    if allowed_hosts
        .iter()
        .any(|allowed_host| host_matches(allowed_host, host))
    {
        return Ok(());
    }
    Err("远程拼图图片主机不在白名单".to_string())
}

fn host_matches(rule: &str, host: &str) -> bool {
    if let Some(suffix) = rule.strip_prefix("*.") {
        return host == suffix || host.ends_with(&format!(".{suffix}"));
    }
    host == rule
}

fn normalize_content_type(value: &str) -> String {
    value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

fn valid_image_content_type(value: &str) -> bool {
    matches!(
        value,
        "image/jpeg"
            | "image/jpg"
            | "image/png"
            | "image/webp"
            | "image/gif"
            | "application/octet-stream"
    )
}

fn slider_image_sources() -> Vec<SliderImageSource> {
    vec![
        SliderImageSource {
            id: "nekos_best_waifu",
            name: "nekos.best waifu",
            api_url: "https://nekos.best/api/v2/waifu",
            json_path: &["results", "0", "url"],
            allowed_hosts: &["nekos.best"],
        },
        SliderImageSource {
            id: "nekos_best_neko",
            name: "nekos.best neko",
            api_url: "https://nekos.best/api/v2/neko",
            json_path: &["results", "0", "url"],
            allowed_hosts: &["nekos.best"],
        },
        SliderImageSource {
            id: "nekos_best_kitsune",
            name: "nekos.best kitsune",
            api_url: "https://nekos.best/api/v2/kitsune",
            json_path: &["results", "0", "url"],
            allowed_hosts: &["nekos.best"],
        },
        SliderImageSource {
            id: "nekos_best_husbando",
            name: "nekos.best husbando",
            api_url: "https://nekos.best/api/v2/husbando",
            json_path: &["results", "0", "url"],
            allowed_hosts: &["nekos.best"],
        },
        SliderImageSource {
            id: "waifu_im_uniform",
            name: "waifu.im uniform",
            api_url: "https://api.waifu.im/images?IncludedTags=uniform&ExcludedTags=ero&ExcludedTags=ecchi&ExcludedTags=oppai&PageSize=1&IsNsfw=False",
            json_path: &["items", "0", "url"],
            allowed_hosts: &["cdn.waifu.im"],
        },
        SliderImageSource {
            id: "waifu_im_genshin_impact",
            name: "waifu.im genshin-impact",
            api_url: "https://api.waifu.im/images?IncludedTags=genshin-impact&ExcludedTags=ero&ExcludedTags=ecchi&ExcludedTags=oppai&PageSize=1&IsNsfw=False",
            json_path: &["items", "0", "url"],
            allowed_hosts: &["cdn.waifu.im"],
        },
        SliderImageSource {
            id: "waifu_im_raiden_shogun",
            name: "waifu.im raiden-shogun",
            api_url: "https://api.waifu.im/images?IncludedTags=raiden-shogun&ExcludedTags=ero&ExcludedTags=ecchi&ExcludedTags=oppai&PageSize=1&IsNsfw=False",
            json_path: &["items", "0", "url"],
            allowed_hosts: &["cdn.waifu.im"],
        },
        SliderImageSource {
            id: "waifu_im_marin_kitagawa",
            name: "waifu.im marin-kitagawa",
            api_url: "https://api.waifu.im/images?IncludedTags=marin-kitagawa&ExcludedTags=ero&ExcludedTags=ecchi&ExcludedTags=oppai&PageSize=1&IsNsfw=False",
            json_path: &["items", "0", "url"],
            allowed_hosts: &["cdn.waifu.im"],
        },
        SliderImageSource {
            id: "nekosia_fox_girl",
            name: "nekosia fox-girl",
            api_url: "https://api.nekosia.cat/api/v1/images/fox-girl",
            json_path: &["image", "compressed", "url"],
            allowed_hosts: &["cdn.nekosia.cat"],
        },
        SliderImageSource {
            id: "nekosia_wolf_girl",
            name: "nekosia wolf-girl",
            api_url: "https://api.nekosia.cat/api/v1/images/wolf-girl",
            json_path: &["image", "compressed", "url"],
            allowed_hosts: &["cdn.nekosia.cat"],
        },
        SliderImageSource {
            id: "nekosia_maid_uniform",
            name: "nekosia maid-uniform",
            api_url: "https://api.nekosia.cat/api/v1/images/maid-uniform",
            json_path: &["image", "compressed", "url"],
            allowed_hosts: &["cdn.nekosia.cat"],
        },
        SliderImageSource {
            id: "nekos_life_fox_girl",
            name: "nekos.life fox_girl",
            api_url: "https://nekos.life/api/v2/img/fox_girl",
            json_path: &["url"],
            allowed_hosts: &["cdn.nekos.life"],
        },
        SliderImageSource {
            id: "nekos_life_waifu",
            name: "nekos.life waifu",
            api_url: "https://nekos.life/api/v2/img/waifu",
            json_path: &["url"],
            allowed_hosts: &["cdn.nekos.life"],
        },
        SliderImageSource {
            id: "nekobot_neko",
            name: "nekobot neko",
            api_url: "https://nekobot.xyz/api/image?type=neko",
            json_path: &["message"],
            allowed_hosts: &["*.nekobot.xyz"],
        },
        SliderImageSource {
            id: "nekobot_kanna",
            name: "nekobot kanna",
            api_url: "https://nekobot.xyz/api/image?type=kanna",
            json_path: &["message"],
            allowed_hosts: &["*.nekobot.xyz"],
        },
    ]
}

fn require_slider_proof(state: &LoginState, proof: &str) -> Option<&'static str> {
    let proof = proof.trim();
    if proof.is_empty() {
        return Some("请先完成拼图验证");
    }
    if state.proof.is_empty() || proof != state.proof {
        return Some("拼图验证无效，请重新验证");
    }
    if expired(state.verified_at, SLIDER_PROOF_TTL_SECONDS) {
        return Some("拼图验证已过期，请重新验证");
    }
    None
}

fn slider_nonce_error(state: &LoginState, nonce: &str) -> Option<&'static str> {
    if state.nonce.is_empty() {
        return Some("请先完成拼图验证");
    }
    if nonce != state.nonce {
        return Some("拼图验证已失效，请刷新后重试");
    }
    None
}

fn parse_slider_left(value: &str) -> Result<i32, &'static str> {
    let number = value
        .trim()
        .parse::<f64>()
        .map_err(|_| "拼图验证数据不完整，请重新验证")?;
    if !number.is_finite() {
        return Err("拼图验证数据不完整，请重新验证");
    }
    let left = number.trunc() as i32;
    if !(0..=SLIDER_WIDTH).contains(&left) {
        return Err("拼图验证数据无效，请重新验证");
    }
    Ok(left)
}

fn parse_slider_trail(value: &str) -> Result<Vec<f64>, &'static str> {
    let Value::Array(points) =
        serde_json::from_str::<Value>(value).map_err(|_| "拼图轨迹缺失，请重新验证")?
    else {
        return Err("拼图轨迹缺失，请重新验证");
    };

    Ok(points
        .into_iter()
        .filter_map(slider_trail_point)
        .take(256)
        .collect())
}

fn slider_trail_point(value: Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64().filter(|point| point.is_finite()),
        Value::String(text) => text
            .trim()
            .parse::<f64>()
            .ok()
            .filter(|point| point.is_finite()),
        _ => None,
    }
}

fn valid_trail(trail: &[f64]) -> bool {
    if trail.len() < 3 {
        return false;
    }
    let average = trail.iter().sum::<f64>() / trail.len() as f64;
    let variance = trail
        .iter()
        .map(|point| (point - average).powi(2))
        .sum::<f64>()
        / trail.len() as f64;
    let min = trail.iter().copied().fold(f64::INFINITY, f64::min);
    let max = trail.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    variance > 0.01 && (max - min).abs() > 0.5
}

fn random_slider_x() -> i32 {
    let piece_size = SLIDER_PIECE_WIDTH + SLIDER_PIECE_RADIUS * 2 + 3;
    random_range(piece_size + 10, SLIDER_WIDTH - (piece_size + 10))
}

fn random_slider_y() -> i32 {
    let piece_size = SLIDER_PIECE_WIDTH + SLIDER_PIECE_RADIUS * 2 + 3;
    random_range(
        10 + SLIDER_PIECE_RADIUS * 2,
        SLIDER_HEIGHT - (piece_size + 10),
    )
}

fn random_range(min: i32, max: i32) -> i32 {
    use rand::Rng;
    rand::thread_rng().gen_range(min..=max)
}

fn hmac_sha256_hex(secret: &str, value: &str) -> Result<String, AppError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .map_err(|_| AppError::CryptoError("记住登录 HMAC 密钥错误"))?;
    mac.update(value.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn persistent_cookie(
    name: &str,
    value: &str,
    max_age_seconds: i64,
    secure: bool,
    path: &str,
) -> String {
    format!(
        "{name}={value}; Max-Age={max_age_seconds}; Path={path}; HttpOnly; SameSite=Strict{}",
        if secure { "; Secure" } else { "" }
    )
}

fn expired_cookie(name: &str, secure: bool, path: &str) -> String {
    format!(
        "{name}=; Max-Age=0; Path={path}; HttpOnly; SameSite=Strict{}",
        if secure { "; Secure" } else { "" }
    )
}

fn expired(issued_at: i64, ttl_seconds: i64) -> bool {
    issued_at <= 0 || now_timestamp() - issued_at > ttl_seconds
}

fn remaining_seconds(issued_at: i64, ttl_seconds: i64) -> i64 {
    let elapsed_seconds = (now_timestamp() - issued_at).max(1);
    (ttl_seconds - elapsed_seconds).max(1)
}

fn slider_random_hex_token() -> String {
    random_hex_token(16)
}

fn random_hex_token(byte_count: usize) -> String {
    let mut bytes = vec![0_u8; byte_count];
    OsRng.fill_bytes(&mut bytes);
    let mut token = String::with_capacity(byte_count * 2);
    for byte in bytes {
        write!(&mut token, "{byte:02x}").expect("write hex token");
    }
    token
}

fn now_timestamp() -> i64 {
    Local::now().timestamp()
}

fn form_value<'a>(form: &'a HashMap<String, String>, key: &str) -> &'a str {
    form.get(key).map(String::as_str).unwrap_or("")
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn optional_meta_span(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    format!("<span>{}</span>", escape_html(value))
}

fn site_web_config(custom_json: &Value) -> &serde_json::Map<String, Value> {
    match custom_json.get("web").and_then(Value::as_object) {
        Some(config) => config,
        None => empty_json_object(),
    }
}

fn empty_json_object() -> &'static serde_json::Map<String, Value> {
    static EMPTY: std::sync::OnceLock<serde_json::Map<String, Value>> = std::sync::OnceLock::new();
    EMPTY.get_or_init(serde_json::Map::new)
}

fn site_text(value: &str, fallback: &str) -> String {
    let text = value.trim();
    if text.is_empty() {
        fallback.trim().to_string()
    } else {
        text.to_string()
    }
}

fn site_image_url(value: &str, fallback: &str) -> String {
    let url = value.trim();
    if url.is_empty() {
        return fallback.to_string();
    }
    if url.starts_with('/') || url.starts_with("https://") || url.starts_with("data:image/") {
        return url.to_string();
    }
    fallback.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_slider_trail_variance() {
        assert!(valid_trail(&[0.0, 1.2, 2.9, 4.1]));
        assert!(!valid_trail(&[1.0, 1.0, 1.0]));
    }

    #[test]
    fn parses_slider_left_like_php_numeric_cast() {
        assert_eq!(123, parse_slider_left("123").expect("integer left"));
        assert_eq!(123, parse_slider_left("123.9").expect("decimal left"));
        assert_eq!(
            "拼图验证数据不完整，请重新验证",
            parse_slider_left("").expect_err("empty left")
        );
        assert_eq!(
            "拼图验证数据无效，请重新验证",
            parse_slider_left("301").expect_err("out of range left")
        );
    }

    #[test]
    fn parses_slider_trail_like_php_filter() {
        let trail = parse_slider_trail(r#"[0,"1.5",null,"bad",2,3]"#).expect("compatible trail");

        assert_eq!(vec![0.0, 1.5, 2.0, 3.0], trail);
        assert_eq!(
            "拼图轨迹缺失，请重新验证",
            parse_slider_trail("{}").expect_err("non-array trail")
        );
    }

    #[test]
    fn validates_slider_proof_like_php_session_guard() {
        let mut state = LoginState {
            csrf_token: crypto::token(16),
            issued_at: now_timestamp(),
            nonce: String::new(),
            challenge_issued_at: 0,
            attempts: 0,
            puzzle_x: 0,
            puzzle_y: 0,
            proof: "proof-token".to_string(),
            verified_at: now_timestamp(),
        };

        assert_eq!(None, require_slider_proof(&state, "proof-token"));
        assert_eq!(Some("请先完成拼图验证"), require_slider_proof(&state, ""));
        assert_eq!(
            Some("拼图验证无效，请重新验证"),
            require_slider_proof(&state, "wrong")
        );
        state.verified_at = now_timestamp() - SLIDER_PROOF_TTL_SECONDS - 1;
        assert_eq!(
            Some("拼图验证已过期，请重新验证"),
            require_slider_proof(&state, "proof-token")
        );
    }

    #[test]
    fn validates_slider_nonce_like_php_session_guard() {
        let mut state = LoginState {
            csrf_token: crypto::token(16),
            issued_at: now_timestamp(),
            nonce: String::new(),
            challenge_issued_at: 0,
            attempts: 0,
            puzzle_x: 0,
            puzzle_y: 0,
            proof: String::new(),
            verified_at: 0,
        };

        assert_eq!(
            Some("请先完成拼图验证"),
            slider_nonce_error(&state, "nonce-token")
        );

        state.nonce = "nonce-token".to_string();
        assert_eq!(None, slider_nonce_error(&state, "nonce-token"));
        assert_eq!(
            Some("拼图验证已失效，请刷新后重试"),
            slider_nonce_error(&state, "wrong")
        );
    }

    #[test]
    fn reports_slider_remaining_seconds_like_php_ceil_age() {
        assert_eq!(
            SLIDER_PROOF_TTL_SECONDS - 1,
            remaining_seconds(now_timestamp(), SLIDER_PROOF_TTL_SECONDS)
        );
        assert_eq!(
            1,
            remaining_seconds(
                now_timestamp() - SLIDER_PROOF_TTL_SECONDS - 10,
                SLIDER_PROOF_TTL_SECONDS
            )
        );
    }

    #[test]
    fn reset_slider_challenge_preserves_page_state() {
        let issued_at = now_timestamp();
        let mut state = LoginState {
            csrf_token: "csrf-token".to_string(),
            issued_at,
            nonce: "nonce-token".to_string(),
            challenge_issued_at: issued_at,
            attempts: 3,
            puzzle_x: 128,
            puzzle_y: 42,
            proof: "proof-token".to_string(),
            verified_at: issued_at,
        };

        reset_slider_challenge(&mut state);

        assert_eq!("csrf-token", state.csrf_token);
        assert_eq!(issued_at, state.issued_at);
        assert_eq!("", state.nonce);
        assert_eq!(0, state.challenge_issued_at);
        assert_eq!(0, state.attempts);
        assert_eq!(0, state.puzzle_x);
        assert_eq!(0, state.puzzle_y);
        assert_eq!("", state.proof);
        assert_eq!(0, state.verified_at);
    }

    #[test]
    fn renders_php_compatible_slider_challenge_url() {
        let view = LoginPageView::from_settings(
            &crate::repository::SiteSettingsRow {
                hostname: "授权管理系统".to_string(),
                site_subtitle: "后台管理入口".to_string(),
                siteurl: String::new(),
                logo_url: String::new(),
                announcement: String::new(),
                contact: String::new(),
                footer_text: String::new(),
                custom_json: json!({}),
            },
            "csrf-token",
            None,
        );
        let html = render_login_html(&view).expect("login html");

        assert!(html.contains("url: '/admin/login/?slider=challenge'"));
        assert!(!html.contains("sliderChallengeUrl"));
        assert!(!html.contains("slider=challenge&token="));
    }

    #[test]
    fn renders_login_badge_like_php_initial_tag() {
        let view = LoginPageView::from_settings(
            &crate::repository::SiteSettingsRow {
                hostname: "授权管理系统".to_string(),
                site_subtitle: "后台管理入口".to_string(),
                siteurl: String::new(),
                logo_url: String::new(),
                announcement: String::new(),
                contact: String::new(),
                footer_text: String::new(),
                custom_json: json!({"web": {"login_badge": "Hi ACE"}}),
            },
            "csrf-token",
            None,
        );
        let html = render_login_html(&view).expect("login html");

        assert!(
            html.contains(r#"<div class="login-visual-tag" id="login-scene-tag">Hi ACE</div>"#)
        );
    }

    #[test]
    fn renders_login_assets_in_php_order() {
        let view = LoginPageView::from_settings(
            &crate::repository::SiteSettingsRow {
                hostname: "授权管理系统".to_string(),
                site_subtitle: "后台管理入口".to_string(),
                siteurl: String::new(),
                logo_url: String::new(),
                announcement: String::new(),
                contact: String::new(),
                footer_text: String::new(),
                custom_json: json!({}),
            },
            "csrf-token",
            None,
        );
        let html = render_login_html(&view).expect("login html");
        let theme = html.find("/sub_admin/css/theme.css").expect("theme css");
        let layui = html.find("/assets/layui/layui.js").expect("layui js");
        let slider = html
            .find("/assets/vendor/sliderCaptcha/slidercaptcha.css")
            .expect("slider css");

        assert!(theme < layui);
        assert!(layui < slider);
    }

    #[test]
    fn serializes_slider_success_body_like_php() {
        let body = login_body(
            "1",
            "",
            json!({
                "nonce": slider_random_hex_token(),
                "expires_in": SLIDER_CHALLENGE_TTL_SECONDS,
            }),
        );
        let value = serde_json::to_value(body).expect("serialize body");

        assert_eq!("1", value["code"]);
        assert!(value.get("msg").is_none());
        assert_eq!(32, value["nonce"].as_str().expect("nonce").len());
    }

    #[test]
    fn generates_php_compatible_slider_hex_token() {
        let token = slider_random_hex_token();

        assert_eq!(32, token.len());
        assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(token, token.to_ascii_lowercase());
    }

    #[test]
    fn generates_php_compatible_csrf_token() {
        let state = new_login_state();

        assert_eq!(64, state.csrf_token.len());
        assert!(
            state
                .csrf_token
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
        assert_eq!(state.csrf_token, state.csrf_token.to_ascii_lowercase());
    }

    #[test]
    fn uses_php_slider_image_sources() {
        let sources = slider_image_sources();

        assert_eq!(15, sources.len());
        assert!(sources.iter().any(|source| source.id == "waifu_im_uniform"));
        assert!(sources.iter().any(|source| source.id == "nekobot_kanna"));
    }

    #[test]
    fn plans_slider_image_pool_batches_like_php() {
        assert_eq!(26, slider_image_pool_batch_size(20, 15));
        assert_eq!(30, slider_image_pool_batch_size(80, 15));
        assert_eq!(15, slider_image_pool_batch_size(1, 15));
    }

    #[test]
    fn caps_slider_image_pool_items_like_php() {
        let mut items = Vec::new();
        let mut image_ids = HashSet::new();
        let mut last_error = String::new();
        let results = (0..25).map(|index| Ok(slider_pool_item(index))).collect();

        collect_slider_image_pool_results(&mut items, &mut image_ids, results, &mut last_error);

        assert_eq!(SLIDER_IMAGE_POOL_SIZE, items.len());
        assert!(last_error.is_empty());
    }

    #[test]
    fn rejects_incomplete_slider_image_pool_like_php() {
        let error = finalize_slider_image_pool(vec![slider_pool_item(1)], "remote source failed")
            .expect_err("incomplete pool should fail");

        assert!(error.contains("仅成功缓存 1/20 张图片"));
        assert!(error.contains("remote source failed"));
    }

    #[test]
    fn refreshes_slider_image_pool_with_php_lead_window() {
        let now = now_timestamp();
        let due_pool = SliderImagePool {
            generated_at: now - SLIDER_IMAGE_POOL_ROTATION_SECONDS,
            expires_at: now + SLIDER_IMAGE_POOL_REFRESH_LEAD_SECONDS,
            rotation_seconds: SLIDER_IMAGE_POOL_ROTATION_SECONDS,
            items: vec![slider_pool_item(1)],
        };
        let fresh_pool = SliderImagePool {
            generated_at: now,
            expires_at: now + SLIDER_IMAGE_POOL_REFRESH_LEAD_SECONDS + 1,
            rotation_seconds: SLIDER_IMAGE_POOL_ROTATION_SECONDS,
            items: vec![slider_pool_item(2)],
        };

        assert!(slider_image_pool_refresh_due(&due_pool));
        assert!(!slider_image_pool_refresh_due(&fresh_pool));
    }

    #[tokio::test]
    async fn reports_cold_slider_pool_like_php_challenge() {
        let project_root = test_cache_root("cold-slider-pool");
        let public_root = project_root.join("public");
        std::fs::create_dir_all(&public_root).expect("create public directory");

        let error = resolve_slider_image(&public_root)
            .await
            .expect_err("cold pool should ask for prewarm");

        assert_eq!("拼图图片池正在后台预热，请稍后重试", error);
        std::fs::remove_dir_all(project_root).expect("remove cold pool cache");
    }

    #[tokio::test]
    async fn reports_cached_slider_prewarm_status_like_php() {
        let project_root = test_cache_root("cached-slider-pool");
        let public_root = project_root.join("public");
        let paths = slider_image_cache_paths(&public_root);
        std::fs::create_dir_all(&paths.image_directory).expect("create image directory");
        let image_bytes = b"cached-slider-prewarm-image";
        let image_id = crypto::sha256_hex_bytes(image_bytes);
        std::fs::write(paths.image_path(&image_id), image_bytes).expect("write cached image");
        let pool = SliderImagePool {
            generated_at: now_timestamp(),
            expires_at: now_timestamp() + SLIDER_IMAGE_POOL_REFRESH_LEAD_SECONDS + 10,
            rotation_seconds: SLIDER_IMAGE_POOL_ROTATION_SECONDS,
            items: vec![SliderImagePoolItem {
                source_id: "nekos_best_neko".to_string(),
                source_name: "nekos.best neko".to_string(),
                image_id: image_id.clone(),
                image_version: image_id,
                image_url: "stale-url".to_string(),
            }],
        };
        write_slider_image_pool(&paths, &pool)
            .await
            .expect("write pool");

        let status = prewarm_slider_images(&public_root, false)
            .await
            .expect("prewarm status");

        assert_eq!("cached", status["status"]);
        assert_eq!(15, status["source_count"]);
        assert_eq!(1, status["cached_count"]);
        assert_eq!(0, status["removed_count"]);
        std::fs::remove_dir_all(project_root).expect("remove cached pool cache");
    }

    #[test]
    fn requires_php_lowercase_slider_image_id() {
        assert!(slider_image_id(&"a".repeat(64)).is_ok());
        assert!(slider_image_id(&"A".repeat(64)).is_err());
        assert!(slider_image_id(&"g".repeat(64)).is_err());
    }

    #[tokio::test]
    async fn normalizes_slider_image_pool_like_php_cache() {
        let cache_root =
            std::env::temp_dir().join(format!("network-auth-rust-slider-{}", crypto::token(8)));
        let paths = SliderImageCachePaths {
            cache_file: cache_root.join("pool.json"),
            image_directory: cache_root.join("images"),
        };
        std::fs::create_dir_all(&paths.image_directory).expect("create image directory");
        let image_bytes = b"cached-slider-image";
        let image_id = crypto::sha256_hex_bytes(image_bytes);
        std::fs::write(paths.image_path(&image_id), image_bytes).expect("write cached image");
        let pool = SliderImagePool {
            generated_at: 1,
            expires_at: SLIDER_IMAGE_POOL_ROTATION_SECONDS + 1,
            rotation_seconds: SLIDER_IMAGE_POOL_ROTATION_SECONDS,
            items: vec![SliderImagePoolItem {
                source_id: "nekos_best_neko".to_string(),
                source_name: "nekos.best neko".to_string(),
                image_id: image_id.clone(),
                image_version: image_id.clone(),
                image_url: "stale-url".to_string(),
            }],
        };

        let normalized = normalize_slider_image_pool(&paths, pool)
            .await
            .expect("normalized pool");

        assert_eq!(1, normalized.items.len());
        assert_eq!(
            slider_image_api_url("nekos_best_neko", &image_id),
            normalized.items[0].image_url
        );
        std::fs::remove_dir_all(cache_root).expect("remove image cache");
    }

    #[test]
    fn verifies_php_bcrypt_prefix() {
        let hash = bcrypt::hash("secret-password", 4).expect("bcrypt hash");
        let php_hash = hash.replacen("$2b$", "$2y$", 1);

        assert!(verify_php_password("secret-password", &php_hash));
        assert!(!verify_php_password("wrong-password", &php_hash));
    }

    fn slider_pool_item(index: usize) -> SliderImagePoolItem {
        let image_id = format!("{index:064x}");
        SliderImagePoolItem {
            source_id: "source".to_string(),
            source_name: "source name".to_string(),
            image_id: image_id.clone(),
            image_version: image_id.clone(),
            image_url: slider_image_api_url("source", &image_id),
        }
    }

    fn test_cache_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("network-auth-rust-{name}-{}", crypto::token(8)))
    }
}
