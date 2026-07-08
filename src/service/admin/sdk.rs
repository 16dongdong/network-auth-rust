use std::{
    collections::BTreeMap,
    fs,
    io::{Cursor, Write},
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde_json::{Value, json};
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use crate::error::AppError;

const SDK_ROOT: &str = "resources/sdk";
const CPP_TEMPLATE_DIR: &str = "cpp";
const CPP_PACKAGE_DIR: &str = "cppPackage";
const PYTHON_TEMPLATE_DIR: &str = "python";

pub struct SdkPackageContext {
    pub app_name: String,
    pub api_url: String,
    pub app_code: String,
    pub api_token: String,
    pub api_success_code: i64,
    pub api_routes: Value,
    pub app_version: String,
    pub client_auth_mode: String,
    pub client_crypto_alg: String,
    pub client_public_key: String,
    pub sdk_type: String,
}

pub fn build_sdk_package(context: &SdkPackageContext) -> Result<Value, AppError> {
    let package_type = SdkPackageType::parse(&context.sdk_type)?;
    let files = match &package_type {
        SdkPackageType::Python => template_files(PYTHON_TEMPLATE_DIR, &[])?,
        SdkPackageType::Cpp(platform) => {
            let mut files = template_files(CPP_TEMPLATE_DIR, &["third_party"])?;
            files.extend(template_files(CPP_PACKAGE_DIR, &[])?);
            render_templates(files, &cpp_replacements(context, platform)?)?
        }
    };
    let rendered_files = match &package_type {
        SdkPackageType::Python => render_templates(files, &python_replacements(context)?)?,
        SdkPackageType::Cpp(_) => files,
    };
    let archive = zip_files(&rendered_files)?;
    Ok(json!({
        "app_code": context.app_code,
        "api_url": context.api_url,
        "filename": package_filename(context, &package_type),
        "mime": "application/zip",
        "size": archive.len(),
        "content_base64": BASE64_STANDARD.encode(&archive),
        "files": rendered_files.keys().cloned().collect::<Vec<_>>(),
    }))
}

enum SdkPackageType {
    Python,
    Cpp(CppPlatform),
}

impl SdkPackageType {
    fn parse(value: &str) -> Result<Self, AppError> {
        let normalized = value.trim().to_ascii_lowercase();
        if matches!(normalized.as_str(), "python" | "py") {
            return Ok(Self::Python);
        }
        Ok(Self::Cpp(CppPlatform::parse(&normalized)?))
    }
}

#[derive(Clone, Copy)]
enum CppPlatform {
    Android,
    Windows,
    Macos,
    Linux,
}

impl CppPlatform {
    fn parse(value: &str) -> Result<Self, AppError> {
        match value {
            "" | "cpp" | "c++" | "windows" | "windowssdk" | "win" | "win32" | "win64" => {
                Ok(Self::Windows)
            }
            "android" | "androidsdk" | "ndk" => Ok(Self::Android),
            "mac" | "macos" | "macsdk" | "osx" | "darwin" => Ok(Self::Macos),
            "linux" | "linuxsdk" | "gnu" => Ok(Self::Linux),
            _ => Err(AppError::InvalidSdkType),
        }
    }

    fn key(self) -> &'static str {
        match self {
            Self::Android => "android",
            Self::Windows => "windows",
            Self::Macos => "macos",
            Self::Linux => "linux",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Android => "Android",
            Self::Windows => "Windows",
            Self::Macos => "macOS",
            Self::Linux => "Linux",
        }
    }

    fn cmake_suffix(self) -> &'static str {
        match self {
            Self::Android => "Android",
            Self::Windows => "Windows",
            Self::Macos => "Macos",
            Self::Linux => "Linux",
        }
    }

    fn build_example_default(self) -> &'static str {
        match self {
            Self::Android => "OFF",
            _ => "ON",
        }
    }

    fn dependency_guide(self) -> &'static str {
        match self {
            Self::Android => {
                "需要提前准备 Android NDK、OpenSSL 3.x 和 nlohmann/json。OpenSSL 可以用 vcpkg、Conan、源码交叉编译或团队现有依赖仓库提供，最终要求 CMake 能找到 `OpenSSL::SSL`、`OpenSSL::Crypto` 和 `nlohmann_json::nlohmann_json`。"
            }
            Self::Windows => {
                "需要提前安装 Windows C++ 工具链、CMake、OpenSSL 3.x 和 nlohmann/json。OpenSSL 可以由 vcpkg、Conan、预编译包或团队现有依赖仓库提供，最终要求 CMake 能找到 `OpenSSL::SSL`、`OpenSSL::Crypto` 和 `nlohmann_json::nlohmann_json`。"
            }
            Self::Macos => {
                "需要提前安装 CMake、OpenSSL 3.x 和 nlohmann/json。可以使用 Homebrew、Conan、源码编译或团队现有依赖仓库提供依赖；如果 CMake 没有自动找到依赖，在配置时传入正确的 `CMAKE_PREFIX_PATH`。"
            }
            Self::Linux => {
                "需要提前安装 C++17 工具链、CMake、OpenSSL 3.x 和 nlohmann/json。可以使用发行版开发包、vcpkg、Conan、源码编译或团队现有依赖仓库提供依赖；最终要求 CMake 能找到 `OpenSSL::SSL`、`OpenSSL::Crypto` 和 `nlohmann_json::nlohmann_json`。"
            }
        }
    }

    fn build_guide(self) -> &'static str {
        match self {
            Self::Android => {
                "```bash\ncmake -S . -B build-android \\\n  -DCMAKE_TOOLCHAIN_FILE=\"$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake\" \\\n  -DVCPKG_CHAINLOAD_TOOLCHAIN_FILE=\"$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake\" \\\n  -DVCPKG_TARGET_TRIPLET=arm64-android \\\n  -DANDROID_ABI=arm64-v8a \\\n  -DANDROID_PLATFORM=android-24 \\\n  -DLICENSE_AUTH_BUILD_EXAMPLE=OFF \\\n  -DCMAKE_BUILD_TYPE=Release\ncmake --build build-android --config Release\n```"
            }
            Self::Windows => {
                "```powershell\ncmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=\"$env:VCPKG_ROOT\\scripts\\buildsystems\\vcpkg.cmake\" -DCMAKE_BUILD_TYPE=Release\ncmake --build build --config Release\n```"
            }
            Self::Macos => {
                "```bash\ncmake -S . -B build -DCMAKE_BUILD_TYPE=Release\ncmake --build build --config Release\n```"
            }
            Self::Linux => {
                "```bash\ncmake -S . -B build -DCMAKE_BUILD_TYPE=Release\ncmake --build build --config Release\n```"
            }
        }
    }

    fn notes(self) -> &'static str {
        match self {
            Self::Android => {
                "Android 包面向 NDK 原生库集成，默认只构建 `LicenseAuthSdk` 静态库。设备指纹会优先读取当前进程可访问的 Android build、SoC、CPU 和系统路径信息。"
            }
            Self::Windows => {
                "Windows 包默认使用 `%APPDATA%` 保存本机身份文件，并在 CMake 中设置 `_WIN32_WINNT=0x0A00` 以匹配现代 Windows TLS/网络能力。"
            }
            Self::Macos => {
                "macOS 包默认使用 `$HOME/.license-auth` 保存本机身份文件。系统 Keychain 或 Secure Enclave 后端需要在业务侧做真实平台适配。"
            }
            Self::Linux => {
                "Linux 包默认使用 `$HOME/.license-auth` 保存本机身份文件。root 权限运行时可以读取更多 DMI、块设备和 SoC 信息；普通权限下只采集当前进程可读信息。"
            }
        }
    }
}

fn template_files(
    template_dir: &str,
    excluded_paths: &[&str],
) -> Result<BTreeMap<String, String>, AppError> {
    let root = sdk_root()?.join(template_dir);
    if !root.is_dir() {
        return Err(AppError::SdkTemplateMissing);
    }
    let mut files = BTreeMap::new();
    collect_template_files(&root, &root, excluded_paths, &mut files)?;
    if files.is_empty() {
        return Err(AppError::SdkTemplateMissing);
    }
    Ok(files)
}

fn collect_template_files(
    root: &Path,
    directory: &Path,
    excluded_paths: &[&str],
    files: &mut BTreeMap<String, String>,
) -> Result<(), AppError> {
    let entries = fs::read_dir(directory).map_err(|_| AppError::SdkBuildFailed)?;
    for entry in entries {
        let entry = entry.map_err(|_| AppError::SdkBuildFailed)?;
        let path = entry.path();
        let relative_path = path
            .strip_prefix(root)
            .map_err(|_| AppError::SdkBuildFailed)?
            .to_string_lossy()
            .replace('\\', "/");
        if is_excluded_path(&relative_path, excluded_paths) {
            continue;
        }
        if path.is_dir() {
            collect_template_files(root, &path, excluded_paths, files)?;
        } else if path.is_file() && is_template_file(&relative_path) {
            let content = fs::read_to_string(&path).map_err(|_| AppError::SdkBuildFailed)?;
            files.insert(relative_path, content);
        }
    }
    Ok(())
}

fn render_templates(
    files: BTreeMap<String, String>,
    replacements: &BTreeMap<&'static str, String>,
) -> Result<BTreeMap<String, String>, AppError> {
    let mut rendered_files = BTreeMap::new();
    for (path, mut content) in files {
        for (placeholder, value) in replacements {
            content = content.replace(placeholder, value);
        }
        rendered_files.insert(path, content);
    }
    Ok(rendered_files)
}

fn python_replacements(
    context: &SdkPackageContext,
) -> Result<BTreeMap<&'static str, String>, AppError> {
    let mut replacements = common_replacements(context)?;
    replacements.insert("{{SdkApiUrlPy}}", json_string(&context.api_url)?);
    replacements.insert("{{SdkAppCodePy}}", json_string(&context.app_code)?);
    replacements.insert("{{SdkApiTokenPy}}", json_string(&context.api_token)?);
    replacements.insert("{{SdkAppVersionPy}}", json_string(&context.app_version)?);
    replacements.insert(
        "{{SdkApiSuccessCodePy}}",
        context.api_success_code.to_string(),
    );
    replacements.insert(
        "{{SdkApiCallIdsPy}}",
        serde_json::to_string(&api_call_ids(&context.api_routes))
            .map_err(|_| AppError::SdkBuildFailed)?,
    );
    replacements.insert(
        "{{SdkClientAuthModePy}}",
        json_string(&context.client_auth_mode)?,
    );
    replacements.insert(
        "{{SdkCryptoAlgorithmPy}}",
        json_string(&context.client_crypto_alg)?,
    );
    replacements.insert(
        "{{SdkClientPublicKeyPy}}",
        json_string(&context.client_public_key)?,
    );
    Ok(replacements)
}

fn cpp_replacements(
    context: &SdkPackageContext,
    platform: &CppPlatform,
) -> Result<BTreeMap<&'static str, String>, AppError> {
    let mut replacements = common_replacements(context)?;
    replacements.insert("{{SdkApiUrlCpp}}", json_string(&context.api_url)?);
    replacements.insert("{{SdkAppCodeCpp}}", json_string(&context.app_code)?);
    replacements.insert("{{SdkApiTokenCpp}}", json_string(&context.api_token)?);
    replacements.insert("{{SdkAppVersionCpp}}", json_string(&context.app_version)?);
    replacements.insert(
        "{{SdkApiSuccessCodeCpp}}",
        context.api_success_code.to_string(),
    );
    replacements.insert(
        "{{SdkApiCallIdsCpp}}",
        cpp_map(&api_call_ids(&context.api_routes))?,
    );
    replacements.insert(
        "{{SdkClientAuthModeCpp}}",
        json_string(&context.client_auth_mode)?,
    );
    replacements.insert(
        "{{SdkCryptoAlgorithmCpp}}",
        json_string(&context.client_crypto_alg)?,
    );
    replacements.insert(
        "{{SdkClientPublicKeyCpp}}",
        cpp_raw_string(&context.client_public_key)?,
    );
    replacements.insert("{{SdkPlatformKey}}", platform.key().to_string());
    replacements.insert("{{SdkPlatformTitle}}", platform.label().to_string());
    replacements.insert(
        "{{SdkPlatformCmakeSuffix}}",
        platform.cmake_suffix().to_string(),
    );
    replacements.insert(
        "{{SdkBuildExampleDefault}}",
        platform.build_example_default().to_string(),
    );
    replacements.insert(
        "{{SdkDependencyGuide}}",
        platform.dependency_guide().to_string(),
    );
    replacements.insert("{{SdkBuildGuide}}", platform.build_guide().to_string());
    replacements.insert("{{SdkPlatformNotes}}", platform.notes().to_string());
    Ok(replacements)
}

fn common_replacements(
    context: &SdkPackageContext,
) -> Result<BTreeMap<&'static str, String>, AppError> {
    let mut replacements = BTreeMap::new();
    replacements.insert("{{SdkApiUrl}}", context.api_url.clone());
    replacements.insert("{{SdkAppCode}}", context.app_code.clone());
    replacements.insert("{{SdkApiToken}}", context.api_token.clone());
    replacements.insert("{{SdkAppVersion}}", context.app_version.clone());
    replacements.insert("{{SdkClientAuthMode}}", context.client_auth_mode.clone());
    replacements.insert("{{SdkCryptoAlgorithm}}", context.client_crypto_alg.clone());
    replacements.insert(
        "{{SdkClientPublicKey}}",
        context.client_public_key.trim_end().to_string(),
    );
    Ok(replacements)
}

fn zip_files(files: &BTreeMap<String, String>) -> Result<Vec<u8>, AppError> {
    let buffer = Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(buffer);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o644);
    for (path, content) in files {
        zip.start_file(path, options)
            .map_err(|_| AppError::SdkBuildFailed)?;
        zip.write_all(content.as_bytes())
            .map_err(|_| AppError::SdkBuildFailed)?;
    }
    let buffer = zip.finish().map_err(|_| AppError::SdkBuildFailed)?;
    Ok(buffer.into_inner())
}

fn sdk_root() -> Result<PathBuf, AppError> {
    let root = std::env::current_dir()
        .map_err(|_| AppError::SdkTemplateMissing)?
        .join(SDK_ROOT);
    if root.is_dir() {
        return Ok(root);
    }
    Err(AppError::SdkTemplateMissing)
}

fn package_filename(context: &SdkPackageContext, package_type: &SdkPackageType) -> String {
    let platform = match package_type {
        SdkPackageType::Python => "python",
        SdkPackageType::Cpp(platform) => platform.key(),
    };
    format!(
        "{}_{}.zip",
        download_filename_part(&context.app_name, &context.app_code),
        platform
    )
}

fn download_filename_part(value: &str, fallback: &str) -> String {
    let name = if value.trim().is_empty() {
        fallback.trim()
    } else {
        value.trim()
    };
    let sanitized = name
        .chars()
        .map(|character| {
            if matches!(
                character,
                '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
            ) || character.is_control()
            {
                '-'
            } else {
                character
            }
        })
        .collect::<String>();
    let collapsed = sanitized.split_whitespace().collect::<Vec<_>>().join(" ");
    let trimmed = collapsed.trim_matches(|character| matches!(character, ' ' | '.'));
    if trimmed.is_empty() {
        "app".to_string()
    } else {
        trimmed.to_string()
    }
}

fn api_call_ids(routes: &Value) -> BTreeMap<String, String> {
    let mut call_ids = BTreeMap::new();
    if let Value::Array(routes) = routes {
        for route in routes {
            let Some(route_path) = route.get("route").and_then(Value::as_str) else {
                continue;
            };
            let Some(call_id) = route.get("call_id").and_then(Value::as_str) else {
                continue;
            };
            call_ids.insert(route_path.to_string(), call_id.to_string());
        }
    }
    call_ids
}

fn json_string(value: &str) -> Result<String, AppError> {
    serde_json::to_string(value).map_err(|_| AppError::SdkBuildFailed)
}

fn cpp_raw_string(value: &str) -> Result<String, AppError> {
    let public_key = value.trim_end();
    if public_key.contains(")SDKPEM") {
        return Err(AppError::SdkBuildFailed);
    }
    Ok(format!("R\"SDKPEM({public_key}\n)SDKPEM\""))
}

fn cpp_map(values: &BTreeMap<String, String>) -> Result<String, AppError> {
    let rows = values
        .iter()
        .map(|(route, call_id)| {
            Ok(format!(
                "{{{}, {}}}",
                json_string(route)?,
                json_string(call_id)?
            ))
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    Ok(format!("{{{}}}", rows.join(", ")))
}

fn is_template_file(relative_path: &str) -> bool {
    let blocked_directories = [".git", ".github", ".idea", ".vscode", "__pycache__"];
    if relative_path
        .split('/')
        .any(|segment| blocked_directories.contains(&segment))
    {
        return false;
    }
    let lowercase = relative_path.to_ascii_lowercase();
    !lowercase.ends_with(".bak")
        && !lowercase.ends_with(".log")
        && !lowercase.ends_with(".pyc")
        && !lowercase.ends_with(".tmp")
        && !lowercase.ends_with(".ds_store")
}

fn is_excluded_path(relative_path: &str, excluded_paths: &[&str]) -> bool {
    excluded_paths.iter().any(|excluded_path| {
        relative_path == *excluded_path || relative_path.starts_with(&format!("{excluded_path}/"))
    })
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use serde_json::json;
    use zip::ZipArchive;

    use super::{SdkPackageContext, build_sdk_package};

    #[test]
    fn builds_python_sdk_zip_with_replacements() {
        let package = build_sdk_package(&package_context("python")).expect("package should build");
        assert_eq!("测试应用_python.zip", package["filename"]);
        let bytes = BASE64_STANDARD
            .decode(package["content_base64"].as_str().expect("base64"))
            .expect("zip base64");
        let mut archive = ZipArchive::new(std::io::Cursor::new(bytes)).expect("zip archive");
        let mut config = String::new();
        archive
            .by_name("licenseauth/config.py")
            .expect("config.py")
            .read_to_string(&mut config)
            .expect("config content");
        assert!(config.contains("apiUrl: str = \"https://example.com/api/v1/index.php\""));
        assert!(config.contains("\"/login/challenge\":\"login_challenge\""));
        let mut client = String::new();
        archive
            .by_name("licenseauth/client.py")
            .expect("client.py")
            .read_to_string(&mut client)
            .expect("client content");
        assert!(client.contains("if route == \"/cloud/download-ticket\":"));
        assert!(client.contains("return str(payload.get(\"file_key\", \"\"))"));
    }

    #[test]
    fn builds_windows_cpp_sdk_zip_with_overlay_readme() {
        let package = build_sdk_package(&package_context("windows")).expect("package should build");
        assert_eq!("测试应用_windows.zip", package["filename"]);
        let bytes = BASE64_STANDARD
            .decode(package["content_base64"].as_str().expect("base64"))
            .expect("zip base64");
        let mut archive = ZipArchive::new(std::io::Cursor::new(bytes)).expect("zip archive");
        let mut readme = String::new();
        archive
            .by_name("README.md")
            .expect("README.md")
            .read_to_string(&mut readme)
            .expect("readme content");
        assert!(readme.starts_with("# LicenseAuth Windows SDK"));
        let mut client = String::new();
        archive
            .by_name("src/AuthClient.cpp")
            .expect("AuthClient.cpp")
            .read_to_string(&mut client)
            .expect("client content");
        assert!(client.contains("if (route == \"/cloud/download-ticket\")"));
        assert!(client.contains("return payload.value(\"file_key\", \"\");"));
        assert!(archive.by_name("third_party/nlohmann/json.hpp").is_err());
    }

    fn package_context(sdk_type: &str) -> SdkPackageContext {
        SdkPackageContext {
            app_name: "测试应用".to_string(),
            api_url: "https://example.com/api/v1/index.php".to_string(),
            app_code: "ACE_TEST".to_string(),
            api_token: "ABCDEFGHIJKLMNOP".to_string(),
            api_success_code: 0,
            api_routes: json!([
                {"route": "/login/challenge", "call_id": "login_challenge"},
                {"route": "/login", "call_id": "card_login"}
            ]),
            app_version: "1.2.3".to_string(),
            client_auth_mode: "local_key_v1".to_string(),
            client_crypto_alg: "rsa_oaep_aes_256_gcm".to_string(),
            client_public_key: "-----BEGIN PUBLIC KEY-----\nKEY\n-----END PUBLIC KEY-----\n"
                .to_string(),
            sdk_type: sdk_type.to_string(),
        }
    }
}
