use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use serde::Serialize;
use thiserror::Error;

use crate::config::AppConfig;

const RELEASE_DEFAULT_BASE: &str = "/var/www/ace-network-auth";
const RELEASE_DEFAULT_KEEP: usize = 3;
const RELEASE_MAX_KEEP: usize = 50;
const STORAGE_DIRS: &[&str] = &["cache", "logs", "runtime-cache", "build", "cloud-storage"];
const RUNTIME_CACHE_DIRS: &[&str] = &["client-app", "client-remote-config"];
const PROJECT_STORAGE_DIRS: &[&str] = &["cache", "logs", "runtime-cache", "cloud-storage"];
const REQUIRED_PUBLIC_FILES: &[&str] = &[
    "install/index.html",
    "install/install.css",
    "install/disclaimer.html",
    "frontend/admin-console/index.html",
    "frontend/admin-console/css/app.css",
    "frontend/admin-console/js/app.js",
    "frontend/admin-console/js/http.js",
    "frontend/admin-console/js/state.js",
    "frontend/admin-console/js/view.js",
    "assets/layui/layui.js",
    "assets/layui/css/layui.css",
    "frontend/admin-console/js/img/brand-avatar.webp",
    "frontend/admin-console/js/img/install-complete.webp",
];
const STORAGE_DIRECTORY_MODE: u32 = 0o750;
const STORAGE_FILE_MODE: u32 = 0o640;

#[derive(Debug, Error)]
pub enum DeployError {
    #[error("{0}")]
    InvalidInput(String),
    #[error("{0}")]
    Io(String),
}

#[derive(Debug)]
pub struct ProjectPreflightOptions {
    pub config_path: PathBuf,
    pub public_root: PathBuf,
    pub schema_path: PathBuf,
    pub storage_root: PathBuf,
    pub strict: bool,
}

#[derive(Debug, Default)]
pub struct PreflightReport {
    pub warnings: Vec<String>,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerSpec {
    owner: String,
    group: String,
}

#[derive(Debug, Serialize)]
pub struct StoragePrepareResult {
    base: String,
    current: String,
    owner: String,
    #[serde(rename = "dryRun")]
    dry_run: bool,
    prepared: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ReleasePruneResult {
    base: String,
    current: String,
    #[serde(rename = "keepCount")]
    keep_count: usize,
    #[serde(rename = "removedCount")]
    removed_count: usize,
    #[serde(rename = "dryRun")]
    dry_run: bool,
    kept: Vec<String>,
    removed: Vec<String>,
}

#[derive(Debug, Clone)]
struct ReleaseEntry {
    path: PathBuf,
    modified_seconds: u64,
}

impl OwnerSpec {
    pub fn parse(value: &str) -> Result<Self, DeployError> {
        let (owner, group) = value.split_once(':').unwrap_or((value, ""));
        let owner = owner.trim();
        let group = group.trim();
        if !valid_owner_name(owner) || (!group.is_empty() && !valid_owner_name(group)) {
            return Err(DeployError::InvalidInput(
                "Runtime owner must be user or user:group".to_string(),
            ));
        }

        Ok(Self {
            owner: owner.to_string(),
            group: group.to_string(),
        })
    }

    fn display(&self) -> String {
        if self.group.is_empty() {
            self.owner.clone()
        } else {
            format!("{}:{}", self.owner, self.group)
        }
    }
}

pub fn release_default_base() -> PathBuf {
    PathBuf::from(RELEASE_DEFAULT_BASE)
}

pub fn release_default_keep() -> usize {
    RELEASE_DEFAULT_KEEP
}

pub fn run_project_preflight(options: &ProjectPreflightOptions) -> PreflightReport {
    let mut report = PreflightReport::default();
    check_config(&mut report, options);
    check_required_files(&mut report, options);
    check_storage_directories(&mut report, options);
    check_git_ignore(&mut report);
    report
}

pub fn parse_release_keep(value: &str) -> Result<usize, DeployError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(DeployError::InvalidInput(
            "Release keep count must be a positive integer".to_string(),
        ));
    }

    let keep = value.parse::<usize>().map_err(|_| {
        DeployError::InvalidInput("Release keep count must be a positive integer".to_string())
    })?;
    validate_keep_count(keep)?;
    Ok(keep)
}

pub fn prepare_release_storage(
    base_path: &Path,
    owner: Option<&OwnerSpec>,
    dry_run: bool,
) -> Result<StoragePrepareResult, DeployError> {
    assert_owner_is_explicit(owner, dry_run)?;
    let base = canonical_base(base_path)?;
    let current = current_release_path(&base)?;
    let mut prepared = Vec::new();
    for path in storage_required_paths(&base) {
        let prepared_path = prepare_storage_path(&path, &base, owner, dry_run)?;
        if !prepared.iter().any(|existing| existing == &prepared_path) {
            prepared.push(prepared_path);
        }
    }
    assert_release_storage_links(&current, &base)?;

    Ok(StoragePrepareResult {
        base: display_path(&base),
        current: display_path(&current),
        owner: owner.map(OwnerSpec::display).unwrap_or_default(),
        dry_run,
        prepared,
    })
}

pub fn prune_releases(
    base_path: &Path,
    keep: usize,
    dry_run: bool,
) -> Result<ReleasePruneResult, DeployError> {
    validate_keep_count(keep)?;
    let base = canonical_base(base_path)?;
    let releases_candidate = base.join("releases");
    if !releases_candidate.is_dir() {
        return Err(DeployError::InvalidInput(format!(
            "Releases directory not found: {}",
            releases_candidate.display()
        )));
    }
    let releases_path = canonicalize(&releases_candidate)?;

    let current = current_release_path(&base)?;
    let releases = release_entries(&releases_path)?;
    let kept = kept_release_paths(&releases, &current, keep);
    let removed = removable_release_paths(&releases, &kept);
    if !dry_run {
        for path in &removed {
            assert_direct_child(
                path,
                &releases_path,
                "Release path is outside releases directory",
            )?;
            fs::remove_dir_all(path).map_err(|error| {
                DeployError::Io(format!("Cannot remove release {}: {error}", path.display()))
            })?;
        }
    }

    Ok(ReleasePruneResult {
        base: display_path(&base),
        current: display_path(&current),
        keep_count: kept.len(),
        removed_count: removed.len(),
        dry_run,
        kept: kept.iter().map(|path| display_path(path)).collect(),
        removed: removed.iter().map(|path| display_path(path)).collect(),
    })
}

fn check_config(report: &mut PreflightReport, options: &ProjectPreflightOptions) {
    match AppConfig::from_php_file(&options.config_path) {
        Ok(config) => {
            if let Err(error) = config.validate() {
                report.failures.push(error.to_string());
            }
            if !valid_admin_token_hash(&config.admin_token_hash) {
                add_warning(
                    report,
                    options.strict,
                    format!(
                        "AUTH_ADMIN_TOKEN_HASH is missing or invalid in {}; admin API will reject all requests.",
                        options.config_path.display()
                    ),
                );
            }
        }
        Err(error) => report.failures.push(error.to_string()),
    }
}

fn check_required_files(report: &mut PreflightReport, options: &ProjectPreflightOptions) {
    for path in required_files(options) {
        if !path.is_file() {
            report
                .failures
                .push(format!("Required file missing: {}", path.display()));
        }
    }
}

fn required_files(options: &ProjectPreflightOptions) -> Vec<PathBuf> {
    let mut files = vec![options.schema_path.clone()];
    files.extend(
        REQUIRED_PUBLIC_FILES
            .iter()
            .map(|relative_path| public_file(&options.public_root, relative_path)),
    );
    files
}

fn public_file(public_root: &Path, relative_path: &str) -> PathBuf {
    relative_path
        .split('/')
        .fold(public_root.to_path_buf(), |path, component| {
            path.join(component)
        })
}

fn check_storage_directories(report: &mut PreflightReport, options: &ProjectPreflightOptions) {
    for directory in PROJECT_STORAGE_DIRS {
        let path = options.storage_root.join(directory);
        if !path.is_dir() {
            report
                .failures
                .push(format!("Required directory missing: {}", path.display()));
            continue;
        }

        let probe = path.join(format!(".preflight-{}.tmp", std::process::id()));
        match fs::write(&probe, b"ok").and_then(|_| fs::remove_file(&probe)) {
            Ok(()) => {}
            Err(_) => report
                .failures
                .push(format!("Directory is not writable: {}", path.display())),
        }
    }
}

fn check_git_ignore(report: &mut PreflightReport) {
    if !should_check_git_ignore(Path::new(".")) {
        return;
    }

    for path in ["config/local.php", "config/sample.config.php"] {
        let ignored = Command::new("git")
            .args(["check-ignore", path])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);
        if !ignored {
            report
                .failures
                .push(format!("{path} is not ignored by git."));
        }
    }
}

fn should_check_git_ignore(project_root: &Path) -> bool {
    project_root.join(".git").exists()
}

fn add_warning(report: &mut PreflightReport, strict: bool, message: String) {
    if strict {
        report.failures.push(message);
    } else {
        report.warnings.push(message);
    }
}

fn valid_admin_token_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_owner_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn validate_keep_count(keep: usize) -> Result<(), DeployError> {
    if !(1..=RELEASE_MAX_KEEP).contains(&keep) {
        return Err(DeployError::InvalidInput(format!(
            "Release keep count must be between 1 and {RELEASE_MAX_KEEP}"
        )));
    }
    Ok(())
}

fn assert_owner_is_explicit(owner: Option<&OwnerSpec>, dry_run: bool) -> Result<(), DeployError> {
    if dry_run || cfg!(windows) || owner.is_some() {
        return Ok(());
    }

    Err(DeployError::InvalidInput(
        "Runtime owner is required when preparing release storage. Pass --owner=user:group."
            .to_string(),
    ))
}

fn canonical_base(base_path: &Path) -> Result<PathBuf, DeployError> {
    if base_path.as_os_str().is_empty() || base_path.to_string_lossy().contains('\0') {
        return Err(DeployError::InvalidInput(
            "Invalid release base path".to_string(),
        ));
    }

    let base = fs::canonicalize(base_path).map_err(|_| {
        DeployError::InvalidInput(format!(
            "Release base path not found: {}",
            base_path.display()
        ))
    })?;
    if !base.is_dir() {
        return Err(DeployError::InvalidInput(format!(
            "Release base path not found: {}",
            base_path.display()
        )));
    }
    Ok(base)
}

fn current_release_path(base: &Path) -> Result<PathBuf, DeployError> {
    let current_link = base.join("current");
    let metadata = fs::symlink_metadata(&current_link).map_err(|_| {
        DeployError::InvalidInput(format!(
            "Current release symlink not found: {}",
            current_link.display()
        ))
    })?;
    if !metadata.file_type().is_symlink() {
        return Err(DeployError::InvalidInput(format!(
            "Current release symlink not found: {}",
            current_link.display()
        )));
    }

    let current = canonicalize(&current_link)?;
    if !current.is_dir() {
        return Err(DeployError::InvalidInput(format!(
            "Current release target is invalid: {}",
            current_link.display()
        )));
    }
    assert_child_path(
        &current,
        &base.join("releases"),
        "Current release is outside releases",
    )?;
    Ok(current)
}

fn storage_required_paths(base: &Path) -> Vec<PathBuf> {
    let shared_storage = base.join("shared").join("storage");
    let mut paths = vec![shared_storage.clone()];
    for directory in STORAGE_DIRS {
        paths.push(shared_storage.join(directory));
    }
    for directory in RUNTIME_CACHE_DIRS {
        paths.push(shared_storage.join("runtime-cache").join(directory));
    }
    paths
}

fn prepare_storage_path(
    path: &Path,
    base: &Path,
    owner: Option<&OwnerSpec>,
    dry_run: bool,
) -> Result<String, DeployError> {
    if !dry_run && !path.is_dir() {
        fs::create_dir_all(path).map_err(|error| {
            DeployError::Io(format!(
                "Cannot create runtime directory {}: {error}",
                path.display()
            ))
        })?;
    }

    let canonical = canonicalize(path)?;
    if !canonical.is_dir() {
        return Err(DeployError::InvalidInput(format!(
            "Cannot resolve runtime directory: {}",
            path.display()
        )));
    }
    assert_child_or_same(&canonical, base, "Runtime path is outside release base")?;
    if !dry_run {
        apply_tree_permissions(&canonical, owner)?;
    }

    Ok(display_path(&canonical))
}

fn assert_release_storage_links(current: &Path, base: &Path) -> Result<(), DeployError> {
    for directory in STORAGE_DIRS {
        let release_path = current.join("storage").join(directory);
        if !release_path.exists() {
            continue;
        }

        let target = canonicalize(&release_path)?;
        assert_child_or_same(&target, base, "Runtime path is outside release base")?;
    }
    Ok(())
}

fn apply_tree_permissions(root: &Path, owner: Option<&OwnerSpec>) -> Result<(), DeployError> {
    apply_path_permissions(root, true, owner)?;
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        for entry in fs::read_dir(&directory).map_err(|error| {
            DeployError::Io(format!("Cannot read {}: {error}", directory.display()))
        })? {
            let entry = entry.map_err(|error| DeployError::Io(error.to_string()))?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                DeployError::Io(format!("Cannot stat {}: {error}", path.display()))
            })?;
            if metadata.file_type().is_symlink() {
                continue;
            }

            let is_dir = metadata.is_dir();
            apply_path_permissions(&path, is_dir, owner)?;
            if is_dir {
                stack.push(path);
            }
        }
    }
    Ok(())
}

fn apply_path_permissions(
    path: &Path,
    directory: bool,
    owner: Option<&OwnerSpec>,
) -> Result<(), DeployError> {
    apply_owner(path, owner)?;
    apply_mode(
        path,
        if directory {
            STORAGE_DIRECTORY_MODE
        } else {
            STORAGE_FILE_MODE
        },
    )
}

#[cfg(unix)]
fn apply_owner(path: &Path, owner: Option<&OwnerSpec>) -> Result<(), DeployError> {
    if let Some(owner) = owner {
        run_owner_command("chown", &owner.owner, path)?;
        if !owner.group.is_empty() {
            run_owner_command("chgrp", &owner.group, path)?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn apply_owner(_path: &Path, _owner: Option<&OwnerSpec>) -> Result<(), DeployError> {
    Ok(())
}

#[cfg(unix)]
fn run_owner_command(command: &str, value: &str, path: &Path) -> Result<(), DeployError> {
    let status = Command::new(command)
        .arg(value)
        .arg(path)
        .status()
        .map_err(|error| DeployError::Io(format!("Cannot run {command}: {error}")))?;
    if !status.success() {
        return Err(DeployError::Io(format!(
            "Cannot change owner for runtime path: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn apply_mode(path: &Path, mode: u32) -> Result<(), DeployError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|error| {
        DeployError::Io(format!(
            "Cannot change mode for {}: {error}",
            path.display()
        ))
    })
}

#[cfg(not(unix))]
fn apply_mode(_path: &Path, _mode: u32) -> Result<(), DeployError> {
    Ok(())
}

fn release_entries(releases_path: &Path) -> Result<Vec<ReleaseEntry>, DeployError> {
    let mut releases = Vec::new();
    for entry in fs::read_dir(releases_path).map_err(|error| {
        DeployError::Io(format!(
            "Cannot read releases directory {}: {error}",
            releases_path.display()
        ))
    })? {
        let entry = entry.map_err(|error| DeployError::Io(error.to_string()))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let release_path = canonicalize(&path)?;
        assert_direct_child(
            &release_path,
            releases_path,
            "Release path is outside releases directory",
        )?;
        let modified_seconds = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        releases.push(ReleaseEntry {
            path: release_path,
            modified_seconds,
        });
    }
    releases.sort_by(|left, right| right.modified_seconds.cmp(&left.modified_seconds));
    Ok(releases)
}

fn kept_release_paths(releases: &[ReleaseEntry], current: &Path, keep: usize) -> Vec<PathBuf> {
    let mut kept = vec![current.to_path_buf()];
    for release in releases.iter().take(keep) {
        if !kept.iter().any(|path| path == &release.path) {
            kept.push(release.path.clone());
        }
    }
    if let Some(php_release) = newest_php_release_path(releases)
        && !kept.iter().any(|path| path == &php_release)
    {
        kept.push(php_release);
    }
    kept
}

fn removable_release_paths(releases: &[ReleaseEntry], kept: &[PathBuf]) -> Vec<PathBuf> {
    releases
        .iter()
        .filter(|release| !kept.iter().any(|path| path == &release.path))
        .map(|release| release.path.clone())
        .collect()
}

fn newest_php_release_path(releases: &[ReleaseEntry]) -> Option<PathBuf> {
    releases
        .iter()
        .find(|release| is_php_release(&release.path))
        .map(|release| release.path.clone())
}

fn is_php_release(path: &Path) -> bool {
    path.join("index.php").is_file()
        && path.join("bootstrap").join("app.php").is_file()
        && path.join("app").is_dir()
}

fn assert_child_or_same(child: &Path, parent: &Path, message: &str) -> Result<(), DeployError> {
    let child = canonicalize(child)?;
    let parent = canonicalize(parent)?;
    if child == parent || child.starts_with(&parent) {
        return Ok(());
    }

    Err(DeployError::InvalidInput(format!(
        "{message}: {}",
        child.display()
    )))
}

fn assert_child_path(child: &Path, parent: &Path, message: &str) -> Result<(), DeployError> {
    let child = canonicalize(child)?;
    let parent = canonicalize(parent)?;
    if child.starts_with(&parent) {
        return Ok(());
    }

    Err(DeployError::InvalidInput(format!(
        "{message}: {}",
        child.display()
    )))
}

fn assert_direct_child(child: &Path, parent: &Path, message: &str) -> Result<(), DeployError> {
    let child = canonicalize(child)?;
    let parent = canonicalize(parent)?;
    if child.parent() == Some(parent.as_path()) {
        return Ok(());
    }

    Err(DeployError::InvalidInput(format!(
        "{message}: {}",
        child.display()
    )))
}

fn canonicalize(path: &Path) -> Result<PathBuf, DeployError> {
    fs::canonicalize(path)
        .map_err(|_| DeployError::InvalidInput(format!("Cannot resolve path: {}", path.display())))
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_owner_spec_like_php_release_tool() {
        let owner = OwnerSpec::parse("nginx:nginx").expect("owner");

        assert_eq!("nginx:nginx", owner.display());
        assert_eq!(
            "nginx",
            OwnerSpec::parse("nginx:").expect("owner").display()
        );
        assert!(OwnerSpec::parse("bad/user").is_err());
        assert!(OwnerSpec::parse(":group").is_err());
    }

    #[test]
    fn validates_release_keep_count_like_php_release_tool() {
        assert_eq!(3, parse_release_keep("3").expect("keep"));
        assert!(parse_release_keep("0").is_err());
        assert!(parse_release_keep("51").is_err());
        assert!(parse_release_keep("abc").is_err());
        assert!(parse_release_keep("-1").is_err());
    }

    #[test]
    fn computes_kept_and_removed_release_paths() {
        let releases = vec![
            ReleaseEntry {
                path: PathBuf::from("/base/releases/a-newest"),
                modified_seconds: 3,
            },
            ReleaseEntry {
                path: PathBuf::from("/base/releases/z-current"),
                modified_seconds: 2,
            },
            ReleaseEntry {
                path: PathBuf::from("/base/releases/m-old"),
                modified_seconds: 1,
            },
        ];
        let kept = kept_release_paths(&releases, Path::new("/base/releases/z-current"), 1);
        let removed = removable_release_paths(&releases, &kept);

        assert_eq!(
            vec![
                PathBuf::from("/base/releases/z-current"),
                PathBuf::from("/base/releases/a-newest")
            ],
            kept
        );
        assert_eq!(vec![PathBuf::from("/base/releases/m-old")], removed);
    }

    #[test]
    fn keeps_latest_php_release_as_rollback_fallback() {
        let root =
            std::env::temp_dir().join(format!("network-auth-prune-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let releases_root = root.join("releases");
        fs::create_dir_all(&releases_root).expect("releases root");

        let current = releases_root.join("rust-current");
        let rust_previous = releases_root.join("rust-previous");
        let php_fallback = releases_root.join("php-fallback");
        fs::create_dir_all(&current).expect("current release");
        fs::create_dir_all(&rust_previous).expect("previous rust release");
        fs::create_dir_all(php_fallback.join("bootstrap")).expect("php bootstrap");
        fs::create_dir_all(php_fallback.join("app")).expect("php app");
        fs::write(php_fallback.join("index.php"), "<?php").expect("php index");
        fs::write(php_fallback.join("bootstrap").join("app.php"), "<?php")
            .expect("php bootstrap app");

        let releases = vec![
            ReleaseEntry {
                path: current.clone(),
                modified_seconds: 3,
            },
            ReleaseEntry {
                path: rust_previous.clone(),
                modified_seconds: 2,
            },
            ReleaseEntry {
                path: php_fallback.clone(),
                modified_seconds: 1,
            },
        ];
        let kept = kept_release_paths(&releases, &current, 1);
        let removed = removable_release_paths(&releases, &kept);

        assert!(kept.contains(&current));
        assert!(kept.contains(&php_fallback));
        assert_eq!(vec![rust_previous], removed);

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn project_preflight_required_files_include_rust_frontend_assets() {
        let options = ProjectPreflightOptions {
            config_path: PathBuf::from("config/local.php"),
            public_root: PathBuf::from("public"),
            schema_path: PathBuf::from("resources/install/schema.sql"),
            storage_root: PathBuf::from("storage"),
            strict: false,
        };
        let files = required_files(&options);

        assert!(files.contains(&PathBuf::from("resources/install/schema.sql")));
        assert!(files.contains(&PathBuf::from("public/install/index.html")));
        assert!(files.contains(&PathBuf::from("public/frontend/admin-console/js/app.js")));
        assert!(files.contains(&PathBuf::from("public/assets/layui/layui.js")));
    }

    #[test]
    fn project_preflight_skips_git_ignore_outside_worktree() {
        let temp_root = std::env::temp_dir().join(format!(
            "network-auth-rust-preflight-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&temp_root);
        fs::create_dir_all(&temp_root).expect("create temp root");

        assert!(!should_check_git_ignore(&temp_root));

        fs::remove_dir_all(&temp_root).expect("remove temp root");
    }
}
