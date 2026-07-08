# Network Auth Rust

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
![Rust 2024](https://img.shields.io/badge/Rust-2024-orange.svg)
![Axum 0.8](https://img.shields.io/badge/Axum-0.8-blue.svg)
![MySQL](https://img.shields.io/badge/MySQL%20%2F%20MariaDB-supported-4479A1.svg)
![Vibe Coding](https://img.shields.io/badge/Vibe%20Coding-project-purple.svg)

Network Auth Rust 是一个用 Rust 构建的网络授权验证平台，覆盖卡密授权、设备绑定、后台管理、远程 API、云存储分发、安装初始化和发布切换流程。

这个仓库作为 **Vibe Coding 项目** 开源展示，重点呈现一个完整后端系统从协议设计、数据建模、管理后台到部署运维的工程闭环。

## 目录

- [项目亮点](#项目亮点)
- [界面预览](#界面预览)
- [功能概览](#功能概览)
- [技术栈](#技术栈)
- [快速开始](#快速开始)
- [常用命令](#常用命令)
- [系统架构](#系统架构)
- [仓库结构](#仓库结构)
- [文档](#文档)
- [贡献](#贡献)
- [安全](#安全)
- [许可证](#许可证)

## 项目亮点

| 方向 | 说明 |
| --- | --- |
| 完整业务闭环 | 客户端授权、卡密生命周期、设备绑定、远程配置、后台管理、安装初始化和发布切换均有真实实现。 |
| Rust 后端实践 | 基于 Axum、Tokio、SQLx、Tower HTTP 构建，服务端路由、业务层、仓储层和加密工具分层明确。 |
| 安全协议密度高 | 覆盖 HMAC、防重放 nonce、AES-GCM、RSA 密钥封装、P256 设备签名、后台会话签名和敏感配置加密。 |
| 可运维发布 | 提供 preflight、migrate、release package check、smoke gate、readiness gate、Nginx 切换和回滚脚本。 |
| 适合阅读复用 | README、架构文档、部署文档、SDK 模板和贡献说明已经整理成公开项目形态。 |

## 界面预览

截图来自本地 Rust 后端和 MariaDB 数据库运行环境。

| 后台控制台 | 安装向导 |
| --- | --- |
| ![后台控制台](docs/screenshots/admin-console.png) | ![安装向导](docs/screenshots/install-wizard.png) |

## 功能概览

- 客户端授权：登录挑战、卡密登录、心跳、解绑、远程配置、远程变量、云下载票据和安全上报。
- 管理后台：应用、卡密、设备、账号、消息、审计日志、站点配置、远程 API Token 和云存储文件管理。
- 安全协议：签名请求、防重放、加密载荷、设备签名、后台会话签名和演示模式保护。
- 云存储：本地存储、阿里云 OSS、腾讯云 COS，支持上传票据、下载 Token、签名 URL、文件列表和删除。
- 安装初始化：数据库 schema 初始化、运行时补丁检查、管理员创建、数据库预检和安装锁。
- 发布运维：Linux release 组装、systemd 服务安装、Nginx 后端切换、切换前 smoke、切换后 gate 和回滚。
- 自动化验证：Rust 单测、PHP 黑盒回归脚本、live smoke、发布脚本自测和项目预检。

## 技术栈

| 模块 | 技术 |
| --- | --- |
| 后端 | Rust 2024, Axum, Tokio, Tower HTTP |
| 数据库 | MySQL / MariaDB, SQLx |
| 加密 | AES-GCM, AES-CBC, RSA, P256 ECDSA, HMAC, SHA-1, SHA-256 |
| 前端 | HTML, CSS, JavaScript |
| 运维 | Nginx, systemd, Bash, PowerShell |
| 验证 | Rust tests, PHP smoke scripts, release gates |

## 快速开始

### 环境要求

- Rust stable 1.85+
- MySQL 8.0+ 或 MariaDB 10.6+
- PowerShell、Bash 或兼容 shell
- PHP CLI，仅在运行 PHP 黑盒回归脚本时需要

### 1. 创建数据库

```sql
CREATE DATABASE network_auth DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'network_auth'@'127.0.0.1' IDENTIFIED BY 'change-me';
GRANT ALL PRIVILEGES ON network_auth.* TO 'network_auth'@'127.0.0.1';
FLUSH PRIVILEGES;
```

### 2. 创建本地配置

```powershell
Copy-Item config/local.example.php config/local.php
```

编辑 `config/local.php`，填写数据库地址、端口、账号、密码、库名和系统密钥。`config/local.php` 已被 `.gitignore` 排除，只应保留在本地或部署环境中。

### 3. 初始化数据库

```powershell
cargo run -- migrate --dry-run --config config/local.php
cargo run -- migrate --config config/local.php
```

### 4. 启动服务

```powershell
cargo run -- serve --listen 127.0.0.1:8080 --config config/local.php
```

启动后访问：

- `http://127.0.0.1:8080/health`
- `http://127.0.0.1:8080/install/`
- `http://127.0.0.1:8080/admin/login/`

### 5. 运行预检

```powershell
cargo run -- preflight --config config/local.php --database --public-root public --schema resources/install/schema.sql --storage-root storage
```

## 常用命令

```powershell
cargo fmt --check
cargo check -j1
cargo test -j1 --lib
cargo run -- migrate --dry-run --config config/local.php
cargo run -- preflight --strict --config config/local.php --database
```

Linux 部署和 release 切换脚本位于 `deploy/scripts/`，完整流程见 [docs/deployment.md](docs/deployment.md)。

## 系统架构

```text
Browser / SDK / Remote API
        |
        v
Axum HTTP Router
        |
        +-- service/       业务编排：客户端授权、后台、登录、远程 API、云存储
        +-- repository/    SQLx MySQL 数据访问
        +-- crypto/        加密、签名、token、密钥工具
        +-- install.rs     安装初始化、schema 检查、运行时补丁
        +-- deploy.rs      项目预检、release storage 检查
        |
        v
MySQL / MariaDB
```

运行时存储与 release 文件分离，生产部署时建议把 `config/local.php` 和 `storage/` 放入 shared 目录，再由 release 目录通过软链引用。

## 仓库结构

```text
src/          Rust 后端源码
public/       管理后台、登录页、安装器静态资源
resources/    数据库 schema、SDK 模板和示例
scripts/      本地回归、smoke、readiness 检查脚本
deploy/       Nginx、systemd、打包、切换和回滚脚本
docs/         架构、部署和维护文档
storage/      运行时目录占位，真实运行数据不应提交
```

## 文档

- [架构说明](docs/architecture.md)
- [部署说明](docs/deployment.md)
- [贡献指南](CONTRIBUTING.md)
- [安全策略](SECURITY.md)
- [支持说明](SUPPORT.md)
- [行为准则](CODE_OF_CONDUCT.md)
- [第三方声明](THIRD_PARTY_NOTICES.md)
- [更新日志](CHANGELOG.md)

## 贡献

欢迎提交 issue 和 pull request。提交前请先运行：

```powershell
cargo fmt --check
cargo check -j1
cargo test -j1 --lib
```

贡献流程、分支建议和代码检查说明见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 安全

本项目包含授权、签名、加密和后台管理相关逻辑。请不要在 issue、PR 或截图中公开真实密钥、云厂商凭据或用户数据。

安全问题请按 [SECURITY.md](SECURITY.md) 提供的方式报告。

## 许可证

本项目使用 [MIT License](LICENSE) 开源。第三方资源按其各自许可证授权，详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
