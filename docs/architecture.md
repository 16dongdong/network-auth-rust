# 架构说明

Network Auth Rust 由 HTTP 路由层、业务服务层、MySQL 仓储层、加密工具和部署脚本组成。核心目标是把授权验证、后台管理、远程 API、云存储和发布检查组合成一个可运行的后端工程。

## 运行链路

```text
HTTP request
  -> src/http
  -> service module
  -> repository
  -> MySQL / MariaDB
  -> JSON response or static response
```

## 主要模块

| 模块 | 职责 |
| --- | --- |
| `src/main.rs` | CLI 入口，负责 serve、preflight、migrate、release storage 和清理命令。 |
| `src/config` | 解析 PHP 风格配置文件，并校验运行时配置。 |
| `src/http` | 定义 Axum 路由、静态资源入口、安装页、API 分发、云下载、中间件和响应头。 |
| `src/service/client.rs` | 客户端授权流程，包括登录、心跳、配置、远程变量、下载票据、安全上报和退出。 |
| `src/service/admin.rs` | 后台 API 分发，覆盖应用、卡密、设备、账号、站点配置、消息、审计、远程 API、云存储和 SDK 包。 |
| `src/service/admin_session.rs` | 后台签名请求、会话打开、nonce 校验和加密响应。 |
| `src/service/login.rs` | 浏览器登录页渲染、滑块挑战、管理员密码校验、Cookie 和记住登录。 |
| `src/service/remote_api.rs` | 远程 API 鉴权、签名校验、防重放、路由日志和审计集成。 |
| `src/service/admin/cloud_storage.rs` | 本地、阿里云 OSS、腾讯云 COS 对象操作，以及上传/下载 token 工具。 |
| `src/repository` | SQLx 查询、事务、领域行模型、分页、状态流转和清理任务。 |
| `src/install.rs` | schema 计划加载、数据库准备、运行时补丁、管理员初始化和安装锁生成。 |
| `src/deploy.rs` | 项目预检和 release storage 检查，供 CLI 与 shell 脚本复用。 |

## 安全设计

- 后台 API 使用 timestamp、nonce 和 HMAC 签名校验请求。
- 远程 API 使用 access key、加密 secret、HMAC 签名、防重放 nonce 和可选 IP 白名单。
- 客户端 API 支持加密请求/响应、RSA 密钥封装、AES-GCM、本地设备密钥和 P256 签名。
- 云厂商 Secret 加密落库，不以明文回显。
- 演示模式会阻止会修改数据的高风险后台操作。

## 存储设计

运行时存储与 release 内容分离：

```text
storage/
  cache/
  logs/
  runtime-cache/
  build/
  cloud-storage/
```

部署脚本期望生产 release 把这些目录指向 shared storage，因此切换版本不会删除运行数据。

## 测试与 Gate

项目包含多层验证：

- Rust 单元测试覆盖协议工具、解析、路由映射和领域行为。
- PHP 黑盒脚本检查 API 行为和数据库副作用。
- Release 脚本自测覆盖打包、smoke、回滚和 readiness 检查。
- Public runtime readiness 检查 health、静态资源、后台登录、重定向和未签名远程 API 错误。
