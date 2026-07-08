# 贡献指南

感谢你愿意改进 Network Auth Rust。这个项目重视可运行、可验证、可维护的工程质量，提交前请先确认改动边界清晰，并附带必要的验证结果。

## 开发流程

1. Fork 仓库并从 `master` 创建特性分支。
2. 复制 `config/local.example.php` 为本地配置，准备 MySQL 或 MariaDB。
3. 保持改动聚焦，一个 Pull Request 只解决一个明确问题。
4. 提交前运行格式化、编译检查和相关测试。
5. 在 Pull Request 中说明改动动机、影响范围和验证命令。

## 本地验证

```powershell
cargo fmt --check
cargo check -j1
cargo test -j1 --lib
.\scripts\openSourceAudit.ps1
cargo run -- preflight --config config/local.php --database --public-root public --schema resources/install/schema.sql --storage-root storage
```

涉及 PHP 黑盒回归脚本、发布脚本或部署脚本时，请补充对应脚本的运行结果。

## 代码规范

- Rust 代码保持 `cargo fmt` 输出。
- 新增业务逻辑应优先放在对应的 `service`、`repository`、`crypto` 或 `http` 模块中。
- 不提交本地配置、运行日志、数据库转储、云存储对象、构建产物或任何真实凭据。
- 不把演示数据、截图、测试输出混进源码目录。
- 修改公共协议、数据库 schema 或发布脚本时，需要同步更新 README 或 docs 文档。

## 提交信息

提交信息建议使用简短祈使句，例如：

```text
Add remote API token validation
Fix install preflight storage check
Document cloud storage setup
```

## 安全问题

请不要通过公开 Issue 披露漏洞细节。认证、签名、加密、云存储、安装流程或部署脚本相关问题，请先按 [SECURITY.md](SECURITY.md) 说明进行私下报告。
