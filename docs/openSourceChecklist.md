# 维护检查清单

这个清单用于公开发布、打包 release 或接受外部贡献前的最后检查。

## 文件卫生

- [ ] `config/local.php`、`.env`、数据库导出和运行日志没有被跟踪。
- [ ] `storage/cache`、`storage/logs`、`storage/runtime-cache`、`storage/build`、`storage/cloud-storage` 只保留必要的占位文件。
- [ ] 没有提交真实密码、云厂商密钥、后台 Token、API Token、session token 或签名密钥。
- [ ] 没有提交真实域名、服务器 IP、发布路径、事故记录或用户数据。
- [ ] 没有提交来源不明、不可再分发或仅限本机使用的字体和素材。
- [ ] 私有笔记使用 `*.private.md` 命名，并保持 untracked。

## 许可证

- [ ] 根目录存在 `LICENSE`。
- [ ] 第三方资源已记录在 `THIRD_PARTY_NOTICES.md`。
- [ ] 第三方资源自带许可证文件时，许可证文件保留在资源目录。

## 验证

```powershell
rg -n "BEGIN .*PRIVATE|AKIA|ICP备|password|secret|credential|access[_-]?key|token|公网|生产|本地路径" .
.\scripts\openSourceAudit.ps1 -CurrentHistory
cargo fmt --check
cargo check -j1
cargo test -j1 --lib
```

关键词扫描会有业务字段误报，发布前需要逐条确认。

## 文档

- [ ] `README.md` 能说明项目用途、截图、快速开始、配置、验证和许可证。
- [ ] `CONTRIBUTING.md` 说明贡献流程和验证命令。
- [ ] `SECURITY.md` 说明漏洞报告方式和凭据处理要求。
- [ ] `SUPPORT.md` 说明适合提交 Issue 的范围。
- [ ] GitHub Issue 和 Pull Request 模板已更新。
- [ ] CI workflow 能运行格式化、编译、测试和开源审计。
