# 部署说明

本文档描述一个通用 Linux 部署模型。示例中的域名、路径和 release 名称都可以按自己的环境替换。

## 目录布局

```text
/var/www/network-auth
├── current -> releases/<release>
├── releases
│   └── <release>
└── shared
    ├── config
    │   └── local.php
    └── storage
        ├── cache
        ├── logs
        ├── runtime-cache
        ├── build
        └── cloud-storage
```

推荐把配置和运行数据放在 `shared` 目录中，release 目录只保存不可变的程序文件、静态资源和脚本。这样切换版本时不会覆盖运行数据。

## 构建

在 Windows 上交叉构建 Linux 二进制：

```powershell
.\deploy\scripts\build-linux-binary.ps1
```

在 Linux 上直接构建：

```bash
cargo build --release
```

## 组装 Release

```bash
deploy/scripts/assemble-release-package.sh \
  --binary /path/to/network-auth-rust \
  --release /var/www/network-auth/releases/<release> \
  --config-symlink-target /var/www/network-auth/shared/config/local.php \
  --storage-symlink-base /var/www/network-auth/shared/storage
```

## 包检查

```bash
/var/www/network-auth/releases/<release>/deploy/scripts/release-package-check.sh \
  --release /var/www/network-auth/releases/<release> \
  --require-config-symlink
```

包检查会验证必需文件、可执行权限、静态资源指纹、配置软链、storage 软链和 release 目录权限。

## 切换前 Smoke

把目标 release 先启动在临时本地端口，确认健康检查和静态资源正常：

```bash
/var/www/network-auth/releases/<release>/deploy/scripts/pre-switch-release-smoke.sh \
  --base /var/www/network-auth \
  --release <release> \
  --require-config-symlink \
  --listen 127.0.0.1:18081
```

## 安装 systemd 服务

```bash
/var/www/network-auth/releases/<release>/deploy/scripts/install-runtime-service.sh \
  --base /var/www/network-auth \
  --apply
```

## 切换当前版本

```bash
/var/www/network-auth/releases/<release>/deploy/scripts/switch-release.sh \
  --base /var/www/network-auth \
  --release <release> \
  --require-config-symlink \
  --startup-timeout 20 \
  --apply
```

## Nginx 后端切换

单 server block 配置：

```bash
deploy/scripts/switch-nginx-backend.sh \
  --config /etc/nginx/conf.d/network-auth.conf \
  --mode rust \
  --apply
```

HTTP 到 HTTPS 加 SSL server block 配置：

```bash
deploy/scripts/switch-nginx-ssl-backend.sh \
  --config /etc/nginx/conf.d/network-auth.conf \
  --mode rust \
  --apply
```

## 切换后 Gate

```bash
/var/www/network-auth/current/deploy/scripts/post-cutover-final-gate.sh \
  --base /var/www/network-auth \
  --public-health-url https://example.com/health \
  --require-config-symlink
```

## 回滚

建议至少保留一个已验证可用的 fallback release：

```bash
/var/www/network-auth/current/deploy/scripts/rollback-to-php-release.sh \
  --base /var/www/network-auth \
  --release <fallback-release> \
  --nginx-config /etc/nginx/conf.d/network-auth.conf \
  --apply
```

回滚目标可以按自己的部署模型调整。执行前先确认 fallback release 的配置软链和 shared storage 可用。
