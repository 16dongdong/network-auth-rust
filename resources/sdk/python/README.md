# LicenseAuth Python SDK

此 SDK 已预填应用信息，解压后安装依赖即可直接集成。

## 当前应用

- 应用编号：`{{SdkAppCode}}`
- API 地址：`{{SdkApiUrl}}`
- 请求 Token：`{{SdkApiToken}}`
- 应用版本：`{{SdkAppVersion}}`
- 鉴权模式：`{{SdkClientAuthMode}}`
- 加密算法：`{{SdkCryptoAlgorithm}}`

## 安装依赖

```bash
python -m pip install -r requirements.txt
```

## 使用

```python
from licenseauth import Client

client = Client()
login = client.login("你的卡密")
heartbeat = client.heartbeat()
config = client.config()
theme = client.variable("theme_color")
security = client.reportSecurityEvent(
    "debugger_detected",
    riskLevel="critical",
    requestedAction="disable_card",
    title="检测到调试器",
    message="反调试模块检测到调试器",
    evidence={"detector": "antiDebug", "matched_rule": "debug-port"},
    sdkVersion="python-1.0.0",
    detectorVersion="antiDebug-1.0.0",
)
```

SDK 首次登录前会自动生成设备指纹 ID 和设备密钥对，请求 `/login/challenge` 时上传设备公钥。后续登录、心跳、配置、变量、退出和解绑都会由 SDK 使用本地设备私钥签名，服务端只保存设备公钥。

请求 Token、API 调用 ID、成功状态码已经写入 SDK 配置，调用业务接口时会自动附带并校验。

远程变量通过 `variable("变量名")` 按变量名单独拉取，不会整包下发全部变量。

安全上报通过 `reportSecurityEvent()` 主动发送反调试、防破解或完整性事件。`requestedAction` 支持 `record_only`、`kick_session`、`disable_device`、`disable_card`。客户端只表达期望动作，服务端根据当前 session 推导卡密、设备和会话目标，并按后台策略裁决最终动作；`manual_review` 只能由服务端策略产生。次数卡不绑定设备，`disable_device` 会降级为踢当前会话。

`heartbeat`、`config`、`variable` 成功后 SDK 会自动覆盖保存服务端下发的新 token。

如果某次成功响应里的新 token 在客户端本地丢失，SDK 在下一次会话请求遇到 `SESSION_INVALID` 时，会使用最近一次 `login()` 的卡密和设备信息自动重新登录一次，再自动补发原请求。

如果运行环境无法创建或保存本地设备私钥，可以把 `Config.forceEphemeralTicket` 设为 `True` 进入临时票据模式。该模式不会下发设备私钥，而是在登录后下发短时 `session_ticket`。后续请求必须同时携带 token 和上一次 ticket，服务端校验成功后会同时轮换 token 和 ticket。SDK 会自动覆盖保存新 ticket。

```python
from licenseauth import Client, Config

config = Config(forceEphemeralTicket=True)
client = Client(config)
client.login("你的卡密")
```

如果你自己持久化了 token，并在下次启动时通过 `setSession()` 恢复它，想继续启用这套自动重登恢复逻辑，还要同时恢复登录上下文：

```python
client.setLoginContext("你的卡密")
client.setSession("上次保存的token", ticket="上次保存的ticket")
```

也可以主动调用：

```python
client.renewSession()
```

## 设备身份模块

设备身份能力已经从 `Client` 拆出，可以由业务侧直接调用：

```python
from licenseauth import generateDeviceId, loadOrCreateDeviceIdentity

device_id = generateDeviceId("{{SdkAppCode}}")
identity = loadOrCreateDeviceIdentity("{{SdkAppCode}}", device_id)
install_id = identity.installId
public_key = identity.publicKeyPem
signature = identity.sign("需要签名的业务字符串")
```

`generateDeviceId()` 会采集当前系统可读的稳定设备信号，归一化后按名称排序，再加入应用编号做 SHA-256，生成每个应用独立的设备 ID。Linux 和 Android 在 root 权限运行时，SDK 能读取到更多 `/sys`、`/proc`、`/system`、`/vendor` 信息；没有 root 权限时则只使用当前进程可读的信息。SDK 不会执行 `su`、`sudo` 或外部命令。

文件职责：

- `client.py`：登录、心跳、远程配置、远程变量、退出、解绑。
- `identity.py`：设备 ID、P-256 密钥生成、本地身份保存、ECDSA 签名。
- `crypto.py`：RSA、AES-GCM、SHA-256、Base64URL 和底层签名函数。

Python SDK 使用 `cryptography` 生成跨平台软件 P-256 密钥。系统 Keystore/TPM/Secure Enclave 需要原生平台扩展，不能在纯 Python 包里伪装不可导出私钥。
