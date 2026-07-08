# LicenseAuth {{SdkPlatformTitle}} SDK

此包是面向 {{SdkPlatformTitle}} 的 LicenseAuth C++ SDK。包内已经写入当前应用的公开接入参数，保留登录、心跳、远程配置、远程变量、退出、解绑、token 自动轮换、本机设备身份、P-256 设备签名和请求加密能力。

## 当前应用

| 参数 | 值 |
| --- | --- |
| 应用编号 | `{{SdkAppCode}}` |
| API 地址 | `{{SdkApiUrl}}` |
| 请求 Token | `{{SdkApiToken}}` |
| 应用版本 | `{{SdkAppVersion}}` |
| 鉴权模式 | `{{SdkClientAuthMode}}` |
| 加密算法 | `{{SdkCryptoAlgorithm}}` |

## 包内容

```text
.
├── CMakeLists.txt
├── README.md
├── examples/
│   └── main.cpp
├── include/
│   ├── AuthCaBundle.hpp
│   ├── AuthClient.hpp
│   ├── AuthConfig.hpp
│   ├── AuthDeviceIdentity.hpp
│   ├── AuthError.hpp
│   └── AuthTypes.hpp
└── src/
    ├── AuthClient.cpp
    ├── AuthDeviceIdentity.cpp
    ├── AuthSupport.cpp
    └── AuthSupport.hpp
```

第三方库不再随包内置源码。SDK 只依赖平台侧提供的 OpenSSL 3.x 和 nlohmann/json，因此包内文件数保持精简，后续维护时只需要关注业务 SDK 本身。

## 依赖安装

{{SdkDependencyGuide}}

## 编译

{{SdkBuildGuide}}

构建完成后会生成：

- `LicenseAuthSdk`：静态库。
- `LicenseAuthExample`：示例程序，Android 包默认不编译示例。

## 快速开始

```cpp
#include "AuthClient.hpp"
#include <iostream>

int main() {
    try {
        LicenseAuth::Client client;

        auto login = client.login("你的卡密");
        auto heartbeat = client.heartbeat();
        auto appConfig = client.config();
        auto themeColor = client.variable("theme_color");

        std::cout << login.dump() << std::endl;
        std::cout << heartbeat.dump() << std::endl;
        std::cout << appConfig.dump() << std::endl;
        std::cout << themeColor.dump() << std::endl;
    } catch (const LicenseAuth::Error& error) {
        std::cerr << error.what() << " code=" << error.code() << std::endl;
        return 1;
    }

    return 0;
}
```

## 客户端 API

| 方法 | 说明 |
| --- | --- |
| `Client()` | 使用 `AuthConfig.hpp` 中预填的应用参数创建客户端。 |
| `login(cardKey, deviceId, deviceName)` | 登录并创建 session。`deviceId` 可为空；为空时 SDK 自动生成设备指纹 ID。 |
| `heartbeat()` | 发送心跳并自动接收新 token。 |
| `config()` | 读取应用配置并自动接收新 token。 |
| `variable(name)` | 按变量名读取远程变量并自动接收新 token。 |
| `logout()` | 注销当前 session，并清空本地会话状态。 |
| `unbind(cardKey, deviceId)` | 解绑指定卡密和设备。`deviceId` 可为空；为空时使用自动设备指纹 ID。 |
| `renewSession()` | 使用最近一次登录上下文重新登录，获取新 token。 |
| `setLoginContext(cardKey, deviceId, deviceName)` | 恢复登录上下文，用于 token 失效后的自动重新登录。 |
| `setSession(token, deviceId, ticket)` | 恢复外部保存的 token。临时票据模式需要同时传入 ticket。 |
| `hasSession()` | 判断当前是否有可用 session 信息。 |
| `token()` | 返回当前内存 token。 |
| `sessionTicket()` | 返回当前内存临时票据；本地密钥模式为空字符串。 |
| `clearSession()` | 清空当前 session 和登录上下文。 |

远程变量必须按名称读取：

```cpp
auto value = client.variable("theme_color");
```

服务端会在 `heartbeat()`、`config()`、`variable()` 成功响应中返回新 token。SDK 会立即覆盖旧 token。客户端丢失新 token 后，只要仍有登录上下文，SDK 会自动重新登录一次并重发原请求。

## 设备身份

SDK 首次登录前会生成设备身份：

- `installId`：设备安装 ID。
- `privateKeyPem`：本地设备私钥。
- `publicKeyPem`：上传给服务端保存的设备公钥。

默认保存位置：

- Windows：`%APPDATA%\.license-auth\{{SdkAppCode}}.json`，如果 `APPDATA` 不存在则使用 `%USERPROFILE%`。
- Linux / macOS / Android：`$HOME/.license-auth/{{SdkAppCode}}.json`。

业务侧也可以直接调用设备身份模块：

```cpp
#include "AuthDeviceIdentity.hpp"

auto deviceId = LicenseAuth::generateDeviceId("{{SdkAppCode}}");
auto identity = LicenseAuth::loadOrCreateDeviceIdentity("{{SdkAppCode}}", deviceId);
auto installId = identity.installId;
auto publicKey = identity.publicKeyPem;
auto signature = identity.sign("需要签名的业务字符串");
```

`generateDeviceId()` 会采集当前系统可读的稳定设备信号，归一化后按名称排序，再加入应用编号做 SHA-256，生成每个应用独立的设备 ID。Linux 和 Android 在 root 权限运行时，SDK 能读取到更多 `/sys`、`/proc`、`/system`、`/vendor` 信息；没有 root 权限时则只使用当前进程可读的信息。SDK 不会执行 `su`、`sudo` 或外部命令。

{{SdkPlatformNotes}}

## 安全模型

SDK 包不包含 `app_secret`，只包含当前应用可公开下发给客户端的接入参数。

请求流程：

1. SDK 使用服务端公钥封装一次性 AES-GCM 会话密钥。
2. 请求体使用 AES-GCM 加密。
3. 登录和会话接口使用设备私钥签名。
4. 服务端只保存设备公钥，用于校验设备签名。
5. token 每次成功调用后轮换，旧 token 不再长期复用。

如果运行环境无法创建或保存本地设备私钥，可以把 `Config::forceEphemeralTicket` 设为 `true` 进入临时票据模式。该模式会使用短时 `session_ticket` 完成会话轮换。

不要在业务代码中打印或上传以下内容：

- `device_private_key`
- 本地身份文件内容
- 当前 token
- 当前 `session_ticket`
- 卡密明文日志

## 排障

### CMake 找不到 OpenSSL 或 nlohmann_json

确认已经按本平台依赖安装步骤安装依赖，并且 CMake 命令使用了正确的 toolchain 或 `CMAKE_PREFIX_PATH`。

### HTTPS 请求失败

确认服务端证书有效，且系统时间正确。SDK 使用内置 CA 根证书包校验 HTTPS 证书，不建议关闭证书校验。

### 重启后自动重登失败

只恢复 token 不够，还需要恢复登录上下文：

```cpp
client.setLoginContext("你的卡密");
client.setSession("上次保存的token", "", "上次保存的ticket");
client.config();
```
