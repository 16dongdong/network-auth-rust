# LicenseAuth C++ SDK

LicenseAuth C++ SDK 用于把应用接入授权验证服务。后台下载时会生成 Android、Windows、macOS、Linux 四个平台包，并写入当前应用的公开接入参数。各平台包不需要业务侧再拼接口、加密请求、维护 token 轮换或手写设备签名。

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
├── src/
│   ├── AuthClient.cpp
│   ├── AuthDeviceIdentity.cpp
│   ├── AuthSupport.cpp
│   └── AuthSupport.hpp
└── third_party/
    └── nlohmann/      # 仓库内编译测试使用，平台下载包不携带
```

核心文件职责：

- `AuthClient.hpp/cpp`：登录、心跳、远程配置、远程变量、退出、解绑和 token 自动轮换。
- `AuthDeviceIdentity.hpp/cpp`：设备 ID、P-256 密钥生成、本地身份保存、ECDSA 签名。
- `AuthConfig.hpp`：当前应用的 API 地址、应用编号、请求 Token、接口调用 ID 和公钥配置。
- `AuthSupport.cpp`：随机数、Base64URL、SHA-256、OpenSSL 错误处理等内部工具。

## 环境要求

- C++17 编译器
- CMake 3.16 或更高版本
- Android NDK、Windows、macOS 或 Linux C++17 工具链

仓库模板保留 nlohmann/json 头文件用于本项目编译测试；后台生成的四个平台下载包不携带第三方源码，接入方按平台 README 安装依赖：

- OpenSSL 3.x：TLS、RSA、AES-GCM、SHA-256、ECDSA、随机数、PEM。
- nlohmann/json 3.12.0：JSON 编解码。
- CA 根证书包：HTTPS 证书校验。

```bash
# Ubuntu / Debian
sudo apt install build-essential cmake

# macOS
brew install cmake

# Windows
# 安装 Visual Studio C++ 工具链或 MinGW，并安装 CMake。
```

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
        LicenseAuth::SecurityReportRequest report;
        report.eventType = "debugger_detected";
        report.riskLevel = "critical";
        report.requestedAction = "disable_card";
        report.title = "检测到调试器";
        report.message = "反调试模块检测到调试器";
        report.evidence = {{"detector", "antiDebug"}, {"matched_rule", "debug-port"}};
        report.sdkVersion = "cpp-1.0.0";
        report.detectorVersion = "antiDebug-1.0.0";
        auto securityReport = client.reportSecurityEvent(report);

        std::cout << login.dump() << std::endl;
        std::cout << heartbeat.dump() << std::endl;
        std::cout << appConfig.dump() << std::endl;
        std::cout << themeColor.dump() << std::endl;
        std::cout << securityReport.dump() << std::endl;
    } catch (const LicenseAuth::Error& error) {
        std::cerr << error.what() << " code=" << error.code() << std::endl;
        return 1;
    }

    return 0;
}
```

最小调用流程：

1. `login()`：用卡密登录，SDK 自动生成或加载设备 ID 和设备密钥。
2. `heartbeat()`：维持会话，服务端会下发新 token，SDK 自动覆盖内存 token。
3. `config()`：读取应用配置。
4. `variable("变量名")`：按变量名读取单个远程变量。
5. `reportSecurityEvent(request)`：客户端主动上报反调试、防破解或完整性事件。
6. `logout()`：退出并撤销当前 session。

## 编译示例

在 SDK 根目录执行：

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

构建完成后会生成：

- `LicenseAuthSdk`：静态库。
- `LicenseAuthExample`：示例程序。

## 集成到现有 CMake 项目

把 SDK 目录放进你的项目，例如：

```text
your-app/
├── CMakeLists.txt
├── src/
│   └── main.cpp
└── vendor/
    └── license-auth-cpp-sdk/
```

在你的 `CMakeLists.txt` 中引用：

```cmake
cmake_minimum_required(VERSION 3.16)
project(YourApp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(vendor/license-auth-cpp-sdk)

add_executable(YourApp src/main.cpp)
target_link_libraries(YourApp PRIVATE LicenseAuthSdk)
```

## 客户端 API

| 方法 | 说明 |
| --- | --- |
| `Client()` | 使用 `AuthConfig.hpp` 中预填的应用参数创建客户端。 |
| `login(cardKey, deviceId, deviceName)` | 登录并创建 session。`deviceId` 可为空；为空时 SDK 自动生成设备指纹 ID。成功后 SDK 保存当前 token、设备 ID 和登录上下文。 |
| `heartbeat()` | 发送心跳并自动接收新 token。 |
| `config()` | 读取应用配置并自动接收新 token。 |
| `variable(name)` | 按变量名读取远程变量并自动接收新 token。 |
| `reportSecurityEvent(request)` | 上报安全事件；`requestedAction` 支持 `record_only`、`kick_session`、`disable_device`、`disable_card`。 |
| `logout()` | 注销当前 session，并清空本地会话状态。 |
| `unbind(cardKey, deviceId)` | 解绑指定卡密和设备。`deviceId` 可为空；为空时使用自动设备指纹 ID。 |
| `renewSession()` | 使用最近一次登录上下文重新登录，获取新 token。 |
| `setLoginContext(cardKey, deviceId, deviceName)` | 恢复登录上下文，用于 token 失效后的自动重新登录。`deviceId` 可为空。 |
| `setSession(token, deviceId, ticket)` | 恢复外部保存的 token。`deviceId` 可为空；临时票据模式需要同时传入 ticket。 |
| `hasSession()` | 判断当前是否有可用 session 信息。 |
| `token()` | 返回当前内存 token。 |
| `sessionTicket()` | 返回当前内存临时票据；本地密钥模式为空字符串。 |
| `clearSession()` | 清空当前 session 和登录上下文。 |

远程变量必须按名称读取：

```cpp
auto value = client.variable("theme_color");
```

远程变量通过变量名按变量名单独拉取，SDK 不会整包拉取全部远程变量。

安全上报示例：

```cpp
LicenseAuth::SecurityReportRequest report;
report.eventType = "hook_detected";
report.riskLevel = "high";
report.requestedAction = "disable_device";
report.actionReason = "接入方反调试策略命中";
report.title = "检测到 Hook 行为";
report.message = "反调试模块检测到 Inline Hook";
report.evidence = {{"detector", "antiDebug"}, {"matched_rule", "inline-hook"}};
report.sdkVersion = "cpp-1.0.0";
report.detectorVersion = "antiDebug-1.0.0";
auto result = client.reportSecurityEvent(report);
```

客户端只表达期望处置动作，实际封禁的卡密、设备和会话由服务端根据当前 session 推导，并由后台策略裁决最终动作；`manual_review` 只能由服务端策略产生。次数卡不绑定设备，`disable_device` 会由服务端降级为踢当前会话。

## Token 机制

服务端会在 `heartbeat()`、`config()`、`variable()` 成功响应中返回新 token。SDK 会立即覆盖旧 token，业务侧不需要手动替换。

如果客户端丢失了新 token，下一次会话请求可能返回 `SESSION_INVALID`。只要 SDK 内还有登录上下文，SDK 会自动重新登录一次，然后重发原请求。

如果运行环境无法创建或保存本地设备私钥，可以把 `Config::forceEphemeralTicket` 设为 `true` 进入临时票据模式。该模式不会下发设备私钥，而是在登录后下发短时 `session_ticket`。后续请求必须同时携带 token 和上一次 ticket，服务端校验成功后会同时轮换 token 和 ticket。SDK 会自动覆盖保存新 ticket。

如果你自己持久化 token，并在应用重启后恢复 session，需要同时恢复登录上下文：

```cpp
LicenseAuth::Client client;

client.setLoginContext("你的卡密");
client.setSession("上次保存的token", "", "上次保存的ticket");

auto appConfig = client.config();
```

也可以在需要时主动重新登录获取新 token：

```cpp
client.renewSession();
```

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

当前采集范围包括：

- Linux DMI：主板序列号、整机 UUID、厂商、机型等。
- Linux / Android SoC：芯片序列号、SoC ID、机型族信息等。
- Android build properties：设备型号、厂商、系统指纹、启动序列号等。
- CPU 信息：硬件名、修订号、CPU 序列号、型号名。
- 网络和存储：网卡 MAC、块设备序列号或 WWID。
- 系统机器 ID：`/etc/machine-id`、`/var/lib/dbus/machine-id`。
- 运行环境：主机名、Windows `COMPUTERNAME`。

当前包内置跨平台软件 P-256 实现，Windows、Linux、macOS 和 Android NDK 都可以编译使用。系统 Keystore、TPM、Secure Enclave 需要真实平台适配，不能用空接口伪装不可导出私钥；后续适配时应保持 `AuthDeviceIdentity` 对外接口不变。

## 安全模型

SDK 包不包含 `app_secret`，只包含当前应用可公开下发给客户端的接入参数。

请求流程：

1. SDK 使用服务端公钥封装一次性 AES-GCM 会话密钥。
2. 请求体使用 AES-GCM 加密。
3. 登录和会话接口使用设备私钥签名。
4. 服务端只保存设备公钥，用于校验设备签名。
5. token 每次成功调用后轮换，旧 token 不再长期复用。

低可信临时票据模式：

1. SDK 不上传设备公钥，也不提交设备签名。
2. 服务端登录成功后下发短时 `session_ticket`。
3. 每次会话请求都必须携带当前 token 和当前 ticket。
4. 请求成功后 token 与 ticket 同时轮换，旧 ticket 立即失效。
5. 后台禁用设备或撤销 session 后，ticket 同步失效。

不要在业务代码中打印或上传以下内容：

- `device_private_key`
- 本地身份文件内容
- 当前 token
- 当前 `session_ticket`
- 卡密明文日志

## 错误处理

所有 SDK 层错误都会抛出 `LicenseAuth::Error`。

```cpp
try {
    auto result = client.login("你的卡密");
} catch (const LicenseAuth::Error& error) {
    std::cerr << error.what() << std::endl;
    std::cerr << "code: " << error.code() << std::endl;
    std::cerr << "http: " << error.httpStatus() << std::endl;
}
```

常见错误：

| 错误 | 处理方式 |
| --- | --- |
| `SESSION_INVALID` | token 已失效。确认已调用 `setLoginContext()`，SDK 会自动重新登录。 |
| `SESSION_TOKEN_MISSING` | 服务端响应缺少新 token，需要检查服务端版本和接口返回。 |
| `SESSION_TICKET_MISSING` | 临时票据模式下服务端响应缺少新 ticket，需要检查服务端版本和接口返回。 |
| `SESSION_TICKET_INVALID` | 临时票据无效，重新登录获取新 ticket。 |
| `CARD_INVALID` | 卡密不存在、已禁用或不属于当前应用。 |
| `DEVICE_DISABLED` | 设备已被后台禁用，需要在后台启用后重新登录。 |
| `SIGNATURE_INVALID` | 设备签名不匹配，通常是设备身份文件被替换或服务端保存的公钥不一致。 |

## 发布检查

接入正式业务前确认：

- API 地址使用 HTTPS。
- 客户端机器时间基本准确。
- 默认使用 SDK 自动生成的设备指纹 ID；如果业务侧显式传入 `deviceId`，必须保证同一设备保持稳定。
- 业务日志不记录 token、卡密、设备私钥。
- 退出账号时调用 `logout()`。
- 长时间运行程序定期调用 `heartbeat()`。
- 远程变量使用 `variable("变量名")` 按需读取。

## 排障

### CMake 找不到头文件

确认你的业务目标已经链接 `LicenseAuthSdk`：

```cmake
target_link_libraries(YourApp PRIVATE LicenseAuthSdk)
```

### HTTPS 请求失败

确认服务端证书有效，且系统时间正确。SDK 使用内置 CA 根证书包校验 HTTPS 证书，不建议关闭证书校验。

### 重启后自动重登失败

只恢复 token 不够，还需要恢复登录上下文：

```cpp
client.setLoginContext("你的卡密");
client.setSession("上次保存的token", "", "上次保存的ticket");
```

### 后台禁用设备后客户端无法登录

这是预期行为。禁用设备会撤销该设备有效 session，登录、心跳、配置、变量和退出接口都会被拒绝。需要后台重新启用设备后再登录。
