#include "AuthClient.hpp"
#include "AuthCaBundle.hpp"
#include "AuthSupport.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509err.h>
#include <openssl/x509_vfy.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstring>
#include <ctime>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>
#include <utility>

namespace LicenseAuth {
namespace {

using SdkInternal::Bytes;
using SdkInternal::base64UrlDecode;
using SdkInternal::base64UrlEncode;
using SdkInternal::bytesToString;
using SdkInternal::randomBytes;
using SdkInternal::requireOpenSsl;
using SdkInternal::sha256Hex;
using SdkInternal::trimCopy;

constexpr const char* kProofModeLocalKey = "local_key_v1";
constexpr const char* kProofModeEphemeralTicket = "ephemeral_ticket_v1";
constexpr std::array<const char*, 4> kSecurityRequestedActions = {"record_only", "kick_session", "disable_device", "disable_card"};
constexpr std::array<const char*, 8> kSecurityEvidenceFields = {
    "detector",
    "matched_rule",
    "module_hash",
    "symbol_hash",
    "process_hashes",
    "debug_port_open",
    "hook_count",
    "attestation_verdict"
};
constexpr std::array<const char*, 7> kSecurityAttestationFields = {
    "provider",
    "nonce_hash",
    "challenge_hash",
    "verdict",
    "key_id",
    "certificate_hash",
    "error_code"
};

struct Envelope {
    std::string iv;
    std::string ciphertext;
    std::string tag;
};

struct Algorithm {
    int keyBytes;
    int rsaPadding;
};

struct ParsedUrl {
    bool tls;
    std::string host;
    std::string port;
    std::string target;
};

struct AuthorityParts {
    std::string host;
    std::string port;
};

struct NoticeCacheEntry {
    Json value;
    std::time_t expiresAt;
};

std::mutex noticeCacheMutex;
std::map<std::string, NoticeCacheEntry> noticeCacheValues;

Algorithm algorithmConfig(const std::string& name) {
    if (name == "rsa_oaep_aes_256_gcm") {
        return {32, RSA_PKCS1_OAEP_PADDING};
    }
    if (name == "rsa_oaep_aes_128_gcm") {
        return {16, RSA_PKCS1_OAEP_PADDING};
    }
    if (name == "rsa_pkcs1_aes_256_gcm") {
        return {32, RSA_PKCS1_PADDING};
    }
    throw Error("unsupported client crypto algorithm: " + name);
}

int checkedIntSize(std::size_t size, const std::string& message) {
    if (size > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw Error(message);
    }
    return static_cast<int>(size);
}

const EVP_CIPHER* aesGcmCipher(const Bytes& key) {
    if (key.size() == 16) {
        return EVP_aes_128_gcm();
    }
    if (key.size() == 32) {
        return EVP_aes_256_gcm();
    }
    throw Error("AES-GCM key length is invalid");
}

Json loginPayload(const std::string& cardKey, const std::string& installId, const std::string& deviceName) {
    const std::string card = trimCopy(cardKey);
    if (card.empty()) {
        throw Error("card key is required");
    }
    return Json{
        {"card_key", card},
        {"install_id", trimCopy(installId)},
        {"device_name", trimCopy(deviceName)}
    };
}

template <std::size_t Size>
void requireAllowedObjectKeys(const Json& value, const std::array<const char*, Size>& allowedKeys, const std::string& fieldName) {
    for (auto iterator = value.begin(); iterator != value.end(); ++iterator) {
        const std::string key = iterator.key();
        const bool allowed = std::any_of(allowedKeys.begin(), allowedKeys.end(), [&key](const char* allowedKey) {
            return key == allowedKey;
        });
        if (!allowed) {
            throw Error("security report " + fieldName + " contains unsupported fields", "SECURITY_REPORT_INVALID");
        }
    }
}

std::string securityRequestedAction(const std::string& value) {
    const std::string action = trimCopy(value);
    const bool allowed = std::any_of(kSecurityRequestedActions.begin(), kSecurityRequestedActions.end(), [&action](const char* allowedAction) {
        return action == allowedAction;
    });
    if (!allowed) {
        throw Error("security report requested action is invalid", "SECURITY_ACTION_INVALID");
    }
    return action;
}

std::string requiredSecurityText(const std::string& value, const std::string& fieldName) {
    const std::string text = trimCopy(value);
    if (text.empty()) {
        throw Error("security report " + fieldName + " is required", "SECURITY_REPORT_INVALID");
    }
    return text;
}

Error apiErrorFromJson(const Json& response, int httpStatus = 0) {
    const std::string message = response.value("message", response.value("error", "request failed"));
    const std::string code = response.value("error", "");
    const int status = httpStatus > 0 ? httpStatus : response.value("code", 0);
    return Error(message, code, status);
}

std::string cardHash(const std::string& appCode, const std::string& cardKey) {
    return sha256Hex(appCode + ":" + cardKey);
}

std::string ephemeralChallengeId() {
    return std::string("ephemeral.") + base64UrlEncode(randomBytes(18));
}

std::string noticeCacheKey(const Config& config) {
    return config.apiUrl + "\n" + config.appCode;
}

Json cachedNotice(const Config& config, const std::function<Json()>& loader) {
    if (config.noticeCacheSeconds <= 0) {
        return loader();
    }

    const std::time_t now = std::time(nullptr);
    const std::string cacheKey = noticeCacheKey(config);
    std::lock_guard<std::mutex> guard(noticeCacheMutex);
    auto cached = noticeCacheValues.find(cacheKey);
    if (cached != noticeCacheValues.end() && cached->second.expiresAt > now) {
        return cached->second.value;
    }

    Json notice = loader();
    noticeCacheValues[cacheKey] = NoticeCacheEntry{notice, now + config.noticeCacheSeconds};
    return notice;
}

bool retryableGatewayError(const Error& error) {
    const int status = error.httpStatus();
    return status == 502 || status == 503 || status == 504;
}

bool retryableLoginError(const Error& error) {
    return error.code() == "NETWORK_ERROR" || error.code() == "DB_ERROR" || retryableGatewayError(error);
}

Envelope aesGcmEncrypt(const std::string& plaintext, const Bytes& key, const std::string& aad) {
    Bytes iv = randomBytes(12);
    Bytes ciphertext(plaintext.size());
    Bytes tag(16);
    int outputLength = 0;
    int finalLength = 0;
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    requireOpenSsl(context != nullptr, "AES-GCM context setup failed");
    requireOpenSsl(EVP_EncryptInit_ex(context.get(), aesGcmCipher(key), nullptr, nullptr, nullptr) == 1, "AES-GCM cipher setup failed");
    requireOpenSsl(EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, checkedIntSize(iv.size(), "AES-GCM IV is too large"), nullptr) == 1, "AES-GCM IV setup failed");
    requireOpenSsl(EVP_EncryptInit_ex(context.get(), nullptr, nullptr, key.data(), iv.data()) == 1, "AES-GCM key setup failed");
    if (!aad.empty()) {
        requireOpenSsl(EVP_EncryptUpdate(context.get(), nullptr, &outputLength, reinterpret_cast<const unsigned char*>(aad.data()), checkedIntSize(aad.size(), "AES-GCM AAD is too large")) == 1, "AES-GCM AAD setup failed");
    }
    if (!plaintext.empty()) {
        requireOpenSsl(EVP_EncryptUpdate(context.get(), ciphertext.data(), &outputLength, reinterpret_cast<const unsigned char*>(plaintext.data()), checkedIntSize(plaintext.size(), "AES-GCM plaintext is too large")) == 1, "AES-GCM encrypt failed");
    }
    requireOpenSsl(EVP_EncryptFinal_ex(context.get(), ciphertext.data() + outputLength, &finalLength) == 1, "AES-GCM encrypt finalization failed");
    ciphertext.resize(static_cast<std::size_t>(outputLength + finalLength));
    requireOpenSsl(EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG, checkedIntSize(tag.size(), "AES-GCM tag is too large"), tag.data()) == 1, "AES-GCM tag export failed");
    return {base64UrlEncode(iv), base64UrlEncode(ciphertext), base64UrlEncode(tag)};
}

std::string aesGcmDecrypt(const Json& envelope, const Bytes& key, const std::string& aad) {
    Bytes iv = base64UrlDecode(envelope.at("iv").get<std::string>());
    Bytes ciphertext = base64UrlDecode(envelope.at("ciphertext").get<std::string>());
    Bytes tag = base64UrlDecode(envelope.at("tag").get<std::string>());
    Bytes plaintext(ciphertext.size());
    int outputLength = 0;
    int finalLength = 0;
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    requireOpenSsl(context != nullptr, "AES-GCM context setup failed");
    requireOpenSsl(EVP_DecryptInit_ex(context.get(), aesGcmCipher(key), nullptr, nullptr, nullptr) == 1, "AES-GCM cipher setup failed");
    requireOpenSsl(EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, checkedIntSize(iv.size(), "AES-GCM IV is too large"), nullptr) == 1, "AES-GCM IV setup failed");
    requireOpenSsl(EVP_DecryptInit_ex(context.get(), nullptr, nullptr, key.data(), iv.data()) == 1, "AES-GCM key setup failed");
    if (!aad.empty()) {
        requireOpenSsl(EVP_DecryptUpdate(context.get(), nullptr, &outputLength, reinterpret_cast<const unsigned char*>(aad.data()), checkedIntSize(aad.size(), "AES-GCM AAD is too large")) == 1, "AES-GCM AAD setup failed");
    }
    if (!ciphertext.empty()) {
        requireOpenSsl(EVP_DecryptUpdate(context.get(), plaintext.data(), &outputLength, ciphertext.data(), checkedIntSize(ciphertext.size(), "AES-GCM ciphertext is too large")) == 1, "AES-GCM decrypt failed");
    }
    requireOpenSsl(EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG, checkedIntSize(tag.size(), "AES-GCM tag is too large"), tag.data()) == 1, "AES-GCM tag setup failed");
    requireOpenSsl(EVP_DecryptFinal_ex(context.get(), plaintext.data() + outputLength, &finalLength) == 1, "AES-GCM response validation failed");
    plaintext.resize(static_cast<std::size_t>(outputLength + finalLength));
    return bytesToString(plaintext);
}

Bytes rsaEncrypt(const std::string& publicKey, const Bytes& payload, const Algorithm& algorithm) {
    std::unique_ptr<BIO, decltype(&BIO_free)> keyBio(BIO_new_mem_buf(publicKey.data(), checkedIntSize(publicKey.size(), "client public key is too large")), BIO_free);
    requireOpenSsl(keyBio != nullptr, "client public key buffer setup failed");
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(PEM_read_bio_PUBKEY(keyBio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    requireOpenSsl(key != nullptr, "invalid client public key");
    if (EVP_PKEY_is_a(key.get(), "RSA") != 1) {
        throw Error("client public key is not RSA");
    }
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(EVP_PKEY_CTX_new(key.get(), nullptr), EVP_PKEY_CTX_free);
    requireOpenSsl(context != nullptr, "RSA encrypt context setup failed");
    requireOpenSsl(EVP_PKEY_encrypt_init(context.get()) == 1, "RSA encrypt setup failed");
    requireOpenSsl(EVP_PKEY_CTX_set_rsa_padding(context.get(), algorithm.rsaPadding) == 1, "RSA padding setup failed");
    if (algorithm.rsaPadding == RSA_PKCS1_OAEP_PADDING) {
        requireOpenSsl(EVP_PKEY_CTX_set_rsa_oaep_md(context.get(), EVP_sha1()) == 1, "RSA OAEP digest setup failed");
        requireOpenSsl(EVP_PKEY_CTX_set_rsa_mgf1_md(context.get(), EVP_sha1()) == 1, "RSA OAEP MGF1 setup failed");
    }
    std::size_t outputLength = 0;
    requireOpenSsl(EVP_PKEY_encrypt(context.get(), nullptr, &outputLength, payload.data(), payload.size()) == 1, "RSA encrypt sizing failed");
    Bytes output(outputLength);
    requireOpenSsl(EVP_PKEY_encrypt(context.get(), output.data(), &outputLength, payload.data(), payload.size()) == 1, "RSA encrypt failed");
    output.resize(outputLength);
    return output;
}

std::string resolvedDeviceName(const std::string& deviceName) {
    return trimCopy(deviceName);
}

std::string normalizedProofMode(const Json& response) {
    const std::string mode = trimCopy(response.value("proof_mode", kProofModeLocalKey));
    return mode.empty() ? kProofModeLocalKey : mode;
}

std::string machineProfileHash(const Config& config) {
    return sha256Hex(config.appCode + "\n" + config.apiUrl + "\n" + config.clientAuthMode + "\n" + config.clientCryptoAlgorithm);
}

std::string sdkPlatformName() {
#if defined(_WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "macos";
#elif defined(__ANDROID__)
    return "android";
#elif defined(__linux__)
    return "linux";
#else
    return "unknown";
#endif
}

std::string securityEventId(const std::string& eventId) {
    const std::string normalized = trimCopy(eventId);
    return normalized.empty() ? base64UrlEncode(randomBytes(18)) : normalized;
}

std::string sessionExtra(const std::string& route, const Json& payload) {
    if (route == "/variable") {
        return trimCopy(payload.value("name", ""));
    }
    if (route == "/security/report") {
        return trimCopy(payload.value("event_id", ""));
    }
    if (route == "/cloud/download-ticket") {
        return payload.value("file_key", "");
    }
    return "";
}

std::string loginCanonical(const std::string& challengeId, const std::string& installId, long timestamp, const std::string& machineProfileHash, const std::string& cardHash, const std::string& serverNonce) {
    return "POST\n/login\n" + challengeId + "\n" + installId + "\n" + std::to_string(timestamp) + "\n" + machineProfileHash + "\n" + cardHash + "\n" + serverNonce;
}

std::string unbindCanonical(const std::string& installId, long timestamp, const std::string& cardHash) {
    return "POST\n/unbind\n" + installId + "\n" + std::to_string(timestamp) + "\n" + cardHash;
}

std::string sessionCanonical(const std::string& route, const std::string& token, const std::string& installId, unsigned long long counter, const std::string& requestNonce, long timestamp, const std::string& extra) {
    return "POST\n" + route + "\n" + token + "\n" + installId + "\n" + std::to_string(counter) + "\n" + requestNonce + "\n" + std::to_string(timestamp) + "\n" + sha256Hex(extra);
}

std::string requestAad(const std::string& route, const std::string& timestamp, const std::string& nonce, const std::string& algorithm) {
    return "client-request\n" + route + "\n" + timestamp + "\n" + nonce + "\n" + algorithm;
}

std::string responseAad(const std::string& route, const std::string& timestamp, const std::string& nonce, const std::string& algorithm) {
    return "client-response\n" + route + "\n" + timestamp + "\n" + nonce + "\n" + algorithm;
}

std::string urlEncode(const std::string& value) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string output;
    for (unsigned char item : value) {
        const bool keep = (item >= 'A' && item <= 'Z') || (item >= 'a' && item <= 'z') || (item >= '0' && item <= '9')
            || item == '-' || item == '_' || item == '.' || item == '~';
        if (keep) {
            output.push_back(static_cast<char>(item));
            continue;
        }
        output.push_back('%');
        output.push_back(digits[item >> 4]);
        output.push_back(digits[item & 0x0f]);
    }
    return output;
}

std::string routeUrl(const std::string& apiUrl, const std::string& route) {
    return apiUrl + (apiUrl.find('?') == std::string::npos ? "?route=" : "&route=") + urlEncode(route);
}

std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char item) {
        return static_cast<char>(std::tolower(item));
    });
    return value;
}

AuthorityParts parseBracketedAuthority(const std::string& authority) {
    const std::size_t close = authority.find(']');
    if (close == std::string::npos) {
        throw Error("API URL IPv6 host is invalid");
    }
    AuthorityParts parts{authority.substr(1, close - 1), ""};
    if (close + 1 < authority.size()) {
        if (authority[close + 1] != ':') {
            throw Error("API URL port is invalid");
        }
        parts.port = authority.substr(close + 2);
    }
    return parts;
}

AuthorityParts parseHostAuthority(const std::string& authority) {
    const std::size_t colon = authority.rfind(':');
    if (colon != std::string::npos && authority.find(':') == colon) {
        return {authority.substr(0, colon), authority.substr(colon + 1)};
    }
    return {authority, ""};
}

AuthorityParts parseAuthority(const std::string& authority) {
    if (authority.empty() || authority.find('@') != std::string::npos) {
        throw Error("API URL authority is invalid");
    }
    if (authority.front() == '[') {
        return parseBracketedAuthority(authority);
    }
    return parseHostAuthority(authority);
}

void validateAuthorityParts(const AuthorityParts& parts) {
    if (parts.host.empty()) {
        throw Error("API URL host is empty");
    }
    if (!parts.port.empty() && !std::all_of(parts.port.begin(), parts.port.end(), [](unsigned char item) { return std::isdigit(item) != 0; })) {
        throw Error("API URL port is invalid");
    }
}

ParsedUrl parseUrl(const std::string& url) {
    const std::size_t schemeEnd = url.find("://");
    if (schemeEnd == std::string::npos) {
        throw Error("API URL missing scheme");
    }
    const std::string scheme = lowercase(url.substr(0, schemeEnd));
    if (scheme != "http" && scheme != "https") {
        throw Error("API URL scheme must be http or https");
    }

    const std::size_t authorityStart = schemeEnd + 3;
    const std::size_t pathStart = url.find('/', authorityStart);
    const std::string authority = url.substr(authorityStart, pathStart == std::string::npos ? std::string::npos : pathStart - authorityStart);
    AuthorityParts parts = parseAuthority(authority);
    validateAuthorityParts(parts);
    if (parts.port.empty()) {
        parts.port = scheme == "https" ? "443" : "80";
    }
    std::string target = pathStart == std::string::npos ? "/" : url.substr(pathStart);
    return {scheme == "https", parts.host, parts.port, target};
}

std::string hostHeader(const ParsedUrl& url) {
    const bool defaultPort = (url.tls && url.port == "443") || (!url.tls && url.port == "80");
    const bool ipv6 = url.host.find(':') != std::string::npos;
    const std::string host = ipv6 ? "[" + url.host + "]" : url.host;
    return defaultPort ? host : host + ":" + url.port;
}

std::string apiCallId(const Config& config, const std::string& route) {
    auto found = config.apiCallIds.find(route);
    return found == config.apiCallIds.end() ? "" : found->second;
}

std::string httpRequestText(const ParsedUrl& url, const Config& config, const std::string& route, const std::string& body, const std::string& timestamp, const std::string& nonce, bool plainClient) {
    std::ostringstream request;
    request << "POST " << url.target << " HTTP/1.1\r\n"
        << "Host: " << hostHeader(url) << "\r\n"
        << "Content-Type: application/json\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Connection: close\r\n"
        << "X-App-Code: " << config.appCode << "\r\n"
        << "X-Api-Token: " << config.apiToken << "\r\n"
        << "X-Api-Call-Id: " << apiCallId(config, route) << "\r\n"
        << "X-Timestamp: " << timestamp << "\r\n"
        << "X-Nonce: " << nonce << "\r\n";
    if (plainClient) {
        request << "X-Plain-Client: 1\r\n";
    }
    request << "\r\n" << body;
    return request.str();
}

std::string connectAddress(const ParsedUrl& url) {
    const bool ipv6 = url.host.find(':') != std::string::npos;
    return (ipv6 ? "[" + url.host + "]" : url.host) + ":" + url.port;
}

void addTrustCertificate(X509_STORE* store, X509* certificate) {
    if (X509_STORE_add_cert(store, certificate) == 1) {
        return;
    }
    const unsigned long error = ERR_peek_last_error();
    if (ERR_GET_LIB(error) == ERR_LIB_X509 && ERR_GET_REASON(error) == X509_R_CERT_ALREADY_IN_HASH_TABLE) {
        ERR_clear_error();
        return;
    }
    requireOpenSsl(false, "CA certificate import failed");
}

void loadCaBundle(SSL_CTX* context) {
    std::unique_ptr<BIO, decltype(&BIO_free)> input(BIO_new_mem_buf(kCaBundlePem, checkedIntSize(std::strlen(kCaBundlePem), "CA bundle is too large")), BIO_free);
    requireOpenSsl(input != nullptr, "CA bundle buffer setup failed");
    X509_STORE* store = SSL_CTX_get_cert_store(context);
    requireOpenSsl(store != nullptr, "TLS trust store setup failed");
    int loaded = 0;
    while (true) {
        std::unique_ptr<X509, decltype(&X509_free)> certificate(PEM_read_bio_X509(input.get(), nullptr, nullptr, nullptr), X509_free);
        if (!certificate) {
            ERR_clear_error();
            break;
        }
        addTrustCertificate(store, certificate.get());
        loaded++;
    }
    if (loaded == 0) {
        throw Error("CA bundle is empty");
    }
}

std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> tlsContext() {
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    requireOpenSsl(context != nullptr, "TLS context setup failed");
    requireOpenSsl(SSL_CTX_set_min_proto_version(context.get(), TLS1_2_VERSION) == 1, "TLS minimum version setup failed");
    SSL_CTX_set_verify(context.get(), SSL_VERIFY_PEER, nullptr);
    loadCaBundle(context.get());
    return context;
}

class HttpConnection final {
public:
    explicit HttpConnection(const ParsedUrl& url) : parsedUrl(url), sslContext(nullptr, SSL_CTX_free), connection(nullptr, BIO_free_all) {
        connect();
    }

    void writeAll(const std::string& request) {
        std::size_t offset = 0;
        while (offset < request.size()) {
            const int written = BIO_write(connection.get(), request.data() + offset, checkedIntSize(request.size() - offset, "HTTP request is too large"));
            if (written > 0) {
                offset += static_cast<std::size_t>(written);
                continue;
            }
            retryOrThrow("HTTP request write failed");
        }
    }

    std::string readAll() {
        std::string response;
        std::vector<unsigned char> buffer(8192);
        while (true) {
            const int readSize = BIO_read(connection.get(), buffer.data(), checkedIntSize(buffer.size(), "HTTP response buffer is too large"));
            if (readSize > 0) {
                response.append(reinterpret_cast<const char*>(buffer.data()), static_cast<std::size_t>(readSize));
                continue;
            }
            if (readSize == 0) {
                return response;
            }
            retryOrThrow("HTTP response read failed");
        }
    }

private:
    void connect() {
        if (parsedUrl.tls) {
            connectTls();
        } else {
            connectPlain();
        }
    }

    void connectPlain() {
        connection.reset(BIO_new_connect(connectAddress(parsedUrl).c_str()));
        requireOpenSsl(connection != nullptr, "TCP connection setup failed");
        requireOpenSsl(BIO_do_connect(connection.get()) == 1, "TCP connection failed");
    }

    void connectTls() {
        sslContext = tlsContext();
        connection.reset(BIO_new_ssl_connect(sslContext.get()));
        requireOpenSsl(connection != nullptr, "TLS connection setup failed");
        SSL* ssl = nullptr;
        BIO_get_ssl(connection.get(), &ssl);
        requireOpenSsl(ssl != nullptr, "TLS session setup failed");
        configureTlsHost(ssl);
        BIO_set_conn_hostname(connection.get(), connectAddress(parsedUrl).c_str());
        requireOpenSsl(BIO_do_connect(connection.get()) == 1, "TCP connection failed");
        requireOpenSsl(BIO_do_handshake(connection.get()) == 1, "TLS handshake failed");
        requireOpenSsl(SSL_get_verify_result(ssl) == X509_V_OK, "TLS certificate verification failed");
    }

    void configureTlsHost(SSL* ssl) {
        requireOpenSsl(SSL_set_tlsext_host_name(ssl, parsedUrl.host.c_str()) == 1, "TLS SNI setup failed");
        X509_VERIFY_PARAM* verifyParams = SSL_get0_param(ssl);
        requireOpenSsl(verifyParams != nullptr, "TLS hostname verifier setup failed");
        requireOpenSsl(X509_VERIFY_PARAM_set1_host(verifyParams, parsedUrl.host.c_str(), 0) == 1, "TLS hostname setup failed");
    }

    void retryOrThrow(const std::string& message) {
        if (BIO_should_retry(connection.get()) != 0) {
            return;
        }
        requireOpenSsl(false, message);
    }

    ParsedUrl parsedUrl;
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> sslContext;
    std::unique_ptr<BIO, decltype(&BIO_free_all)> connection;
};

std::string trimHeaderValue(std::string value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.erase(value.begin());
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '\r')) {
        value.pop_back();
    }
    return value;
}

std::string headerValue(const std::string& headers, const std::string& name) {
    std::istringstream stream(headers);
    std::string line;
    const std::string expected = lowercase(name);
    while (std::getline(stream, line)) {
        const std::size_t colon = line.find(':');
        if (colon == std::string::npos) {
            continue;
        }
        if (lowercase(line.substr(0, colon)) == expected) {
            return trimHeaderValue(line.substr(colon + 1));
        }
    }
    return "";
}

std::string decodeChunked(const std::string& body) {
    std::string output;
    std::size_t offset = 0;
    while (true) {
        const std::size_t lineEnd = body.find("\r\n", offset);
        if (lineEnd == std::string::npos) {
            throw Error("chunked response is invalid");
        }
        const std::string sizeText = body.substr(offset, lineEnd - offset);
        const std::size_t semicolon = sizeText.find(';');
        const std::size_t size = std::stoul(sizeText.substr(0, semicolon), nullptr, 16);
        offset = lineEnd + 2;
        if (size == 0) {
            return output;
        }
        if (offset + size + 2 > body.size()) {
            throw Error("chunked response body is incomplete");
        }
        output.append(body.data() + offset, size);
        offset += size + 2;
    }
}

std::string httpBody(const std::string& rawResponse) {
    const std::size_t headerEnd = rawResponse.find("\r\n\r\n");
    if (headerEnd == std::string::npos) {
        throw Error("HTTP response headers are invalid");
    }

    const std::string headers = rawResponse.substr(0, headerEnd);
    std::string body = rawResponse.substr(headerEnd + 4);
    std::istringstream statusStream(headers);
    std::string httpVersion;
    int status = 0;
    statusStream >> httpVersion >> status;
    if (status < 200 || status >= 300) {
        try {
            const Json response = Json::parse(body);
            throw apiErrorFromJson(response, status);
        } catch (const Json::parse_error&) {
            throw Error("HTTP status " + std::to_string(status) + ": " + body, "HTTP_ERROR", status);
        }
    }

    if (lowercase(headerValue(headers, "Transfer-Encoding")).find("chunked") != std::string::npos) {
        body = decodeChunked(body);
    }

    const std::string lengthText = headerValue(headers, "Content-Length");
    if (!lengthText.empty()) {
        const std::size_t length = static_cast<std::size_t>(std::stoul(lengthText));
        if (body.size() >= length) {
            body.resize(length);
        }
    }
    return body;
}

std::string httpPost(const Config& config, const std::string& route, const std::string& body, const std::string& timestamp, const std::string& nonce, bool plainClient = false) {
    ParsedUrl url = parseUrl(routeUrl(config.apiUrl, route));
    HttpConnection connection(url);
    connection.writeAll(httpRequestText(url, config, route, body, timestamp, nonce, plainClient));
    return httpBody(connection.readAll());
}

} // namespace

Client::Client(Config config) : configValue(std::move(config)) {}

Json Client::login(const std::string& cardKey, const std::string& deviceId, const std::string& deviceName) {
    const std::string preferredInstallId = trimCopy(deviceId);
    bool useEphemeralTicket = configValue.forceEphemeralTicket;
    if (!useEphemeralTicket) {
        try {
            ensureIdentity(preferredInstallId);
        } catch (const Error&) {
            if (!configValue.allowEphemeralTicket) {
                throw;
            }
            useEphemeralTicket = true;
        }
    }
    const std::string normalizedInstallId = useEphemeralTicket
        ? (preferredInstallId.empty() ? generateDeviceId(configValue.appCode) : preferredInstallId)
        : identity.installId;
    const std::string normalizedName = resolvedDeviceName(deviceName);
    Json payload = loginPayload(cardKey, normalizedInstallId, normalizedName);
    const std::string normalizedCard = payload.at("card_key").get<std::string>();
    Json response = performLoginWithRetry(normalizedCard, normalizedInstallId, normalizedName, useEphemeralTicket);
    captureLoginContext(normalizedCard, normalizedInstallId, normalizedName);
    captureSession(response);
    return response;
}

Json Client::unbind(const std::string& cardKey, const std::string& deviceId) {
    ensureIdentity(trimCopy(deviceId));
    const std::string installId = identity.installId;
    const std::string card = trimCopy(cardKey);
    if (card.empty()) {
        throw Error("card key is required");
    }
    const long timestamp = std::time(nullptr);
    Json response = post("/unbind", Json{
        {"card_key", card},
        {"install_id", installId},
        {"timestamp", timestamp},
        {"signature", identity.sign(unbindCanonical(installId, timestamp, cardHash(configValue.appCode, card)))}
    });
    if (installId == sessionInstallId) {
        clearSession();
    }
    return response;
}

Json Client::notice() {
    return cachedNotice(configValue, [this]() {
        return plainPost("/notice", Json::object());
    });
}

Json Client::config() {
    return sessionPost("/config", Json::object());
}

Json Client::heartbeat() {
    return sessionPost("/heartbeat", Json::object());
}

Json Client::variable(const std::string& name) {
    const std::string variableName = trimCopy(name);
    if (variableName.empty()) {
        throw Error("variable name is required");
    }
    return sessionPost("/variable", Json{{"name", variableName}});
}

Json Client::reportSecurityEvent(const SecurityReportRequest& request) {
    ensureSession("/security/report");
    Json evidence = request.evidence.is_null() ? Json::object() : request.evidence;
    Json attestation = request.attestation.is_null() ? Json::object() : request.attestation;
    if (!evidence.is_object() || !attestation.is_object()) {
        throw Error("security report evidence and attestation must be objects", "SECURITY_REPORT_INVALID");
    }
    if (evidence.empty()) {
        throw Error("security report evidence is required", "SECURITY_REPORT_INVALID");
    }
    requireAllowedObjectKeys(evidence, kSecurityEvidenceFields, "evidence");
    requireAllowedObjectKeys(attestation, kSecurityAttestationFields, "attestation");
    Json payload = {
        {"event_id", securityEventId(request.eventId)},
        {"event_type", requiredSecurityText(request.eventType, "event_type")},
        {"risk_level", trimCopy(request.riskLevel)},
        {"confidence", request.confidence},
        {"requested_action", securityRequestedAction(request.requestedAction)},
        {"action_reason", trimCopy(request.actionReason)},
        {"title", requiredSecurityText(request.title, "title")},
        {"message", requiredSecurityText(request.message, "message")},
        {"evidence", evidence},
        {"attestation", attestation},
        {"occurred_at", request.occurredAt > 0 ? request.occurredAt : static_cast<long>(std::time(nullptr))},
        {"sdk_version", requiredSecurityText(request.sdkVersion, "sdk_version")},
        {"detector_version", requiredSecurityText(request.detectorVersion, "detector_version")},
        {"platform", trimCopy(request.platform).empty() ? sdkPlatformName() : trimCopy(request.platform)}
    };
    Json response = sendSessionRequest("/security/report", payload);
    if (response.value("session_revoked", false) || response.value("device_disabled", false) || response.value("card_disabled", false)) {
        clearSession();
        return response;
    }
    applySessionResponse("/security/report", response);
    return response;
}

Json Client::logout() {
    Json response = sessionPost("/logout", Json::object());
    clearSession();
    return response;
}

Json Client::renewSession() {
    if (!canRenewSession()) {
        throw Error("login context is not initialized");
    }
    const bool useEphemeralTicket = sessionProofMode == kProofModeEphemeralTicket || configValue.forceEphemeralTicket;
    if (!useEphemeralTicket) {
        ensureIdentity(loginInstallId);
    }
    Json response = performLoginWithRetry(loginCardKey, loginInstallId, loginDeviceName, useEphemeralTicket);
    captureSession(response);
    return response;
}

bool Client::hasSession() const {
    return !sessionToken.empty() && !sessionInstallId.empty();
}

std::string Client::token() const {
    return sessionToken;
}

std::string Client::sessionTicket() const {
    return sessionTicketValue;
}

void Client::setSession(std::string token, std::string deviceId, std::string ticket) {
    const std::string preferredInstallId = trimCopy(deviceId);
    const std::string normalizedTicket = trimCopy(ticket);
    if (normalizedTicket.empty()) {
        ensureIdentity(preferredInstallId);
        sessionInstallId = identity.installId;
    } else {
        sessionInstallId = preferredInstallId.empty() ? generateDeviceId(configValue.appCode) : preferredInstallId;
    }
    sessionToken = trimCopy(std::move(token));
    sessionTicketValue = normalizedTicket;
    sessionProofMode = sessionTicketValue.empty() ? kProofModeLocalKey : kProofModeEphemeralTicket;
    sessionCounter = 0;
}

void Client::setLoginContext(std::string cardKey, std::string deviceId, std::string deviceName) {
    const std::string preferredInstallId = trimCopy(deviceId);
    std::string installId;
    if (configValue.forceEphemeralTicket) {
        installId = preferredInstallId.empty() ? generateDeviceId(configValue.appCode) : preferredInstallId;
    } else {
        ensureIdentity(preferredInstallId);
        installId = identity.installId;
    }
    Json payload = loginPayload(cardKey, installId, deviceName);
    captureLoginContext(
        payload.at("card_key").get<std::string>(),
        payload.at("install_id").get<std::string>(),
        payload.at("device_name").get<std::string>()
    );
}

void Client::clearSession() {
    sessionToken.clear();
    sessionTicketValue.clear();
    sessionProofMode.clear();
    sessionInstallId.clear();
    sessionCounter = 0;
    loginCardKey.clear();
    loginInstallId.clear();
    loginDeviceName.clear();
}

Json Client::post(const std::string& route, const Json& payload) const {
    Algorithm algorithm = algorithmConfig(configValue.clientCryptoAlgorithm);
    Bytes sessionKey = randomBytes(static_cast<std::size_t>(algorithm.keyBytes));
    std::string timestamp = std::to_string(std::time(nullptr));
    std::string nonce = base64UrlEncode(randomBytes(18));
    Envelope encrypted = aesGcmEncrypt(payload.dump(), sessionKey, requestAad(route, timestamp, nonce, configValue.clientCryptoAlgorithm));
    Bytes wrappedKey = rsaEncrypt(configValue.clientPublicKey, sessionKey, algorithm);

    Json envelope = {
        {"alg", configValue.clientCryptoAlgorithm},
        {"key", base64UrlEncode(wrappedKey)},
        {"iv", encrypted.iv},
        {"ciphertext", encrypted.ciphertext},
        {"tag", encrypted.tag}
    };
    std::string body = envelope.dump();
    Json response = Json::parse(httpPost(configValue, route, body, timestamp, nonce));
    if (response.value("code", 500) != configValue.successCode) {
        throw apiErrorFromJson(response);
    }
    std::string plaintext = aesGcmDecrypt(response.at("data"), sessionKey, responseAad(route, timestamp, nonce, configValue.clientCryptoAlgorithm));
    return Json::parse(plaintext);
}

Json Client::plainPost(const std::string& route, const Json& payload) const {
    std::string timestamp = std::to_string(std::time(nullptr));
    std::string nonce = base64UrlEncode(randomBytes(18));
    Json response = Json::parse(httpPost(configValue, route, payload.dump(), timestamp, nonce, true));
    if (response.value("code", 500) != configValue.successCode) {
        throw apiErrorFromJson(response);
    }
    Json data = response.at("data");
    if (!data.is_object()) {
        throw Error("response data is not an object", "INVALID_RESPONSE");
    }
    return data;
}

Json Client::sessionPost(const std::string& route, Json payload) {
    ensureSession(route);
    try {
        Json response = sendSessionRequest(route, payload);
        applySessionResponse(route, response);
        return response;
    } catch (const Error& error) {
        if (!shouldRenewSession(route, error)) {
            throw;
        }
        renewSession();
        Json response = sendSessionRequest(route, payload);
        applySessionResponse(route, response);
        return response;
    }
}

Json Client::performLogin(const std::string& cardKey, const std::string& deviceId, const std::string& deviceName, bool useEphemeralTicket) {
    const std::string proofMode = useEphemeralTicket ? kProofModeEphemeralTicket : kProofModeLocalKey;
    Json challenge = Json::object();
    if (!useEphemeralTicket) {
        Json challengePayload = Json{
            {"install_id", deviceId},
            {"device_name", deviceName},
            {"device_key_mode", proofMode},
            {"device_public_key", identity.publicKeyPem}
        };
        challenge = post("/login/challenge", challengePayload);
    }
    const long timestamp = std::time(nullptr);
    const std::string profile = machineProfileHash(configValue);
    Json payload = Json{
        {"card_key", cardKey},
        {"challenge_id", useEphemeralTicket ? ephemeralChallengeId() : challenge.at("challenge_id").get<std::string>()},
        {"install_id", deviceId},
        {"device_name", deviceName},
        {"device_key_mode", proofMode},
        {"machine_profile_hash", profile},
        {"client_version", configValue.appVersion},
        {"timestamp", timestamp}
    };
    if (!useEphemeralTicket) {
        payload["signature"] = identity.sign(loginCanonical(
            challenge.at("challenge_id").get<std::string>(),
            deviceId,
            timestamp,
            profile,
            cardHash(configValue.appCode, cardKey),
            challenge.at("server_nonce").get<std::string>()
        ));
    }
    return useEphemeralTicket ? plainPost("/login", payload) : post("/login", payload);
}

Json Client::performLoginWithRetry(const std::string& cardKey, const std::string& deviceId, const std::string& deviceName, bool useEphemeralTicket) {
    const int retries = std::max(0, configValue.loginNetworkRetries);
    const double delaySeconds = std::max(0.0, configValue.loginRetryDelaySeconds);
    for (int attempt = 0; ; ++attempt) {
        try {
            return performLogin(cardKey, deviceId, deviceName, useEphemeralTicket);
        } catch (const Error& error) {
            if (!useEphemeralTicket || !retryableLoginError(error) || attempt >= retries) {
                throw;
            }
            std::this_thread::sleep_for(std::chrono::duration<double>(delaySeconds * static_cast<double>(attempt + 1)));
        }
    }
}

Json Client::sendSessionRequest(const std::string& route, Json payload) {
    const bool useEphemeralTicket = sessionProofMode == kProofModeEphemeralTicket;
    if (!useEphemeralTicket) {
        ensureIdentity(sessionInstallId);
    }
    const unsigned long long counter = sessionCounter + 1;
    const long timestamp = std::time(nullptr);
    const std::string requestNonce = base64UrlEncode(randomBytes(18));
    payload["token"] = sessionToken;
    payload["install_id"] = sessionInstallId;
    payload["client_version"] = configValue.appVersion;
    payload["counter"] = counter;
    payload["request_nonce"] = requestNonce;
    payload["timestamp"] = timestamp;
    if (useEphemeralTicket) {
        if (sessionTicketValue.empty()) {
            throw Error("client session ticket is not initialized", "SESSION_TICKET_MISSING");
        }
        payload["session_ticket"] = sessionTicketValue;
    } else {
        payload["signature"] = identity.sign(sessionCanonical(route, sessionToken, sessionInstallId, counter, requestNonce, timestamp, sessionExtra(route, payload)));
    }
    Json response = useEphemeralTicket ? plainPost(route, payload) : post(route, payload);
    sessionCounter = counter;
    return response;
}

void Client::ensureSession(const std::string& route) {
    if (hasSession()) {
        return;
    }
    if (route != "/logout" && canRenewSession()) {
        renewSession();
        return;
    }
    throw Error("client session is not initialized");
}

void Client::captureSession(const Json& response) {
    const std::string token = trimCopy(response.value("token", ""));
    if (token.empty()) {
        throw Error("login response missing token", "SESSION_TOKEN_MISSING");
    }
    sessionToken = token;
    sessionProofMode = normalizedProofMode(response);
    sessionTicketValue = trimCopy(response.value("session_ticket", ""));
    if (sessionProofMode == kProofModeEphemeralTicket && sessionTicketValue.empty()) {
        throw Error("login response missing session ticket", "SESSION_TICKET_MISSING");
    }
    sessionInstallId = loginInstallId;
    sessionCounter = 0;
}

void Client::captureLoginContext(const std::string& cardKey, const std::string& deviceId, const std::string& deviceName) {
    loginCardKey = cardKey;
    loginInstallId = deviceId;
    loginDeviceName = deviceName;
}

void Client::applySessionResponse(const std::string& route, const Json& response) {
    if (route == "/logout") {
        return;
    }
    auto token = response.find("token");
    if (token == response.end() || !token->is_string()) {
        throw Error(route + " response missing refreshed token", "SESSION_TOKEN_MISSING");
    }
    sessionToken = trimCopy(token->get<std::string>());
    if (sessionToken.empty()) {
        throw Error(route + " response missing refreshed token", "SESSION_TOKEN_MISSING");
    }
    sessionProofMode = normalizedProofMode(response);
    if (sessionProofMode == kProofModeEphemeralTicket) {
        auto ticket = response.find("session_ticket");
        if (ticket == response.end() || !ticket->is_string()) {
            throw Error(route + " response missing refreshed session ticket", "SESSION_TICKET_MISSING");
        }
        sessionTicketValue = trimCopy(ticket->get<std::string>());
        if (sessionTicketValue.empty()) {
            throw Error(route + " response missing refreshed session ticket", "SESSION_TICKET_MISSING");
        }
    } else {
        sessionTicketValue.clear();
    }
}

bool Client::canRenewSession() const {
    return !loginCardKey.empty() && !loginInstallId.empty();
}

bool Client::shouldRenewSession(const std::string& route, const Error& error) const {
    if (route == "/logout" || !canRenewSession()) {
        return false;
    }
    const std::string code = error.code();
    if (
        code == "SESSION_INVALID"
        || code == "SESSION_TICKET_MISSING"
        || code == "SESSION_TICKET_INVALID"
        || code == "SESSION_TICKET_EXPIRED"
    ) {
        return true;
    }
    if (retryableGatewayError(error)) {
        return true;
    }
    const std::string message = error.what();
    return message.find("SESSION_INVALID") != std::string::npos
        || message.find("SESSION_TICKET_MISSING") != std::string::npos
        || message.find("SESSION_TICKET_INVALID") != std::string::npos
        || message.find("SESSION_TICKET_EXPIRED") != std::string::npos;
}

void Client::ensureIdentity(const std::string& preferredInstallId) {
    const std::string installId = trimCopy(preferredInstallId);
    if (identity.ready() && (installId.empty() || identity.installId == installId)) {
        return;
    }
    identity = loadOrCreateDeviceIdentity(configValue.appCode, installId);
}

} // namespace LicenseAuth
