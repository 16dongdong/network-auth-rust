#include "AuthDeviceIdentity.hpp"
#include "AuthError.hpp"
#include "AuthSupport.hpp"
#include "AuthTypes.hpp"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <set>
#include <sstream>
#include <system_error>
#include <vector>

namespace LicenseAuth {
namespace {

using SdkInternal::Bytes;
using SdkInternal::base64UrlEncode;
using SdkInternal::randomBytes;
using SdkInternal::requireOpenSsl;
using SdkInternal::sha256Hex;
using SdkInternal::trimCopy;

struct FingerprintPart {
    std::string name;
    std::string value;
};

std::string environmentValue(const char* name) {
    const char* value = std::getenv(name);
    return value == nullptr ? "" : trimCopy(value);
}

std::filesystem::path identityDirectory() {
#ifdef _WIN32
    std::string base = environmentValue("APPDATA");
    if (base.empty()) {
        base = environmentValue("USERPROFILE");
    }
#else
    std::string base = environmentValue("HOME");
#endif
    if (base.empty()) {
        throw Error("user home directory is unavailable");
    }
    return std::filesystem::path(base) / ".license-auth";
}

std::string safeIdentityName(const std::string& appCode) {
    std::string output;
    for (unsigned char item : appCode) {
        const bool keep = std::isalnum(item) != 0 || item == '-' || item == '_';
        output.push_back(keep ? static_cast<char>(item) : '-');
    }
    return output.empty() ? "app" : output;
}

std::filesystem::path identityPath(const std::string& appCode) {
    return identityDirectory() / (safeIdentityName(appCode) + ".json");
}

bool usefulFingerprintValue(const std::string& value) {
    std::string normalized = trimCopy(value);
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char item) {
        return static_cast<char>(std::tolower(item));
    });
    return !normalized.empty()
        && normalized != "unknown"
        && normalized != "none"
        && normalized != "default string"
        && normalized != "to be filled by o.e.m."
        && normalized.find("00000000-0000-0000-0000-000000000000") == std::string::npos;
}

void addFingerprintPart(std::vector<FingerprintPart>& parts, std::string name, std::string value) {
    value = trimCopy(std::move(value));
    if (usefulFingerprintValue(value)) {
        parts.push_back({std::move(name), std::move(value)});
    }
}

std::string readLimitedFile(const std::filesystem::path& path, std::size_t maxBytes = 8192) {
    std::error_code statusError;
    if (!std::filesystem::is_regular_file(path, statusError)) {
        return "";
    }
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        return "";
    }
    std::string content(maxBytes, '\0');
    input.read(content.data(), static_cast<std::streamsize>(content.size()));
    content.resize(static_cast<std::size_t>(input.gcount()));
    return trimCopy(content);
}

void addFileFingerprint(std::vector<FingerprintPart>& parts, const std::string& name, const std::filesystem::path& path) {
    addFingerprintPart(parts, name, readLimitedFile(path));
}

std::string propertyValue(const std::string& line) {
    const std::size_t equal = line.find('=');
    if (equal == std::string::npos) {
        return "";
    }
    return trimCopy(line.substr(equal + 1));
}

void addAndroidProperties(std::vector<FingerprintPart>& parts, const std::filesystem::path& path) {
    static const std::set<std::string> keys = {
        "ro.boot.hardware",
        "ro.boot.serialno",
        "ro.build.fingerprint",
        "ro.product.board",
        "ro.product.brand",
        "ro.product.device",
        "ro.product.manufacturer",
        "ro.product.model",
        "ro.serialno"
    };
    std::istringstream stream(readLimitedFile(path, 65536));
    for (std::string line; std::getline(stream, line);) {
        const std::size_t equal = line.find('=');
        const std::string key = equal == std::string::npos ? "" : trimCopy(line.substr(0, equal));
        if (keys.find(key) != keys.end()) {
            addFingerprintPart(parts, "android." + key, propertyValue(line));
        }
    }
}

void addCpuInfo(std::vector<FingerprintPart>& parts) {
    static const std::set<std::string> keys = {"Hardware", "Revision", "Serial", "model name"};
    std::istringstream stream(readLimitedFile("/proc/cpuinfo", 65536));
    for (std::string line; std::getline(stream, line);) {
        const std::size_t colon = line.find(':');
        const std::string key = colon == std::string::npos ? "" : trimCopy(line.substr(0, colon));
        if (keys.find(key) != keys.end()) {
            addFingerprintPart(parts, "cpu." + key, line.substr(colon + 1));
        }
    }
}

void addDirectoryFiles(std::vector<FingerprintPart>& parts, const std::filesystem::path& directory, const std::set<std::string>& names, const std::string& prefix) {
    for (const std::string& name : names) {
        addFileFingerprint(parts, prefix + "." + name, directory / name);
    }
}

std::vector<std::filesystem::path> directoryChildren(const std::filesystem::path& directory) {
    std::error_code error;
    std::vector<std::filesystem::path> children;
    if (!std::filesystem::is_directory(directory, error)) {
        return children;
    }
    std::filesystem::directory_iterator iterator(directory, std::filesystem::directory_options::skip_permission_denied, error);
    for (const std::filesystem::directory_iterator end; !error && iterator != end; iterator.increment(error)) {
        children.push_back(iterator->path());
    }
    std::sort(children.begin(), children.end());
    return children;
}

void addNetworkFingerprints(std::vector<FingerprintPart>& parts) {
    for (const auto& path : directoryChildren("/sys/class/net")) {
        const std::string name = path.filename().string();
        const std::string address = trimCopy(readLimitedFile(path / "address"));
        if (name != "lo" && address != "00:00:00:00:00:00") {
            addFingerprintPart(parts, "net." + name, address);
        }
    }
}

void addBlockFingerprints(std::vector<FingerprintPart>& parts) {
    for (const auto& path : directoryChildren("/sys/block")) {
        const std::string name = path.filename().string();
        if (name.rfind("loop", 0) == 0 || name.rfind("ram", 0) == 0) {
            continue;
        }
        addFileFingerprint(parts, "block." + name + ".serial", path / "device" / "serial");
        addFileFingerprint(parts, "block." + name + ".wwid", path / "wwid");
    }
}

void addRuntimeFingerprints(std::vector<FingerprintPart>& parts) {
    addFingerprintPart(parts, "env.computername", environmentValue("COMPUTERNAME"));
    addFingerprintPart(parts, "env.hostname", environmentValue("HOSTNAME"));
}

int checkedIntSize(std::size_t size, const std::string& message) {
    if (size > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw Error(message);
    }
    return static_cast<int>(size);
}

std::vector<FingerprintPart> collectFingerprintParts() {
    std::vector<FingerprintPart> parts;
    addDirectoryFiles(parts, "/sys/class/dmi/id", {"board_serial", "chassis_serial", "product_serial", "product_uuid", "product_name", "sys_vendor"}, "dmi");
    addDirectoryFiles(parts, "/sys/devices/soc0", {"serial_number", "soc_id", "machine", "family"}, "soc");
    addFileFingerprint(parts, "machine.etc", "/etc/machine-id");
    addFileFingerprint(parts, "machine.dbus", "/var/lib/dbus/machine-id");
    addFileFingerprint(parts, "android.usb.serial", "/sys/class/android_usb/android0/iSerial");
    addAndroidProperties(parts, "/system/build.prop");
    addAndroidProperties(parts, "/vendor/build.prop");
    addAndroidProperties(parts, "/odm/build.prop");
    addCpuInfo(parts);
    addNetworkFingerprints(parts);
    addBlockFingerprints(parts);
    addRuntimeFingerprints(parts);
    return parts;
}

std::string canonicalFingerprintPayload(std::vector<FingerprintPart> parts) {
    std::vector<std::string> rows;
    rows.reserve(parts.size());
    for (const FingerprintPart& part : parts) {
        rows.push_back(part.name + "=" + part.value);
    }
    std::sort(rows.begin(), rows.end());
    rows.erase(std::unique(rows.begin(), rows.end()), rows.end());
    std::ostringstream output;
    for (const std::string& row : rows) {
        output << row << '\n';
    }
    return output.str();
}

DeviceIdentity loadIdentityFromDisk(const std::string& appCode) {
    const std::filesystem::path path = identityPath(appCode);
    if (!std::filesystem::exists(path)) {
        return {};
    }
    std::ifstream input(path);
    if (!input.is_open()) {
        throw Error("device credential file open failed");
    }
    try {
        const Json data = Json::parse(input);
        return {
            trimCopy(data.value("install_id", "")),
            trimCopy(data.value("device_private_key", "")),
            trimCopy(data.value("device_public_key", ""))
        };
    } catch (const Json::parse_error&) {
        throw Error("device credential file is invalid");
    }
}

std::string bioString(BIO* output) {
    BUF_MEM* memory = nullptr;
    BIO_get_mem_ptr(output, &memory);
    if (memory == nullptr || memory->data == nullptr || memory->length == 0) {
        throw Error("device key PEM export failed");
    }
    return std::string(memory->data, memory->length);
}

std::string exportPrivateKeyPem(EVP_PKEY* key) {
    std::unique_ptr<BIO, decltype(&BIO_free)> output(BIO_new(BIO_s_mem()), BIO_free);
    requireOpenSsl(output != nullptr, "device private key buffer setup failed");
    requireOpenSsl(PEM_write_bio_PrivateKey(output.get(), key, nullptr, nullptr, 0, nullptr, nullptr) == 1, "device private key export failed");
    return bioString(output.get());
}

std::string exportPublicKeyPem(EVP_PKEY* key) {
    std::unique_ptr<BIO, decltype(&BIO_free)> output(BIO_new(BIO_s_mem()), BIO_free);
    requireOpenSsl(output != nullptr, "device public key buffer setup failed");
    requireOpenSsl(PEM_write_bio_PUBKEY(output.get(), key) == 1, "device public key export failed");
    return bioString(output.get());
}

DeviceIdentity generateP256Identity(const std::string& installId) {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);
    requireOpenSsl(context != nullptr, "device key context setup failed");
    requireOpenSsl(EVP_PKEY_keygen_init(context.get()) == 1, "device key setup failed");
    requireOpenSsl(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context.get(), NID_X9_62_prime256v1) == 1, "device curve setup failed");
    EVP_PKEY* rawKey = nullptr;
    requireOpenSsl(EVP_PKEY_keygen(context.get(), &rawKey) == 1, "device key generation failed");
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(rawKey, EVP_PKEY_free);
    return {installId, exportPrivateKeyPem(key.get()), exportPublicKeyPem(key.get())};
}

std::string signP256Message(const std::string& privateKeyPem, const std::string& message) {
    if (trimCopy(privateKeyPem).empty()) {
        throw Error("device credential is not initialized");
    }

    std::unique_ptr<BIO, decltype(&BIO_free)> input(BIO_new_mem_buf(privateKeyPem.data(), checkedIntSize(privateKeyPem.size(), "device private key PEM is too large")), BIO_free);
    requireOpenSsl(input != nullptr, "device private key buffer setup failed");
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(PEM_read_bio_PrivateKey(input.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    requireOpenSsl(key != nullptr, "device private key parse failed");
    if (EVP_PKEY_is_a(key.get(), "EC") != 1) {
        throw Error("device private key is not ECDSA");
    }
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    requireOpenSsl(context != nullptr, "device signature context setup failed");
    requireOpenSsl(EVP_DigestSignInit(context.get(), nullptr, EVP_sha256(), nullptr, key.get()) == 1, "device signature setup failed");
    std::size_t signatureLength = 0;
    requireOpenSsl(EVP_DigestSign(context.get(), nullptr, &signatureLength, reinterpret_cast<const unsigned char*>(message.data()), message.size()) == 1, "device ECDSA signature sizing failed");
    Bytes signature(signatureLength);
    requireOpenSsl(EVP_DigestSign(context.get(), signature.data(), &signatureLength, reinterpret_cast<const unsigned char*>(message.data()), message.size()) == 1, "device ECDSA signature failed");
    signature.resize(signatureLength);
    return base64UrlEncode(signature);
}

} // namespace

bool DeviceIdentity::ready() const {
    return !trimCopy(installId).empty() && !trimCopy(privateKeyPem).empty() && !trimCopy(publicKeyPem).empty();
}

std::string DeviceIdentity::sign(const std::string& message) const {
    return signP256Message(privateKeyPem, message);
}

std::string generateInstallId() {
    return base64UrlEncode(randomBytes(24));
}

std::string generateDeviceId(const std::string& appCode) {
    const std::string payload = canonicalFingerprintPayload(collectFingerprintParts());
    if (payload.empty()) {
        return generateInstallId();
    }
    return "fp-" + sha256Hex("LicenseAuthDeviceIdV2\n" + trimCopy(appCode) + "\n" + payload).substr(0, 48);
}

DeviceIdentity generateDeviceIdentity(const std::string& preferredInstallId) {
    const std::string installId = trimCopy(preferredInstallId).empty() ? generateInstallId() : trimCopy(preferredInstallId);
    return generateP256Identity(installId);
}

DeviceIdentity loadOrCreateDeviceIdentity(const std::string& appCode, const std::string& preferredInstallId) {
    const std::string installId = trimCopy(preferredInstallId);
    DeviceIdentity identity = loadIdentityFromDisk(appCode);
    if (!installId.empty() && identity.installId != installId) {
        identity = generateDeviceIdentity(installId);
        saveDeviceIdentity(appCode, identity);
        return identity;
    }
    if (identity.installId.empty()) {
        identity.installId = installId.empty() ? generateDeviceId(appCode) : installId;
    }
    if (!identity.ready()) {
        identity = generateDeviceIdentity(identity.installId);
        saveDeviceIdentity(appCode, identity);
    }
    return identity;
}

void saveDeviceIdentity(const std::string& appCode, const DeviceIdentity& identity) {
    if (!identity.ready()) {
        throw Error("device credential is not initialized");
    }
    const std::filesystem::path path = identityPath(appCode);
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::trunc);
    if (!output.is_open()) {
        throw Error("device credential file write failed");
    }
    output << Json{
        {"install_id", trimCopy(identity.installId)},
        {"device_private_key", trimCopy(identity.privateKeyPem)},
        {"device_public_key", trimCopy(identity.publicKeyPem)}
    }.dump(2);
    if (!output.good()) {
        throw Error("device credential file write failed");
    }
}

} // namespace LicenseAuth
