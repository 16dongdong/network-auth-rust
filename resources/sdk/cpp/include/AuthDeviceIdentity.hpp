#pragma once

#include <string>

namespace LicenseAuth {

struct DeviceIdentity final {
    std::string installId;
    std::string privateKeyPem;
    std::string publicKeyPem;

    bool ready() const;
    std::string sign(const std::string& message) const;
};

std::string generateInstallId();
std::string generateDeviceId(const std::string& appCode);
DeviceIdentity generateDeviceIdentity(const std::string& preferredInstallId = "");
DeviceIdentity loadOrCreateDeviceIdentity(const std::string& appCode, const std::string& preferredInstallId = "");
void saveDeviceIdentity(const std::string& appCode, const DeviceIdentity& identity);

} // namespace LicenseAuth
