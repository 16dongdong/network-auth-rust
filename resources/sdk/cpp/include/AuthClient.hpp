#pragma once

#include "AuthConfig.hpp"
#include "AuthDeviceIdentity.hpp"
#include "AuthError.hpp"
#include "AuthTypes.hpp"

#include <string>

namespace LicenseAuth {

class Client final {
public:
    explicit Client(Config config = Config{});

    Json login(const std::string& cardKey, const std::string& deviceId = "", const std::string& deviceName = "");
    Json unbind(const std::string& cardKey, const std::string& deviceId = "");
    Json notice();
    Json config();
    Json heartbeat();
    Json variable(const std::string& name);
    Json reportSecurityEvent(const SecurityReportRequest& request);
    Json logout();
    Json renewSession();

    bool hasSession() const;
    std::string token() const;
    std::string sessionTicket() const;
    void setSession(std::string token, std::string deviceId = "", std::string ticket = "");
    void setLoginContext(std::string cardKey, std::string deviceId = "", std::string deviceName = "");
    void clearSession();

private:
    Json post(const std::string& route, const Json& payload) const;
    Json plainPost(const std::string& route, const Json& payload) const;
    Json sessionPost(const std::string& route, Json payload);
    Json performLogin(const std::string& cardKey, const std::string& deviceId, const std::string& deviceName, bool useEphemeralTicket);
    Json performLoginWithRetry(const std::string& cardKey, const std::string& deviceId, const std::string& deviceName, bool useEphemeralTicket);
    Json sendSessionRequest(const std::string& route, Json payload);
    void ensureSession(const std::string& route);
    void captureSession(const Json& response);
    void captureLoginContext(const std::string& cardKey, const std::string& installId, const std::string& deviceName);
    void applySessionResponse(const std::string& route, const Json& response);
    bool canRenewSession() const;
    bool shouldRenewSession(const std::string& route, const Error& error) const;
    void ensureIdentity(const std::string& preferredInstallId = "");

    Config configValue;
    std::string sessionToken;
    std::string sessionTicketValue;
    std::string sessionProofMode;
    std::string sessionInstallId;
    unsigned long long sessionCounter = 0;
    std::string loginCardKey;
    std::string loginInstallId;
    std::string loginDeviceName;
    DeviceIdentity identity;
};

} // namespace LicenseAuth
