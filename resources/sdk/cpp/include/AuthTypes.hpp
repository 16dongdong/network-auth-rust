#pragma once

#include <nlohmann/json.hpp>

#include <string>

namespace LicenseAuth {

using Json = nlohmann::json;

struct SecurityReportRequest {
    std::string eventId;
    std::string eventType;
    std::string riskLevel = "high";
    int confidence = 100;
    std::string requestedAction = "record_only";
    std::string actionReason;
    std::string title;
    std::string message;
    Json evidence = Json::object();
    Json attestation = Json::object();
    long occurredAt = 0;
    std::string sdkVersion;
    std::string detectorVersion;
    std::string platform;
};

} // namespace LicenseAuth
