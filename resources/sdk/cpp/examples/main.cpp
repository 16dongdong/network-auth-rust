#include "AuthClient.hpp"
#include <iostream>

int main() {
    try {
        LicenseAuth::Client client;
        auto notice = client.notice();
        std::cout << "notice: " << notice.dump() << std::endl;

        auto login = client.login("CARD-KEY");
        std::cout << "login: " << login.dump() << std::endl;

        auto heartbeat = client.heartbeat();
        std::cout << "heartbeat: " << heartbeat.dump() << std::endl;

        auto config = client.config();
        std::cout << "config: " << config.dump() << std::endl;

        LicenseAuth::SecurityReportRequest report;
        report.eventType = "debugger_detected";
        report.riskLevel = "critical";
        report.requestedAction = "record_only";
        report.title = "检测到调试器";
        report.message = "反调试模块检测到调试器";
        report.evidence = {{"detector", "example"}, {"matched_rule", "debugger-detected"}};
        report.sdkVersion = "cpp-1.0.0";
        report.detectorVersion = "example-1.0.0";
        auto securityReport = client.reportSecurityEvent(report);
        std::cout << "security report: " << securityReport.dump() << std::endl;
    } catch (const std::exception& error) {
        std::cerr << error.what() << std::endl;
        return 1;
    }
    return 0;
}
