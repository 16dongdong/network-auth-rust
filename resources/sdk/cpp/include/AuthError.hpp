#pragma once

#include <stdexcept>
#include <string>
#include <utility>

namespace LicenseAuth {

class Error final : public std::runtime_error {
public:
    explicit Error(std::string message, std::string code = "", int httpStatus = 0)
        : std::runtime_error(message), errorCode(std::move(code)), httpStatusCode(httpStatus) {}

    const std::string& code() const noexcept {
        return errorCode;
    }

    int httpStatus() const noexcept {
        return httpStatusCode;
    }

private:
    std::string errorCode;
    int httpStatusCode;
};

} // namespace LicenseAuth
