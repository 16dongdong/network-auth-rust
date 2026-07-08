#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace LicenseAuth::SdkInternal {

using Bytes = std::vector<unsigned char>;

void requireOpenSsl(bool success, const std::string& message);
Bytes randomBytes(std::size_t size);
std::string base64UrlEncode(const Bytes& bytes);
Bytes base64UrlDecode(const std::string& value);
std::string bytesToString(const Bytes& bytes);
std::string sha256Hex(const std::string& value);
std::string trimCopy(std::string value);

} // namespace LicenseAuth::SdkInternal
