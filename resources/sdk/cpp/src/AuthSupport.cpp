#include "AuthSupport.hpp"
#include "AuthError.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cctype>
#include <limits>

namespace LicenseAuth::SdkInternal {
namespace {

std::string openSslError() {
    const unsigned long code = ERR_get_error();
    if (code == 0) {
        return "";
    }
    char buffer[256] = {};
    ERR_error_string_n(code, buffer, sizeof(buffer));
    return std::string(": ") + buffer;
}

std::string hex(const Bytes& bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string output;
    output.reserve(bytes.size() * 2);
    for (unsigned char value : bytes) {
        output.push_back(digits[value >> 4]);
        output.push_back(digits[value & 0x0f]);
    }
    return output;
}

int base64Value(char item) {
    if (item >= 'A' && item <= 'Z') {
        return item - 'A';
    }
    if (item >= 'a' && item <= 'z') {
        return item - 'a' + 26;
    }
    if (item >= '0' && item <= '9') {
        return item - '0' + 52;
    }
    if (item == '-') {
        return 62;
    }
    if (item == '_') {
        return 63;
    }
    return -1;
}

} // namespace

void requireOpenSsl(bool success, const std::string& message) {
    if (!success) {
        throw Error(message + openSslError());
    }
}

Bytes randomBytes(std::size_t size) {
    if (size > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw Error("random bytes request is too large");
    }
    Bytes output(size);
    if (!output.empty()) {
        requireOpenSsl(RAND_bytes(output.data(), static_cast<int>(output.size())) == 1, "random bytes generation failed");
    }
    return output;
}

std::string base64UrlEncode(const Bytes& bytes) {
    static constexpr char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string output;
    output.reserve((bytes.size() * 4 + 2) / 3);
    int value = 0;
    int bits = -6;
    for (unsigned char item : bytes) {
        value = (value << 8) + item;
        bits += 8;
        while (bits >= 0) {
            output.push_back(table[(value >> bits) & 0x3f]);
            bits -= 6;
        }
    }
    if (bits > -6) {
        output.push_back(table[((value << 8) >> (bits + 8)) & 0x3f]);
    }
    return output;
}

Bytes base64UrlDecode(const std::string& value) {
    Bytes output;
    int buffer = 0;
    int bits = -8;
    for (char item : value) {
        if (item == '=') {
            break;
        }
        const int decoded = base64Value(item);
        if (decoded < 0) {
            throw Error("base64url decode failed");
        }
        buffer = (buffer << 6) | decoded;
        bits += 6;
        if (bits >= 0) {
            output.push_back(static_cast<unsigned char>((buffer >> bits) & 0xff));
            bits -= 8;
        }
    }
    return output;
}

std::string bytesToString(const Bytes& bytes) {
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

std::string sha256Hex(const std::string& value) {
    Bytes digest(32);
    unsigned int digestLength = 0;
    requireOpenSsl(EVP_Digest(
        value.data(),
        value.size(),
        digest.data(),
        &digestLength,
        EVP_sha256(),
        nullptr
    ) == 1, "SHA-256 digest failed");
    if (digestLength != digest.size()) {
        throw Error("SHA-256 digest length is invalid");
    }
    return hex(digest);
}

std::string trimCopy(std::string value) {
    const auto left = std::find_if_not(value.begin(), value.end(), [](unsigned char character) {
        return std::isspace(character) != 0;
    });
    const auto right = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char character) {
        return std::isspace(character) != 0;
    }).base();
    if (left >= right) {
        return "";
    }
    return std::string(left, right);
}

} // namespace LicenseAuth::SdkInternal
