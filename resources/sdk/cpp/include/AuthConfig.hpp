#pragma once

#include <map>
#include <string>

namespace LicenseAuth {

struct Config {
#ifdef LICENSE_AUTH_LOCAL_TEMPLATE_BUILD
    std::string apiUrl = "http://127.0.0.1:8000/api/v1/index.php";
    std::string appCode = "LocalTemplateApp";
    std::string apiToken = "";
    std::string appVersion = "";
    int successCode = 0;
    std::map<std::string, std::string> apiCallIds = {};
    std::string clientAuthMode = "local_key_v1";
    std::string clientCryptoAlgorithm = "rsa_oaep_aes_256_gcm";
    std::string clientPublicKey = "";
#else
    std::string apiUrl = {{SdkApiUrlCpp}};
    std::string appCode = {{SdkAppCodeCpp}};
    std::string apiToken = {{SdkApiTokenCpp}};
    std::string appVersion = {{SdkAppVersionCpp}};
    int successCode = {{SdkApiSuccessCodeCpp}};
    std::map<std::string, std::string> apiCallIds = {{SdkApiCallIdsCpp}};
    std::string clientAuthMode = {{SdkClientAuthModeCpp}};
    std::string clientCryptoAlgorithm = {{SdkCryptoAlgorithmCpp}};
    std::string clientPublicKey = {{SdkClientPublicKeyCpp}};
#endif
    bool allowEphemeralTicket = true;
    bool forceEphemeralTicket = false;
    int timeoutSeconds = 30;
    int noticeCacheSeconds = 300;
    int loginNetworkRetries = 2;
    double loginRetryDelaySeconds = 1.0;
};

} // namespace LicenseAuth
