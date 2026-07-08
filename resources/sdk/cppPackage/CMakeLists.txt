cmake_minimum_required(VERSION 3.16)
project(LicenseAuth{{SdkPlatformCmakeSuffix}}Sdk LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(LICENSE_AUTH_TARGET_PLATFORM "{{SdkPlatformKey}}" CACHE STRING "LicenseAuth SDK target platform.")
set(LICENSE_AUTH_BUILD_EXAMPLE {{SdkBuildExampleDefault}} CACHE BOOL "Build LicenseAuth example executable.")

find_package(OpenSSL REQUIRED)
if(OPENSSL_VERSION VERSION_LESS 3.0.0)
    message(FATAL_ERROR "LicenseAuthSdk requires OpenSSL 3.x or newer.")
endif()
find_package(nlohmann_json CONFIG REQUIRED)

add_library(LicenseAuthSdk STATIC
    src/AuthDeviceIdentity.cpp
    src/AuthSupport.cpp
    src/AuthClient.cpp
)

target_include_directories(LicenseAuthSdk PUBLIC include)
target_link_libraries(LicenseAuthSdk PUBLIC OpenSSL::SSL OpenSSL::Crypto nlohmann_json::nlohmann_json)
target_compile_definitions(LicenseAuthSdk PRIVATE LICENSE_AUTH_TARGET_PLATFORM="{{SdkPlatformKey}}")

if(WIN32)
    target_compile_definitions(LicenseAuthSdk PRIVATE _WIN32_WINNT=0x0A00)
endif()

if(MSVC)
    target_compile_options(LicenseAuthSdk PRIVATE /W4 /permissive-)
else()
    target_compile_options(LicenseAuthSdk PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(LICENSE_AUTH_BUILD_EXAMPLE)
    add_executable(LicenseAuthExample examples/main.cpp)
    target_link_libraries(LicenseAuthExample PRIVATE LicenseAuthSdk)
endif()
