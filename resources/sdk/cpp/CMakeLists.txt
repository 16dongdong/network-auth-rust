cmake_minimum_required(VERSION 3.16)
project(LicenseAuthSdk LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
if(OPENSSL_VERSION VERSION_LESS 3.0.0)
    message(FATAL_ERROR "LicenseAuthSdk requires OpenSSL 3.x or newer.")
endif()

add_library(LicenseAuthSdk STATIC
    src/AuthDeviceIdentity.cpp
    src/AuthSupport.cpp
    src/AuthClient.cpp
)

target_include_directories(LicenseAuthSdk PUBLIC include third_party)
target_link_libraries(LicenseAuthSdk PUBLIC OpenSSL::SSL OpenSSL::Crypto)
target_compile_definitions(LicenseAuthSdk PUBLIC LICENSE_AUTH_LOCAL_TEMPLATE_BUILD=1)

if(MSVC)
    target_compile_options(LicenseAuthSdk PRIVATE /W4 /permissive-)
else()
    target_compile_options(LicenseAuthSdk PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(LicenseAuthExample examples/main.cpp)
target_link_libraries(LicenseAuthExample PRIVATE LicenseAuthSdk)
