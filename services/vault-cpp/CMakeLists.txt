cmake_minimum_required(VERSION 3.20)
project(vault-cpp CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Find liboqs if available via vcpkg
find_package(liboqs CONFIG QUIET)

include_directories(include ${OPENSSL_INCLUDE_DIR})

set(SOURCES
    src/evp_cipher_engine.cpp
    src/rsa_keygen.cpp
    src/liboqs_bridge.cpp
    src/main.cpp
    src/hsm_socket.cpp
    src/vault_storage.cpp
    src/key_rotation.cpp
    src/access_logger.cpp
)

add_executable(vault-server ${SOURCES})

target_link_libraries(vault-server PRIVATE OpenSSL::Crypto OpenSSL::SSL)

if(TARGET oqs)
    target_link_libraries(vault-server PRIVATE oqs)
endif()
