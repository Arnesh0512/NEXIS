cmake_minimum_required(VERSION 3.20)
project(hsm-c C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Find liboqs if available via vcpkg
find_package(liboqs CONFIG QUIET)

include_directories(include ${OPENSSL_INCLUDE_DIR})

set(SOURCES
    src/pkcs11_driver.c
    src/entropy_pool.c
    src/pqc_driver.c
    src/memory_scrubber.c
    src/diagnostic_probe.c
    src/hsm_ipc.c
    src/session_table.c
    src/hsm_main.c
)

add_executable(hsm-daemon ${SOURCES})

target_link_libraries(hsm-daemon PRIVATE OpenSSL::Crypto)

if(TARGET oqs)
    target_link_libraries(hsm-daemon PRIVATE oqs)
endif()
