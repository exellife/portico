cmake_minimum_required(VERSION 3.16)
project(portico C)

# portico — a single-binary HTTP/1.1 + WebSocket server library for C.
#   - WebSocket core: hardened wslib (RFC 6455)
#   - HTTP core:      picohttpparser (request parsing) + portico http layer
# One listener, one epoll loop, per-connection dispatch to WS or HTTP.

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()
add_compile_definitions(_GNU_SOURCE)

option(PORTICO_BUILD_TESTS    "Build tests"            ON)
option(PORTICO_BUILD_EXAMPLES "Build example servers"  ON)
option(PORTICO_ASAN           "Build with AddressSanitizer" OFF)
if(PORTICO_ASAN)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
endif()
option(PORTICO_TSAN           "Build with ThreadSanitizer" OFF)
if(PORTICO_TSAN)
    add_compile_options(-fsanitize=thread -fno-omit-frame-pointer -g -O1)
    add_link_options(-fsanitize=thread)
endif()

find_package(Threads REQUIRED)

# Optional TLS. portico builds plaintext-only if OpenSSL is absent; when present,
# the listener can terminate TLS (cert/key paths in ws_config_t). The define +
# linkage are PUBLIC so they propagate to consumers (e.g. pgforge).
option(PORTICO_TLS "Enable TLS termination (requires OpenSSL)" ON)
if(PORTICO_TLS)
    find_package(OpenSSL)
    if(NOT OpenSSL_FOUND)
        message(STATUS "portico: OpenSSL not found — building without TLS")
        set(PORTICO_TLS OFF)
    endif()
endif()

# --- vendored third-party (kept warning-quiet) ---
add_library(picohttpparser STATIC third_party/picohttpparser/picohttpparser.c)
target_include_directories(picohttpparser PUBLIC third_party/picohttpparser)
target_compile_options(picohttpparser PRIVATE -w)

# --- portico library ---
file(GLOB PORTICO_WS_SOURCES   CONFIGURE_DEPENDS src/ws/*.c)
file(GLOB PORTICO_HTTP_SOURCES CONFIGURE_DEPENDS src/http/*.c)
file(GLOB PORTICO_SOURCES      CONFIGURE_DEPENDS src/*.c)

add_library(portico STATIC
    ${PORTICO_WS_SOURCES} ${PORTICO_HTTP_SOURCES} ${PORTICO_SOURCES})
target_include_directories(portico
    PUBLIC  src/ws/include include
    PRIVATE src/ws src/ws/internal src/http)
# WS sources are vendored & warning-noisy; keep them quiet, surface warnings in
# portico's own http/ code instead.
set_source_files_properties(${PORTICO_WS_SOURCES} PROPERTIES COMPILE_OPTIONS "-w")
target_compile_options(portico PRIVATE -Wall -Wextra -Wno-unused-parameter)
target_link_libraries(portico PUBLIC Threads::Threads picohttpparser)
if(PORTICO_TLS)
    target_link_libraries(portico PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(portico PUBLIC PORTICO_TLS=1)
endif()

# --- examples ---
if(PORTICO_BUILD_EXAMPLES)
    add_executable(echo_server examples/echo_server.c)
    target_link_libraries(echo_server PRIVATE portico)
    add_executable(http_server examples/http_server.c)
    target_link_libraries(http_server PRIVATE portico)
    add_executable(autobahn_server examples/autobahn_server.c)
    target_link_libraries(autobahn_server PRIVATE portico)
    add_executable(stress_server examples/stress_server.c)
    target_link_libraries(stress_server PRIVATE portico)
endif()

# --- tests ---
if(PORTICO_BUILD_TESTS)
    enable_testing()
    find_program(PYTHON3 python3)
    if(PYTHON3 AND PORTICO_BUILD_EXAMPLES)
        add_test(NAME ws_adversarial
            COMMAND ${PYTHON3} ${CMAKE_SOURCE_DIR}/tests/run_with_server.py
                    $<TARGET_FILE:echo_server> ${CMAKE_SOURCE_DIR}/tests/ws_test.py)
        # Server-initiated close teardown (C-2): exercise ws_close_connection ->
        # process_close_message under churn (double-free / slot aliasing / fd leak).
        add_test(NAME ws_srvclose
            COMMAND ${PYTHON3} ${CMAKE_SOURCE_DIR}/tests/run_with_server.py
                    $<TARGET_FILE:echo_server> ${CMAKE_SOURCE_DIR}/tests/srvclose_test.py)
        # http_server speaks both protocols, so it exercises WS + HTTP on one port.
        add_test(NAME ws_adversarial_unified
            COMMAND ${PYTHON3} ${CMAKE_SOURCE_DIR}/tests/run_with_server.py
                    $<TARGET_FILE:http_server> ${CMAKE_SOURCE_DIR}/tests/ws_test.py)
        add_test(NAME http_adversarial
            COMMAND ${PYTHON3} ${CMAKE_SOURCE_DIR}/tests/run_with_server.py
                    $<TARGET_FILE:http_server> ${CMAKE_SOURCE_DIR}/tests/http_test.py)
        # Accept-time IP gate: a blacklisted peer is dropped before any handshake.
        add_test(NAME accept_gate
            COMMAND bash ${CMAKE_SOURCE_DIR}/tests/accept_test.sh $<TARGET_FILE:http_server>)
        # Slowloris reaper: stalled pre-request connections are reaped without
        # racing the event loop into a double-close / fd-reuse (finding H-7).
        add_test(NAME reaper
            COMMAND bash ${CMAKE_SOURCE_DIR}/tests/reaper_test.sh $<TARGET_FILE:http_server>)
        # Keepalive + idle reaping of established connections (H-8): an idle WS is
        # PINGed and reaped on pong timeout; an idle HTTP keep-alive is reaped too.
        add_test(NAME keepalive
            COMMAND bash ${CMAKE_SOURCE_DIR}/tests/keepalive_test.sh $<TARGET_FILE:http_server>)
        # TLS: HTTPS + WSS against one TLS listener (needs openssl to mint a cert).
        find_program(OPENSSL_BIN openssl)
        if(PORTICO_TLS AND OPENSSL_BIN)
            add_test(NAME tls
                COMMAND bash ${CMAKE_SOURCE_DIR}/tests/tls_test.sh $<TARGET_FILE:http_server>)
        endif()
    endif()
endif()
