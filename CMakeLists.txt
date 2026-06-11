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

add_library(cjson STATIC third_party/cjson/cJSON.c)
target_include_directories(cjson PUBLIC third_party/cjson/include)
target_compile_options(cjson PRIVATE -w)

# --- ACME client (RFC 8555), built incrementally; cJSON + OpenSSL (the latter for
# the verifying HTTPS client and JWS crypto, gated on PORTICO_TLS like the lib). ---
file(GLOB PORTICO_ACME_SOURCES CONFIGURE_DEPENDS src/acme/*.c)
add_library(portico_acme STATIC ${PORTICO_ACME_SOURCES})
target_include_directories(portico_acme PUBLIC include src/acme)
target_compile_options(portico_acme PRIVATE -Wall -Wextra -Wno-unused-parameter)
target_link_libraries(portico_acme PUBLIC cjson)
if(PORTICO_TLS)
    target_link_libraries(portico_acme PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(portico_acme PRIVATE PORTICO_TLS=1)
endif()

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
target_link_libraries(portico PUBLIC Threads::Threads picohttpparser portico_aio)
if(PORTICO_TLS)
    target_link_libraries(portico PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(portico PUBLIC PORTICO_TLS=1)
endif()

# --- async file I/O (standalone, loop-agnostic) ---
# Deliberately NOT linked into `portico` yet: it depends only on libc + pthreads
# and is developed/tested in isolation. The eventual file-serving path will link
# it and integrate via its wakeup eventfd. See include/portico_aio.h.
file(GLOB PORTICO_AIO_SOURCES CONFIGURE_DEPENDS src/aio/*.c)
add_library(portico_aio STATIC ${PORTICO_AIO_SOURCES})
target_include_directories(portico_aio PUBLIC include PRIVATE src/aio)
target_compile_options(portico_aio PRIVATE -Wall -Wextra -Wno-unused-parameter)
target_link_libraries(portico_aio PUBLIC Threads::Threads)
# io_uring backend uses raw syscalls (no liburing); enable it where the kernel
# headers exist. Absent → aio_uring.c is an -ENOSYS stub and PORTICO_AIO_IOURING
# falls back. No extra link dependency.
include(CheckIncludeFile)
check_include_file("linux/io_uring.h" PORTICO_HAVE_LINUX_IO_URING)
if(PORTICO_HAVE_LINUX_IO_URING)
    target_compile_definitions(portico_aio PRIVATE PORTICO_AIO_HAVE_IOURING=1)
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

    # Async file I/O: pure C unit test, no server/sockets — runs in isolation.
    add_executable(aio_test tests/aio_test.c)
    target_link_libraries(aio_test PRIVATE portico_aio)
    add_test(NAME aio COMMAND aio_test)

    # ACME base64url codec + cJSON vendoring sanity (pure C, no network).
    add_executable(base64url_test tests/base64url_test.c)
    target_link_libraries(base64url_test PRIVATE portico_acme)
    add_test(NAME base64url COMMAND base64url_test)

    # ACME account key + JWS/ES256 (only with TLS — needs OpenSSL). Known-answer JWK/
    # thumbprint + cryptographic signature verification.
    if(PORTICO_TLS)
        add_executable(jws_test tests/jws_test.c)
        target_link_libraries(jws_test PRIVATE portico_acme)
        add_test(NAME jws COMMAND jws_test)
    endif()

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
        # Proxy client-IP resolution (M-8): rightmost X-Forwarded-For + IP validation.
        add_test(NAME proxy_ip
            COMMAND bash ${CMAKE_SOURCE_DIR}/tests/proxy_ip_test.sh $<TARGET_FILE:http_server>)
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
        # Static file serving (async aio path): correct bytes/types, large-file
        # byte-exactness, 404/403, traversal + symlink safety, keep-alive resume.
        add_test(NAME static
            COMMAND bash ${CMAKE_SOURCE_DIR}/tests/static_test.sh $<TARGET_FILE:http_server>)
        # Name-based virtual hosting: Host -> per-vhost docroot (+ wildcard, allow-list).
        add_test(NAME vhost
            COMMAND bash ${CMAKE_SOURCE_DIR}/tests/vhost_test.sh $<TARGET_FILE:http_server>)
        # TLS: HTTPS + WSS against one TLS listener (needs openssl to mint a cert).
        find_program(OPENSSL_BIN openssl)
        if(PORTICO_TLS AND OPENSSL_BIN)
            add_test(NAME tls
                COMMAND bash ${CMAKE_SOURCE_DIR}/tests/tls_test.sh $<TARGET_FILE:http_server>)
            # SNI multi-cert: a different per-domain cert is presented by SNI server_name.
            add_test(NAME sni
                COMMAND bash ${CMAKE_SOURCE_DIR}/tests/sni_test.sh $<TARGET_FILE:http_server>)
            # SIGHUP TLS cert hot-reload: new certs served, server stays up (zero downtime).
            add_test(NAME reload
                COMMAND bash ${CMAKE_SOURCE_DIR}/tests/reload_test.sh $<TARGET_FILE:http_server>)
            # ACME verifying HTTPS client: chain + hostname verification (local TLS server).
            add_executable(https_probe tests/https_probe.c)
            target_link_libraries(https_probe PRIVATE portico_acme)
            add_test(NAME https_client
                COMMAND bash ${CMAKE_SOURCE_DIR}/tests/https_client_test.sh
                        $<TARGET_FILE:http_server> $<TARGET_FILE:https_probe>)
        endif()
    endif()
endif()
