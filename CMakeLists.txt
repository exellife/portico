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

find_package(Threads REQUIRED)

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

# --- examples ---
if(PORTICO_BUILD_EXAMPLES)
    add_executable(echo_server examples/echo_server.c)
    target_link_libraries(echo_server PRIVATE portico)
    add_executable(http_server examples/http_server.c)
    target_link_libraries(http_server PRIVATE portico)
endif()

# --- tests ---
if(PORTICO_BUILD_TESTS)
    enable_testing()
    find_program(PYTHON3 python3)
    if(PYTHON3 AND PORTICO_BUILD_EXAMPLES)
        add_test(NAME ws_adversarial
            COMMAND ${PYTHON3} ${CMAKE_SOURCE_DIR}/tests/run_with_server.py
                    $<TARGET_FILE:echo_server> ${CMAKE_SOURCE_DIR}/tests/ws_test.py)
        # http_server speaks both protocols, so it exercises WS + HTTP on one port.
        add_test(NAME ws_adversarial_unified
            COMMAND ${PYTHON3} ${CMAKE_SOURCE_DIR}/tests/run_with_server.py
                    $<TARGET_FILE:http_server> ${CMAKE_SOURCE_DIR}/tests/ws_test.py)
        add_test(NAME http_adversarial
            COMMAND ${PYTHON3} ${CMAKE_SOURCE_DIR}/tests/run_with_server.py
                    $<TARGET_FILE:http_server> ${CMAKE_SOURCE_DIR}/tests/http_test.py)
    endif()
endif()
