/* ============================================================================
 * WSLib - WebSocket Handshake Implementation
 * 
 * RFC 6455 compliant WebSocket handshake processing
 * ============================================================================ */

#define _GNU_SOURCE
#include "internal/ws_internal.h"
#include "internal/ws_utils.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>

/* ============================================================================
 * HTTP Header Parsing
 * ============================================================================ */

static char* find_header_value(const char *headers, const char *header_name) {
    if (!headers || !header_name) {
        return NULL;
    }
    
    size_t header_len = strlen(header_name);
    const char *search_pos = headers;
    
    /* Search for header name at the beginning of lines only */
    while ((search_pos = strcasestr(search_pos, header_name)) != NULL) {
        /* Check if this is at the start of a line (beginning or after \r\n) */
        if (search_pos == headers || 
            (search_pos >= headers + 2 && search_pos[-2] == '\r' && search_pos[-1] == '\n')) {
            
            /* Check if followed by colon (with possible whitespace) */
            const char *after_header = search_pos + header_len;
            while (*after_header == ' ' || *after_header == '\t') {
                after_header++;
            }
            
            if (*after_header == ':') {
                /* Found the correct header, move to after colon */
                search_pos = after_header + 1;
                break;
            }
        }
        
        /* Move past this match and continue searching */
        search_pos++;
    }
    
    if (!search_pos) {
        return NULL;
    }
    
    /* Skip whitespace after colon */
    while (*search_pos && (*search_pos == ' ' || *search_pos == '\t')) {
        search_pos++;
    }
    
    /* Find end of value (before \r\n) */
    const char *end = strstr(search_pos, "\r\n");
    if (!end) {
        end = search_pos + strlen(search_pos);
    }
    
    /* Remove trailing whitespace */
    while (end > search_pos && (*(end-1) == ' ' || *(end-1) == '\t')) {
        end--;
    }
    
    size_t len = end - search_pos;
    char *value = malloc(len + 1);
    if (value) {
        memcpy(value, search_pos, len);
        value[len] = '\0';
    }
    
    return value;
}

static int validate_websocket_headers(const char *headers) {
    /* Check for required headers */
    char *upgrade = find_header_value(headers, "Upgrade");
    char *connection = find_header_value(headers, "Connection");
    char *ws_version = find_header_value(headers, "Sec-WebSocket-Version");
    
    int valid = 0;
    
    if (upgrade && ws_string_contains_token(upgrade, "websocket") &&
        connection && ws_string_contains_token(connection, "upgrade") &&
        ws_version && strcmp(ws_version, "13") == 0) {
        valid = 1;
    }
    
    free(upgrade);
    free(connection);
    free(ws_version);
    
    return valid;
}

/* ============================================================================
 * Handshake Processing Functions
 * ============================================================================ */

int ws_parse_handshake_request(const char *request, ws_handshake_info_t *info) {
    if (!request || !info) {
        return -1;
    }
    
    memset(info, 0, sizeof(ws_handshake_info_t));
    
    /* Check for GET method */
    if (strncmp(request, "GET ", 4) != 0) {
        info->error_code = 405; /* Method Not Allowed */
        return -1;
    }
    
    /* Extract path */
    const char *path_start = request + 4;
    const char *path_end = strchr(path_start, ' ');
    if (!path_end) {
        info->error_code = 400; /* Bad Request */
        return -1;
    }
    
    size_t path_len = path_end - path_start;
    if (path_len >= sizeof(info->path)) {
        info->error_code = 414; /* URI Too Long */
        return -1;
    }
    
    memcpy(info->path, path_start, path_len);
    info->path[path_len] = '\0';
    
    /* Validate WebSocket headers */
    if (!validate_websocket_headers(request)) {
        info->error_code = 400; /* Bad Request */
        return -1;
    }
    
    /* Extract WebSocket key */
    char *ws_key = find_header_value(request, "Sec-WebSocket-Key");
    if (!ws_key) {
        info->error_code = 400; /* Bad Request */
        return -1;
    }
    
    strncpy(info->sec_websocket_key, ws_key, sizeof(info->sec_websocket_key) - 1);
    info->sec_websocket_key[sizeof(info->sec_websocket_key) - 1] = '\0';
    free(ws_key);
    
    /* Extract optional headers */
    char *protocol = find_header_value(request, "Sec-WebSocket-Protocol");
    if (protocol) {
        strncpy(info->sec_websocket_protocol, protocol, sizeof(info->sec_websocket_protocol) - 1);
        info->sec_websocket_protocol[sizeof(info->sec_websocket_protocol) - 1] = '\0';
        free(protocol);
    }
    
    char *origin = find_header_value(request, "Origin");
    if (origin) {
        strncpy(info->origin, origin, sizeof(info->origin) - 1);
        info->origin[sizeof(info->origin) - 1] = '\0';
        free(origin);
    }
    
    return 0;
}

int ws_create_handshake_response(const ws_handshake_info_t *info, const char *selected_protocol,
                                char *response, size_t response_size) {
    if (!info || !response || response_size == 0) {
        return -1;
    }
    
    /* Generate accept key using utility function */
    char accept_key[WS_WEBSOCKET_ACCEPT_LENGTH + 1];
    if (ws_generate_accept_key(info->sec_websocket_key, accept_key) != 0) {
        return -1;
    }
    
    /* Build response */
    int written = snprintf(response, response_size,
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n",
        accept_key);
    
    if (written >= (int)response_size) {
        return -1; /* Response buffer too small */
    }
    
    /* Add protocol if selected */
    if (selected_protocol && strlen(selected_protocol) > 0) {
        int protocol_written = snprintf(response + written, response_size - written,
            "Sec-WebSocket-Protocol: %s\r\n", selected_protocol);
        
        if (protocol_written >= (int)(response_size - written)) {
            return -1; /* Response buffer too small */
        }
        written += protocol_written;
    }
    
    /* Add final CRLF */
    if (written + 2 >= (int)response_size) {
        return -1; /* Response buffer too small */
    }
    
    strcat(response, "\r\n");
    written += 2;
    
    return written;
}

int ws_send_handshake_error(ws_connection_t *conn, int error_code, const char *error_message) {
    char response[512];
    const char *status_text;
    
    switch (error_code) {
        case 400: status_text = "Bad Request"; break;
        case 403: status_text = "Forbidden"; break;
        case 405: status_text = "Method Not Allowed"; break;
        case 414: status_text = "URI Too Long"; break;
        case 426: status_text = "Upgrade Required"; break;
        case 500: status_text = "Internal Server Error"; break;
        default: 
            error_code = 400;
            status_text = "Bad Request";
            break;
    }
    
    if (!error_message) {
        error_message = status_text;
    }
    
    int len = snprintf(response, sizeof(response),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        error_code, status_text, strlen(error_message), error_message);
    
    ssize_t sent = ws_conn_socket_write(conn, response, len);
    return (sent == len) ? 0 : -1;
}

/* ============================================================================
 * High-Level Handshake Processing
 * ============================================================================ */

int ws_process_handshake(ws_connection_t *conn, const char *request, const ws_callbacks_t *callbacks) {
    if (!request || !callbacks) {
        return -1;
    }

    ws_handshake_info_t info;
    if (ws_parse_handshake_request(request, &info) != 0) {
        ws_send_handshake_error(conn, info.error_code, NULL);
        return -1;
    }

    /* Call application handshake callback if provided */
    const char *selected_protocol = NULL;
    if (callbacks->on_handshake) {
        int result = callbacks->on_handshake(conn->fd, &info, &selected_protocol);
        if (result != 0) {
            ws_send_handshake_error(conn, 403, "Forbidden");
            return -1;
        }
    }

    /* Create and send handshake response */
    char response[1024];
    int response_len = ws_create_handshake_response(&info, selected_protocol, response, sizeof(response));
    if (response_len < 0) {
        ws_send_handshake_error(conn, 500, "Internal Server Error");
        return -1;
    }

    ssize_t sent = ws_conn_socket_write(conn, response, response_len);
    if (sent != response_len) {
        return -1;
    }

    return 0;
}
