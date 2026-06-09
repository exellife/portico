/* ============================================================================
 * portico — unified HTTP/1.1 + WebSocket server library (public umbrella header).
 *
 *   #include "portico.h"
 *
 * Create a server with ws_server_create(); register WebSocket callbacks and/or an
 * HTTP handler (callbacks.on_http_request) on ws_server_start(). One listener
 * serves both: connections that send a WebSocket upgrade take the WS path, all
 * others are served as HTTP.
 * ============================================================================ */
#ifndef PORTICO_H
#define PORTICO_H

#include "wslib.h"         /* server lifecycle, ws_callbacks_t (with on_http_request) */
#include "portico_http.h"  /* HTTP request/response types + builders */

#endif /* PORTICO_H */
