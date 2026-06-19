/* ============================================================================
 * portico — JSON config-file loader (optional, opt-in).
 *
 * Parses a deployment config file into the structs portico already consumes
 * (ws_config_t + a portico_vhost_t[]) — the core library does no file I/O; this
 * module is the only place that touches a config file. The returned object OWNS
 * every string it exposes (hostnames, docroots, cert paths); the views below are
 * valid only until portico_config_free().
 *
 * See docs/portico-config-design.md for the schema and the reload model.
 * ============================================================================ */
#ifndef PORTICO_CONFIG_H
#define PORTICO_CONFIG_H

#include "wslib.h"         /* ws_config_t, ws_tls_sni_cert_t */
#include "portico_http.h"  /* portico_vhost_t */
#include <stddef.h>

/* How the listener provisions its TLS certificates. */
typedef enum {
    PORTICO_TLS_OFF = 0,   /* plaintext only */
    PORTICO_TLS_FILES,     /* default cert/key from disk (+ per-site SNI certs) */
    PORTICO_TLS_ACME       /* obtain/renew certs via ACME (cert paths resolved later) */
} portico_tls_mode_t;

/* ACME settings (meaningful only when the mode is PORTICO_TLS_ACME). Pointers are
 * into the owned config and live for its lifetime; NULL where unset. */
typedef struct {
    const char *directory_url;    /* ACME directory (defaults to LE production) */
    const char *email;            /* optional contact, may be NULL */
    const char *account_key_path; /* account key PEM (load or create) */
    const char *cert_dir;         /* issued chain+key are written under here */
    const char *ca_file;          /* NULL = system roots (set for Pebble) */
    int         renew_days;       /* renew when fewer days remain (0 = manager default) */
    int         challenge_port;   /* HTTP-01 port (0 = manager default, 80) */
} portico_acme_settings_t;

typedef struct portico_config portico_config_t;

/* Parse + validate the JSON config at `path`. On failure returns NULL and, if
 * `err` is non-NULL, writes a human-readable reason into it (NUL-terminated,
 * truncated to errcap). On success returns an owned config object. */
portico_config_t *portico_config_load(const char *path, char *err, size_t errcap);

/* Free the config and every string it owns. Safe on NULL. Must outlive any server
 * still referencing its ws_config_t / vhosts. */
void portico_config_free(portico_config_t *cfg);

/* ---- views into the owned config (valid until portico_config_free) ---- */

/* The listener + TLS config, ready for ws_server_create(). In ACME mode the default
 * cert/key are left unset here (resolved after issuance by the caller). */
const ws_config_t     *portico_config_ws(const portico_config_t *cfg);

/* The Host-routing table, ready for portico_res_vhost(). *n receives the count. */
const portico_vhost_t *portico_config_vhosts(const portico_config_t *cfg, size_t *n);

portico_tls_mode_t            portico_config_tls_mode(const portico_config_t *cfg);
const portico_acme_settings_t *portico_config_acme(const portico_config_t *cfg);

/* The site hostnames (the SAN set for the ACME manager). Fallback (host==NULL)
 * sites are excluded. *n receives the count. */
const char *const *portico_config_acme_domains(const portico_config_t *cfg, size_t *n);

#endif /* PORTICO_CONFIG_H */
