# portico demo site

A real multi-page static site for serving with portico — demonstrates clean-URL
routing, shared assets, an SVG, petite-vue interactivity (reactive UI + live
`/health`/`/ip` fetch + a WSS echo), and brotli/gzip precompression.

Layout:
- `index.html`, `about/index.html`, `demo/index.html` — pages (clean URLs)
- `assets/` — `style.css`, `app.js`, `logo.svg`, vendored `petite-vue.iife.js`

Serve it with the http_server example:
```
STATIC_ROOT=/path/to/site STATIC_PRECOMPRESSED=1 STATIC_DIR_REDIRECT=1 \
  PORT=443 ACME_DOMAINS=your.domain ... ./http_server
```
Precompressed siblings (`*.br`, `*.gz`) are generated at deploy, not committed:
```
for f in assets/style.css assets/app.js assets/petite-vue.iife.js; do
  gzip -9 -k -f "$f"; brotli -q 11 -k -f "$f"
done
```
