# RecoverMax Website

Static landing page for [recovermax.dev](https://recovermax.dev).

## Deployment

Serve the `website/` directory with any static file server:

```bash
# Python
python3 -m http.server 8000 --directory website/

# Node
npx serve website/

# Caddy
caddy file-server --root website/ --listen :8000
```

No build step required. The site is a single `index.html` file with all CSS inlined.
