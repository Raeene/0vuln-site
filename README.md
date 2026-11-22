# 0vuln.com hub

Landing page for [0vuln.com](https://0vuln.com): links the tools ([Range](https://range.0vuln.com), [PacketStory](https://pcap.0vuln.com)) and [Raeene's site](https://raeene.0vuln.com), with a small in-browser shell.

Static files in `public/`, served by Cloudflare Workers static assets (`wrangler.jsonc`).

```
npx wrangler dev      # local preview
npx wrangler deploy   # deploy
```

- No inline scripts or styles: the CSP in `public/_headers` is `script-src 'self'; style-src 'self'`.
- `security.txt` is served at both `/.well-known/security.txt` and `/security.txt`.
