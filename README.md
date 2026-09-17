# Arlo Client Reports

Small static-site toolkit for password-gated client reports. It turns a title, an HTML report body, and a shared password into a single self-contained static HTML file that can be served by GitHub Pages without a backend.

The generated report page shows only the title and a password field at first. On submit, browser Web Crypto derives an AES-256-GCM key from the password using PBKDF2-SHA-256 with 200000 iterations and the embedded random salt, then decrypts the embedded ciphertext and injects the report HTML only after authentication succeeds.

## Build A Report

Create the report body as HTML, then run:

```sh
python3 tools/build_report.py \
  --title "Client Report" \
  --input path/to/body.html \
  --password "shared-password" \
  --output reports/client-slug/index.html
```

The input file is treated as raw HTML. This toolkit does not parse Markdown; convert Markdown to HTML before calling the builder.

Encryption uses Python's `cryptography` package when available. If `cryptography` is not installed, the builder falls back to local Node.js and `node:crypto` WebCrypto, which matches the browser-side PBKDF2 and AES-GCM primitives used for decryption.

## Demo

A demo report is included at `reports/demo/`. The password is:

```text
demo1234
```

Verify the generated demo ciphertext with Node WebCrypto:

```sh
node tools/verify_demo.mjs
```

## GitHub Pages

Enable GitHub Pages once for this repository:

Settings -> Pages -> Source: Deploy from branch -> main -> / (root)

After Pages is enabled, reports can be linked from the root `index.html`. Add future reports as list items such as:

```html
<li><a href="reports/client-slug/">Client Report</a></li>
```

## Security Note

This is a lightweight deterrent, not enterprise access control. The report content is encrypted client-side with a shared password, which is useful for keeping a report link from being casually stumbled on. It is not appropriate for truly sensitive data, regulated data, user-specific authorization, audit requirements, password rotation, or revoking access after a link and password have been shared.
