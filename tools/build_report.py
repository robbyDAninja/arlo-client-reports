#!/usr/bin/env python3
"""Build a self-contained password-gated static report.

The output HTML uses the browser's Web Crypto API to derive an AES-256-GCM key
from the supplied password with PBKDF2-SHA-256, 200000 iterations, and a random
16-byte salt. The encrypted report body is embedded as base64 ciphertext with a
random 12-byte IV.

Encryption is performed with Python's ``cryptography`` package when it is
available. If it is not installed, this script falls back to local Node.js and
``node:crypto`` WebCrypto primitives, which are compatible with browser
``crypto.subtle`` decryption. No external Python or JavaScript dependencies are
required for the fallback path.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


PBKDF2_ITERATIONS = 200000
SALT_BYTES = 16
IV_BYTES = 12
KEY_BYTES = 32
ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = ROOT / "templates" / "report_template.html"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a self-contained AES-GCM password-gated static report."
    )
    parser.add_argument("--title", required=True, help="Report title shown before unlock.")
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Path to the report body HTML. The file is embedded as raw HTML.",
    )
    parser.add_argument(
        "--password",
        required=True,
        help="Shared password used to encrypt the report body.",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Output HTML path, for example reports/client-slug/index.html.",
    )
    return parser.parse_args()


def encrypt_with_cryptography(password: str, body: bytes, salt: bytes, iv: bytes) -> bytes | None:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        return None

    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=KEY_BYTES,
    )
    return AESGCM(key).encrypt(iv, body, None)


def encrypt_with_node(password: str, body: bytes, salt: bytes, iv: bytes) -> bytes:
    node = shutil.which("node")
    if node is None:
        raise RuntimeError("Node.js is required because the Python cryptography package is unavailable.")

    script = r"""
const { webcrypto } = require("node:crypto");

async function main() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const payload = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  const passwordBytes = new TextEncoder().encode(payload.password);
  const salt = Buffer.from(payload.saltB64, "base64");
  const iv = Buffer.from(payload.ivB64, "base64");
  const body = Buffer.from(payload.bodyB64, "base64");
  const passwordKey = await webcrypto.subtle.importKey(
    "raw",
    passwordBytes,
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  const key = await webcrypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: payload.iterations,
      hash: "SHA-256"
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );
  const ciphertext = await webcrypto.subtle.encrypt({ name: "AES-GCM", iv }, key, body);
  process.stdout.write(Buffer.from(ciphertext).toString("base64"));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
"""
    payload = {
        "password": password,
        "saltB64": base64.b64encode(salt).decode("ascii"),
        "ivB64": base64.b64encode(iv).decode("ascii"),
        "bodyB64": base64.b64encode(body).decode("ascii"),
        "iterations": PBKDF2_ITERATIONS,
    }
    result = subprocess.run(
        [node, "-e", script],
        input=json.dumps(payload).encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace").strip())
    return base64.b64decode(result.stdout.strip())


def render_template(title: str, salt: bytes, iv: bytes, ciphertext: bytes) -> str:
    template = TEMPLATE_PATH.read_text(encoding="utf-8")
    replacements = {
        "__TITLE_HTML__": html.escape(title, quote=True),
        "__TITLE_JSON__": json.dumps(title),
        "__SALT_B64__": base64.b64encode(salt).decode("ascii"),
        "__IV_B64__": base64.b64encode(iv).decode("ascii"),
        "__CIPHERTEXT_B64__": base64.b64encode(ciphertext).decode("ascii"),
    }
    for placeholder, value in replacements.items():
        template = template.replace(placeholder, value)
    return template


def main() -> int:
    args = parse_args()
    body = args.input.read_bytes()
    salt = os.urandom(SALT_BYTES)
    iv = os.urandom(IV_BYTES)

    ciphertext = encrypt_with_cryptography(args.password, body, salt, iv)
    if ciphertext is None:
        ciphertext = encrypt_with_node(args.password, body, salt, iv)

    output = args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_template(args.title, salt, iv, ciphertext), encoding="utf-8")
    print(f"Wrote {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
