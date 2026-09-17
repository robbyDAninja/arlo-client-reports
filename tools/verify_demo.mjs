#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { webcrypto } from "node:crypto";
import assert from "node:assert/strict";

const PASSWORD = "demo1234";
const EXPECTED_BODY = `<h1>Bridge Ninja Demo Report</h1>
<p>This is a confidential Bridge Ninja client report. If you can read this, the password gate worked.</p>
`;
const PBKDF2_ITERATIONS = 200000;

function extractConstant(html, name) {
  const pattern = new RegExp(`const\\s+${name}\\s*=\\s*"([^"]+)"`);
  const match = html.match(pattern);
  assert.ok(match, `Missing ${name}`);
  return match[1];
}

function b64ToBytes(value) {
  return Buffer.from(value, "base64");
}

async function deriveKey(password, salt) {
  const passwordKey = await webcrypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return webcrypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

const html = await readFile(new URL("../reports/demo/index.html", import.meta.url), "utf8");
const salt = b64ToBytes(extractConstant(html, "SALT_B64"));
const iv = b64ToBytes(extractConstant(html, "IV_B64"));
const ciphertext = b64ToBytes(extractConstant(html, "CIPHERTEXT_B64"));
const key = await deriveKey(PASSWORD, salt);
const plaintext = await webcrypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
const decoded = new TextDecoder().decode(plaintext);

assert.equal(decoded, EXPECTED_BODY);
console.log("PASS: demo report decrypts with WebCrypto and matches reports/demo/body.html");
