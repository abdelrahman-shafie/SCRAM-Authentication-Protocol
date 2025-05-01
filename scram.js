// scram-auth/scram.js
const crypto = require("crypto");

function generateSalt(len = 16) {
  return crypto.randomBytes(len).toString("base64");
}

function generateNonce(len = 16) {
  return crypto.randomBytes(len).toString("base64");
}

function hi(password, salt, iterations) {
  return crypto.pbkdf2Sync(
    password,
    Buffer.from(salt, "base64"),
    iterations,
    32,
    "sha256",
  );
}

function hmac(key, msg) {
  return crypto.createHmac("sha256", key).update(msg).digest();
}

function hash(buf) {
  return crypto.createHash("sha256").update(buf).digest();
}

function xor(a, b) {
  return Buffer.from(a.map((v, i) => v ^ b[i]));
}

module.exports = { generateSalt, generateNonce, hi, hmac, hash, xor };
