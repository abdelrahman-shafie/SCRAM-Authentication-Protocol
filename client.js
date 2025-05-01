// scram-auth/client.js
const axios = require("axios");
const crypto = require("crypto");

const username = "alice";
const password = "secret123";
const clientNonce = crypto.randomBytes(16).toString("base64");

const hi = (pw, s, i) =>
  crypto.pbkdf2Sync(pw, Buffer.from(s, "base64"), i, 32, "sha256");
const hmacFn = (k, m) => crypto.createHmac("sha256", k).update(m).digest();
const hashFn = (b) => crypto.createHash("sha256").update(b).digest();
const xorFn = (a, b) => Buffer.from(a.map((v, i) => v ^ b[i]));

(async () => {
  // start
  const { data } = await axios.post("http://localhost:3000/auth/start", {
    username,
    clientNonce,
  });
  const { salt, iterations, combinedNonce } = data;

  // proof
  const saltedPwd = hi(password, salt, iterations);
  const clientKey = hmacFn(saltedPwd, "Client Key");
  const storeKey = hashFn(clientKey);
  const authMsg = `n=${username},r=${clientNonce},s=${salt},i=${iterations},r=${combinedNonce}`;
  const clientSign = hmacFn(storeKey, authMsg);
  const clientProof = xorFn(clientKey, clientSign).toString("base64");

  // finish
  const resFinish = await axios.post("http://localhost:3000/auth/finish", {
    username,
    clientProof,
  });
  console.log("[+] Auth OK:", resFinish.data);
})().catch((e) => {
  console.error("[-] Auth error:", e.response?.data || e.message);
});
