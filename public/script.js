// scram-auth/public/script.js

function log(msg) {
  document.getElementById("log").innerText += `> ${msg}\n`;
}

async function register() {
  const u = document.getElementById("reg-username").value;
  const p = document.getElementById("reg-password").value;
  const r = await fetch("/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: u, password: p }),
  });
  const t = await r.text();
  document.getElementById("result").innerText = t;
  log(`Registered ${u}`);
}

async function login(wrong = false) {
  const u = document.getElementById("log-username").value;
  const p = wrong
    ? "incorrect!"
    : document.getElementById("log-password").value;
  document.getElementById("result").innerText = "";
  document.getElementById("log").innerText = "";

  const cn = btoa(
    Array.from(crypto.getRandomValues(new Uint8Array(12)))
      .map((b) => String.fromCharCode(b))
      .join(""),
  );
  log(`Client nonce: ${cn}`);
  log("→ POST /auth/start");
  const start = await fetch("/auth/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: u, clientNonce: cn }),
  });
  if (!start.ok) {
    log("User not found");
    document.getElementById("result").innerText = "No such user";
    return;
  }
  const { salt, iterations, combinedNonce } = await start.json();
  log("← salt & serverNonce received");

  // derive
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(p),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const saltBuf = Uint8Array.from(atob(salt), (c) => c.charCodeAt(0));
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBuf, iterations, hash: "SHA-256" },
    key,
    256,
  );
  const sp = new Uint8Array(bits);

  const authMsg = `n=${u},r=${cn},s=${salt},i=${iterations},r=${combinedNonce}`;
  const ck = await hmac(sp, "Client Key");
  const sk = await hash(ck);
  const cs = await hmac(sk, authMsg);
  const proof = xor(ck, cs);

  log("→ POST /auth/finish");
  const fin = await fetch("/auth/finish", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: u,
      clientProof: btoa(String.fromCharCode(...proof)),
    }),
  });

  if (fin.ok) {
    const { serverSignature } = await fin.json();
    document.getElementById("result").innerText = "Authenticated!";
    log("Authentication successful");
    log(`Server signature: ${serverSignature}`);
  } else {
    document.getElementById("result").innerText = "Login failed";
    log("Authentication failed");
  }
}

async function loginWrong() {
  await login(true);
}

async function hmac(key, msg) {
  const enc = new TextEncoder();
  const k = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const s = await crypto.subtle.sign("HMAC", k, enc.encode(msg));
  return new Uint8Array(s);
}

async function hash(buf) {
  const d = await crypto.subtle.digest("SHA-256", buf);
  return new Uint8Array(d);
}

function xor(a, b) {
  return new Uint8Array(a.map((v, i) => v ^ b[i]));
}
