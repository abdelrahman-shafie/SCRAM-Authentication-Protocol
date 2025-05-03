// scram-auth/public/showcase.js
async function runShowcase() {
  const user = document.getElementById("user").value;
  const pw = document.getElementById("pw").value;
  const saltB64 = document.getElementById("salt").value;
  const iter = parseInt(document.getElementById("iter").value, 10);
  const cnonce = document.getElementById("cnonce").value;
  const snonce = document.getElementById("snonce").value;
  const outEl = document.getElementById("steps");
  outEl.innerText = "";

  function log(line = "") {
    outEl.innerText += line + "\n";
  }

  const enc = new TextEncoder();

  // 1) PBKDF2 → saltedPassword
  log("1) saltedPassword = PBKDF2(password, salt, iterations):");
  const keyMat = await crypto.subtle.importKey(
    "raw",
    enc.encode(pw),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const saltBuf = Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0));
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBuf, iterations: iter, hash: "SHA-256" },
    keyMat,
    32 * 8,
  );
  const saltedPassword = btoa(String.fromCharCode(...new Uint8Array(bits)));
  log(`   ${saltedPassword}\n`);

  // 2) clientKey = HMAC(saltedPassword, "Client Key")
  log('2) clientKey = HMAC_SHA256(saltedPassword, "Client Key"):');
  const spKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(bits),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const ckBuf = await crypto.subtle.sign(
    "HMAC",
    spKey,
    enc.encode("Client Key"),
  );
  const clientKey = btoa(String.fromCharCode(...new Uint8Array(ckBuf)));
  log(`   ${clientKey}\n`);

  // 3) storedKey = SHA256(clientKey)
  log("3) storedKey = SHA256(clientKey):");
  const ckBytes = Uint8Array.from(atob(clientKey), (c) => c.charCodeAt(0));
  const skBuf = await crypto.subtle.digest("SHA-256", ckBytes);
  const storedKey = btoa(String.fromCharCode(...new Uint8Array(skBuf)));
  log(`   ${storedKey}\n`);

  // 4) authMessage
  const combinedNonce = cnonce + snonce;
  const authMessage = `n=${user},r=${cnonce},s=${saltB64},i=${iter},r=${combinedNonce}`;
  log("4) authMessage:");
  log(`   ${authMessage}\n`);

  // 5) clientSignature = HMAC(storedKey, authMessage)
  log("5) clientSignature = HMAC_SHA256(storedKey, authMessage):");
  const skKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(skBuf),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const csBuf = await crypto.subtle.sign(
    "HMAC",
    skKey,
    enc.encode(authMessage),
  );
  const clientSignature = btoa(String.fromCharCode(...new Uint8Array(csBuf)));
  log(`   ${clientSignature}\n`);

  // 6) clientProof = clientKey ⊕ clientSignature
  log("6) clientProof = XOR(clientKey, clientSignature):");
  const proofBytes = Uint8Array.from(atob(clientKey), (c) =>
    c.charCodeAt(0),
  ).map(
    (v, i) =>
      v ^ Uint8Array.from(atob(clientSignature), (c) => c.charCodeAt(0))[i],
  );
  const clientProof = btoa(String.fromCharCode(...proofBytes));
  log(`   ${clientProof}\n`);

  // 7) serverKey = HMAC(saltedPassword, "Server Key")
  log('7) serverKey = HMAC_SHA256(saltedPassword, "Server Key"):');
  const sk2Buf = await crypto.subtle.sign(
    "HMAC",
    spKey,
    enc.encode("Server Key"),
  );
  const serverKey = btoa(String.fromCharCode(...new Uint8Array(sk2Buf)));
  log(`   ${serverKey}\n`);

  // 8) serverSignature = HMAC(serverKey, authMessage)
  log("8) serverSignature = HMAC_SHA256(serverKey, authMessage):");
  const srvKey = Uint8Array.from(atob(serverKey), (c) => c.charCodeAt(0));
  const srvKeyObj = await crypto.subtle.importKey(
    "raw",
    srvKey,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const ssBuf = await crypto.subtle.sign(
    "HMAC",
    srvKeyObj,
    enc.encode(authMessage),
  );
  const serverSignature = btoa(String.fromCharCode(...new Uint8Array(ssBuf)));
  log(`   ${serverSignature}\n`);

  // 9) POST /auth/start
  log("\n9) POST /auth/start →");
  let start = await fetch("/auth/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: user, clientNonce: cnonce }),
  });
  let sd = await start.json();
  log(`   salt:         ${sd.salt}`);
  log(`   serverNonce:  ${sd.serverNonce}`);
  log(`   combinedNonce:${sd.combinedNonce}\n`);

  // 10) POST /auth/finish
  log("10) POST /auth/finish →");
  let finish = await fetch("/auth/finish", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: user, clientProof }),
  });
  if (!finish.ok) {
    log(`   ERROR: ${await finish.text()}`);
  } else {
    let fd = await finish.json();
    log(`   message:         ${fd.message}`);
    log(`   serverSignature: ${fd.serverSignature}`);
  }

  log("\n🏁 Demo complete.");
}
