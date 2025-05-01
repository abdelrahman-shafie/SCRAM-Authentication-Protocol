// scram-auth/app.js
const express = require("express");
const path = require("path");
const bodyParser = require("body-parser");
const { generateSalt, generateNonce, hi, hmac, hash, xor } = require("./scram");
const db = require("./db");

const app = express();
const ITERATIONS = 4096;

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));

// 1. Registration endpoint
app.post("/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send("Missing fields");

  const salt = generateSalt();
  const saltedPassword = hi(password, salt, ITERATIONS);

  const clientKey = hmac(saltedPassword, "Client Key");
  const storedKey = hash(clientKey);
  const serverKey = hmac(saltedPassword, "Server Key");

  db.saveUser(username, { salt, storedKey, serverKey, iterations: ITERATIONS });
  res.send("User registered");
});

// 2. Start authentication (client → server)
app.post("/auth/start", (req, res) => {
  const { username, clientNonce } = req.body;
  const user = db.getUser(username);
  if (!user) return res.status(404).send("User not found");

  const serverNonce = generateNonce();
  const combinedNonce = clientNonce + serverNonce;

  // save the nonces for this user session
  db.saveUser(username, { ...user, clientNonce, serverNonce, combinedNonce });

  res.json({
    salt: user.salt,
    iterations: user.iterations,
    serverNonce,
    combinedNonce,
  });
});

// 3. Finish authentication (client proof → server)
app.post("/auth/finish", (req, res) => {
  const { username, clientProof } = req.body;
  const user = db.getUser(username);
  if (!user) return res.status(404).send("User not found");

  const authMessage =
    `n=${username},r=${user.clientNonce}` +
    `,s=${user.salt},i=${user.iterations}` +
    `,r=${user.combinedNonce}`;

  // verify client proof
  const clientProofBuf = Buffer.from(clientProof, "base64");
  const clientSignature = hmac(user.storedKey, authMessage);
  const clientKey = xor(clientProofBuf, clientSignature);
  const computedStoredKey = hash(clientKey);

  if (!computedStoredKey.equals(user.storedKey)) {
    return res.status(401).send("Authentication failed");
  }

  // generate server signature
  const serverSignature = hmac(user.serverKey, authMessage);
  res.json({
    message: "Authenticated",
    serverSignature: serverSignature.toString("base64"),
  });
});

app.listen(3000, () => {
  console.log("SCRAM server running at http://localhost:3000");
});
