// scram-auth/db.js
const users = {}; // in‑memory store

module.exports = {
  getUser: (username) => users[username],
  saveUser: (username, data) => {
    users[username] = data;
  },
};
