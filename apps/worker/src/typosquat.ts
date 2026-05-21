/**
 * Typosquatting detection for npm package names.
 *
 * Compares a candidate package name against a curated list of the most
 * popular npm packages using Levenshtein edit-distance (hand-rolled, no
 * external deps). Packages within edit-distance 1–2 of a popular name, but
 * not that name itself, emit a `dependencyConfusion` ScriptFinding.
 *
 * Also catches common squatting tricks independent of edit-distance:
 *   - Scope stripping (@org/pkg → pkg)
 *   - Hyphen/dot/underscore swaps (lodash → lo-dash, lo.dash)
 *   - Common character substitutions (0→o, 1→l, rn→m, vv→w, etc.)
 */

import type { ScriptFinding } from "@binshield/analysis-types";

// ---------------------------------------------------------------------------
// Popular package list — ~200 of the most-downloaded npm packages
// ---------------------------------------------------------------------------

export const POPULAR_PACKAGES: ReadonlySet<string> = new Set([
  // Core runtime / utils
  "lodash", "underscore", "ramda", "rxjs", "immer", "date-fns", "moment", "dayjs",
  "luxon", "uuid", "nanoid", "cuid", "short-uuid", "hashids",
  // Node fundamentals
  "chalk", "colors", "ansi-colors", "kleur", "yargs", "commander", "minimist",
  "meow", "caporal", "oclif", "enquirer", "inquirer", "prompts", "ora", "listr",
  "boxen", "figlet", "gradient-string", "log-symbols", "strip-ansi", "ansi-regex",
  "string-width", "wrap-ansi", "supports-color", "is-ci",
  // File / path
  "glob", "globby", "fast-glob", "micromatch", "picomatch", "minimatch", "chokidar",
  "fs-extra", "del", "rimraf", "mkdirp", "make-dir", "move-file", "copy-dir",
  "find-up", "pkg-dir", "read-pkg", "write-pkg", "load-json-file", "write-json-file",
  "tempy", "temp", "tmp",
  // HTTP / network
  "axios", "got", "node-fetch", "superagent", "request", "needle", "undici",
  "cross-fetch", "isomorphic-fetch", "ky", "wretch", "httpie",
  "ws", "socket.io", "socket.io-client", "sockjs", "sockjs-client",
  // Parsing / serialization
  "yaml", "js-yaml", "toml", "ini", "dotenv", "dotenv-expand",
  "csv-parse", "csv-stringify", "papaparse", "fast-csv",
  "xml2js", "xml-js", "htmlparser2", "cheerio", "jsdom", "parse5",
  "marked", "markdown-it", "remark", "unified",
  "semver", "compare-versions",
  // Schema / validation
  "ajv", "joi", "yup", "zod", "superstruct", "valibot", "typebox",
  "class-validator", "class-transformer",
  // Crypto / security
  "bcrypt", "bcryptjs", "argon2", "crypto-js", "node-rsa", "jsrsasign",
  "jsonwebtoken", "jose", "jwks-rsa",
  // Build tooling (native addons that run node-gyp)
  "node-gyp", "prebuild", "prebuild-install", "node-pre-gyp",
  "bindings", "nan", "node-addon-api",
  // Compression
  "archiver", "extract-zip", "decompress", "tar", "tar-stream", "tar-fs",
  "adm-zip", "jszip", "fflate", "pako",
  // Database / ORM
  "mongoose", "pg", "mysql", "mysql2", "sqlite3", "better-sqlite3",
  "redis", "ioredis", "knex", "sequelize", "typeorm", "prisma",
  "mongodb", "cassandra-driver", "couchdb",
  // Testing
  "jest", "vitest", "mocha", "jasmine", "ava", "tape", "tap", "qunit",
  "chai", "sinon", "nock", "supertest", "playwright", "puppeteer", "cypress",
  // Bundlers / compilers
  "webpack", "rollup", "esbuild", "vite", "parcel", "browserify", "snowpack",
  "babel", "@babel/core", "typescript", "ts-node", "tsx",
  "postcss", "sass", "less", "stylus",
  // Frameworks
  "express", "fastify", "koa", "hapi", "restify", "polka", "micro",
  "next", "nuxt", "gatsby", "astro", "remix", "sveltekit",
  "react", "react-dom", "react-router", "react-query",
  "vue", "vuex", "pinia", "angular",
  "svelte", "lit", "preact", "solid-js",
  // Linting / formatting
  "eslint", "prettier", "stylelint", "tslint", "jshint",
  "husky", "lint-staged", "commitizen", "standard",
  // Monorepo / package management helpers
  "lerna", "nx", "turborepo", "changesets",
  // Misc popular utilities
  "cross-env", "cross-spawn", "execa", "shelljs",
  "debug", "morgan", "winston", "pino", "bunyan",
  "qs", "querystring", "form-data", "multiparty", "busboy",
  "mime", "mime-types", "content-type",
  "classnames", "clsx",
  "deepmerge", "merge", "defaults-deep",
  "retry", "async-retry", "p-retry", "p-limit", "p-queue", "p-map",
  "eventemitter3", "mitt", "tiny-emitter",
  "ms", "pretty-ms", "human-readable-duration",
  "bytes", "filesize", "numeral",
  "slugify", "speakingurl", "limax",
  "camelcase", "snakecase", "kebabcase", "start-case",
  "escape-html", "entities", "he", "htmlencode",
  "validator", "is-url", "is-email", "valid-url",
  "object-path", "dot-prop", "lodash.get", "lodash.set",
  "diff", "diff-match-patch", "jsdiff",
  "natural", "fuse.js", "lunr",
  "mathjs", "decimal.js", "big.js", "fraction.js"
]);

// ---------------------------------------------------------------------------
// Levenshtein edit-distance (hand-rolled, no external deps)
// ---------------------------------------------------------------------------

/**
 * Classic Wagner–Fischer dynamic programming Levenshtein implementation.
 * Returns the minimum number of single-character edits (insert/delete/substitute)
 * to transform `a` into `b`. O(|a| × |b|) time, O(|b|) space.
 *
 * Early-exit when the running minimum exceeds `threshold` to keep it fast for
 * the long popular-packages list.
 */
export function levenshtein(a: string, b: string, threshold = 2): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > threshold) return threshold + 1;

  // Keep two rows of the DP matrix.
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  let curr = new Array<number>(b.length + 1);

  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    let rowMin = i;

    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        curr[j - 1] + 1,       // insert
        prev[j] + 1,           // delete
        prev[j - 1] + cost     // substitute
      );
      if (curr[j] < rowMin) rowMin = curr[j];
    }

    // Early-exit: entire row is beyond threshold
    if (rowMin > threshold) return threshold + 1;

    [prev, curr] = [curr, prev];
  }

  return prev[b.length];
}

// ---------------------------------------------------------------------------
// Canonicalization helpers
// ---------------------------------------------------------------------------

/**
 * Return the "bare" name: strip any npm scope (@org/), then normalise
 * separators (-, _, .) to empty string for fuzzy comparison.
 */
function bare(name: string): string {
  return name
    .replace(/^@[^/]+\//, "") // strip @scope/
    .toLowerCase();
}

/**
 * Collapse separator characters so "lo-dash", "lo_dash", "lo.dash" all
 * compare equal to "lodash" in the separator-variation check.
 */
function collapseSeparators(name: string): string {
  return name.replace(/[-_.]/g, "");
}

/** Apply common visual substitutions used by squatters. */
function normaliseVisual(name: string): string {
  return name
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/rn/g, "m")
    .replace(/vv/g, "w")
    .replace(/cl/g, "d")
    .replace(/nn/g, "m");
}

// ---------------------------------------------------------------------------
// Public detection API
// ---------------------------------------------------------------------------

export interface TyposquatMatch {
  candidate: string;
  target: string;
  distance: number;
  trick: string;
}

/**
 * Return the closest popular-package match for `candidate`, or `null` if
 * no suspicious similarity is found.
 *
 * Detection strategies (in priority order):
 *  1. Exact match → not a typosquat (it IS a popular package).
 *  2. Scope-strip match: @evil/lodash → lodash.
 *  3. Separator collapse: lo-dash, lo_dash, lo.dash → lodash.
 *  4. Visual substitution on collapsed form.
 *  5. Levenshtein distance 1–2 on the bare name.
 */
export function findTyposquatMatch(candidate: string): TyposquatMatch | null {
  if (!candidate || typeof candidate !== "string") return null;

  const lc = candidate.toLowerCase();

  // 1. Exact match — not a typosquat
  if (POPULAR_PACKAGES.has(lc)) return null;

  const bareName = bare(lc);

  // Require a minimum length to avoid matching empty/trivial names against
  // very short popular packages like "ky", "ms", etc.
  if (bareName.length < 3) return null;

  // 2. Scope-strip: @org/lodash → "lodash"
  if (lc !== bareName && POPULAR_PACKAGES.has(bareName)) {
    return { candidate, target: bareName, distance: 0, trick: "scope-strip" };
  }

  const collapsed = collapseSeparators(bareName);
  const visualCollapsed = normaliseVisual(collapsed);

  let bestDist = Infinity;
  let bestTarget = "";
  let bestTrick = "";

  for (const popular of POPULAR_PACKAGES) {
    const popularBare = bare(popular);

    // 3. Separator collapse match
    if (collapsed !== collapseSeparators(popularBare) && collapsed === collapseSeparators(popularBare)) {
      return { candidate, target: popular, distance: 0, trick: "separator-variation" };
    }
    if (collapseSeparators(bareName) === collapseSeparators(popularBare) && bareName !== popularBare) {
      return { candidate, target: popular, distance: 0, trick: "separator-variation" };
    }

    // 4. Visual substitution
    if (visualCollapsed === normaliseVisual(collapseSeparators(popularBare)) && bareName !== popularBare) {
      return { candidate, target: popular, distance: 0, trick: "visual-substitution" };
    }

    // 5. Levenshtein on bare names — only consider if length is plausible
    if (Math.abs(bareName.length - popularBare.length) <= 2) {
      const d = levenshtein(bareName, popularBare, 2);
      if (d > 0 && d <= 2 && d < bestDist) {
        bestDist = d;
        bestTarget = popular;
        bestTrick = `edit-distance-${d}`;
      }
    }
  }

  if (bestDist <= 2) {
    return { candidate, target: bestTarget, distance: bestDist, trick: bestTrick };
  }

  return null;
}

/**
 * Analyse a package name for typosquatting and return a `ScriptFinding` when
 * a suspicious match is found, or `null` otherwise.
 *
 * The finding uses `category: "dependencyConfusion"` (the closest existing
 * category for name-based impersonation attacks) with `severity: "high"`.
 */
export function detectTyposquat(packageName: string): ScriptFinding | null {
  if (!packageName || typeof packageName !== "string") return null;

  const match = findTyposquatMatch(packageName);
  if (!match) return null;

  const trickLabel: Record<string, string> = {
    "scope-strip": "scoped-package impersonation",
    "separator-variation": "separator swap (hyphen/dot/underscore variation)",
    "visual-substitution": "visual character substitution (0→o, rn→m, etc.)",
    "edit-distance-1": "1-character edit (insert/delete/substitute)",
    "edit-distance-2": "2-character edit (insert/delete/substitute)"
  };
  const humanTrick = trickLabel[match.trick] ?? match.trick;

  return {
    category: "dependencyConfusion",
    severity: "high",
    title: `Possible typosquat of \`${match.target}\``,
    description:
      `Package name \`${packageName}\` closely resembles the popular package \`${match.target}\` ` +
      `(${humanTrick}). This is a common supply-chain attack technique where an attacker ` +
      `publishes a malicious package under a confusingly similar name to intercept installations.`,
    filePath: "package.json#name",
    evidence: `"${packageName}" vs "${match.target}" (${match.trick})`,
    recommendation:
      `Verify you intended to install \`${match.target}\` and not \`${packageName}\`. ` +
      `If this package was found unexpectedly in a lockfile or dependency tree, treat it as potentially malicious.`
  };
}
