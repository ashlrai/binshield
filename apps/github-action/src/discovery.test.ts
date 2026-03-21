import { mkdirSync, writeFileSync } from "node:fs";
import { mkdtempSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { discoverTargets } from "./discovery";

function createWorkspace(lockfile: object) {
  const root = mkdtempSync(path.join(os.tmpdir(), "binshield-action-"));
  writeFileSync(
    path.join(root, "package.json"),
    JSON.stringify(
      {
        name: "fixture",
        version: "1.0.0",
        dependencies: {
          bcrypt: "5.1.1",
          lodash: "4.17.21",
          sharp: "0.33.2"
        },
        devDependencies: {
          eslint: "8.57.0"
        }
      },
      null,
      2
    )
  );
  writeFileSync(path.join(root, "package-lock.json"), JSON.stringify(lockfile, null, 2));
  return root;
}

describe("discovery", () => {
  it("discovers native candidates from a v3 lockfile", async () => {
    const root = createWorkspace({
      lockfileVersion: 3,
      packages: {
        "": {
          name: "fixture",
          version: "1.0.0"
        },
        "node_modules/bcrypt": {
          name: "bcrypt",
          version: "5.1.1",
          hasInstallScript: true
        },
        "node_modules/lodash": {
          name: "lodash",
          version: "4.17.21"
        },
        "node_modules/sharp": {
          name: "sharp",
          version: "0.33.2",
          bin: { sharp: "bin.js" }
        },
        "node_modules/eslint": {
          name: "eslint",
          version: "8.57.0",
          dev: true
        }
      }
    });

    const targets = await discoverTargets(root, "native-only", false);
    expect(targets.map((target) => target.name)).toEqual(["bcrypt", "sharp"]);
  });

  it("can include all dependencies when requested", async () => {
    const root = createWorkspace({
      lockfileVersion: 3,
      packages: {
        "": {
          name: "fixture",
          version: "1.0.0"
        },
        "node_modules/bcrypt": {
          name: "bcrypt",
          version: "5.1.1",
          hasInstallScript: true
        },
        "node_modules/lodash": {
          name: "lodash",
          version: "4.17.21"
        }
      }
    });

    const targets = await discoverTargets(root, "all-dependencies", false);
    expect(targets.map((target) => target.name)).toEqual(["bcrypt", "lodash"]);
  });

  it("supports recursive v1 lockfiles", async () => {
    const root = createWorkspace({
      lockfileVersion: 1,
      dependencies: {
        bcrypt: {
          version: "5.1.1",
          hasInstallScript: true,
          dependencies: {
            nan: {
              version: "2.22.0",
              gypfile: true
            }
          }
        },
        lodash: {
          version: "4.17.21"
        }
      }
    });

    const targets = await discoverTargets(root, "native-only", false);
    expect(targets.map((target) => target.name)).toEqual(["bcrypt", "nan"]);
  });
});
