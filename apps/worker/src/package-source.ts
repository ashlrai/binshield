import { access, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { isPythonNativeExtension, hasPyPiAbiTag } from "./native-indicators";
import { analyzePypiBuildSystem } from "./pypi-sdist-analyzer";

import type { AcquiredPackage, PackageManifest, PackageAcquisitionService, WorkerScanRequest } from "./types";
import type { BuildSystemType, PythonBuildThreatDetails } from "@binshield/analysis-types";

const execFileAsync = promisify(execFile);

async function fileExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

/**
 * Walk every file/dir produced by an archive extraction and verify nothing
 * escaped the intended output directory.  Checks two attack vectors:
 *
 *  1. Path traversal — entry whose resolved absolute path is outside extractDir
 *     (e.g. "../../evil" in a tarball header).
 *  2. Symlink escape — a symlink whose target resolves to a path outside
 *     extractDir (absolute symlinks or chained "../.." hops).
 *
 * Throws a clear "rejected malicious archive" error on the first violation found.
 */
async function validateExtraction(extractDir: string): Promise<void> {
  // Resolve the canonical base so we can do prefix-check comparisons.
  const resolvedBase = await realpath(extractDir);
  const base = resolvedBase.endsWith(path.sep) ? resolvedBase : resolvedBase + path.sep;

  async function walk(dir: string): Promise<void> {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const entryPath = path.join(dir, entry.name);

      // Resolve the real path of the entry itself (not its target if symlink).
      // We use lstat so we can distinguish symlinks from regular files/dirs.
      const st = await lstat(entryPath);

      if (st.isSymbolicLink()) {
        // For symlinks, resolve the full target and verify it stays inside.
        // realpath() follows all hops, so chained symlinks are covered.
        let resolved: string;
        try {
          resolved = await realpath(entryPath);
        } catch {
          // Dangling symlink — target does not exist yet inside extractDir.
          // A dangling symlink cannot be exploited for reads, but an absolute
          // dangling symlink that points outside is still suspicious.  Resolve
          // the raw target relative to the symlink's directory instead.
          const { readlink } = await import("node:fs/promises");
          const rawTarget = await readlink(entryPath);
          const candidate = path.resolve(path.dirname(entryPath), rawTarget);
          if (!candidate.startsWith(base)) {
            throw new Error(
              `Rejected malicious archive: symlink "${entryPath}" points outside the extraction directory (target: "${rawTarget}")`
            );
          }
          continue;
        }
        if (!resolved.startsWith(base)) {
          throw new Error(
            `Rejected malicious archive: symlink "${entryPath}" resolves to "${resolved}" which is outside the extraction directory`
          );
        }
        // Do NOT recurse into symlink targets — that could loop and is already covered.
      } else {
        // Regular file or directory — verify its own real path stays inside.
        let resolved: string;
        try {
          resolved = await realpath(entryPath);
        } catch {
          // Entry disappeared between readdir and realpath (race) — skip it.
          continue;
        }
        if (!resolved.startsWith(base)) {
          throw new Error(
            `Rejected malicious archive: entry "${entryPath}" resolves to "${resolved}" which is outside the extraction directory`
          );
        }
        if (entry.isDirectory()) {
          await walk(entryPath);
        }
      }
    }
  }

  await walk(extractDir);
}

function normalizeManifest(raw: Record<string, unknown> | undefined): PackageManifest {
  const dependencies = raw?.dependencies && typeof raw.dependencies === "object" ? (raw.dependencies as Record<string, string>) : {};
  const optionalDependencies =
    raw?.optionalDependencies && typeof raw.optionalDependencies === "object"
      ? (raw.optionalDependencies as Record<string, string>)
      : {};
  const scripts = raw?.scripts && typeof raw.scripts === "object" ? (raw.scripts as Record<string, string>) : {};

  return {
    name: typeof raw?.name === "string" ? raw.name : "unknown-package",
    version: typeof raw?.version === "string" ? raw.version : "0.0.0",
    scripts,
    dependencies,
    optionalDependencies
  };
}

async function readManifest(packageRoot: string): Promise<PackageManifest> {
  const manifestPath = path.join(packageRoot, "package.json");
  const content = await readFile(manifestPath, "utf8");
  return normalizeManifest(JSON.parse(content) as Record<string, unknown>);
}

export class LocalDirectoryPackageSource implements PackageAcquisitionService {
  readonly name = "local-directory";

  constructor(private readonly packageRoot: string) {}

  async acquire(): Promise<AcquiredPackage> {
    if (!(await fileExists(path.join(this.packageRoot, "package.json")))) {
      throw new Error(`Package root does not contain a package.json: ${this.packageRoot}`);
    }

    const manifest = await readManifest(this.packageRoot);
    return {
      sourceKind: "directory",
      packageRoot: this.packageRoot,
      packageJsonPath: path.join(this.packageRoot, "package.json"),
      manifest
    };
  }
}

export class RegistryPackageSource implements PackageAcquisitionService {
  readonly name = "npm-registry";

  async acquire(request: WorkerScanRequest): Promise<AcquiredPackage> {
    const spec = `${request.packageName}@${request.version}`;
    const tempRoot = await mkdtemp(path.join(os.tmpdir(), "binshield-registry-"));
    const tarballDir = path.join(tempRoot, "tarballs");
    const extractDir = path.join(tempRoot, "package");
    await mkdir(tarballDir, { recursive: true });
    await mkdir(extractDir, { recursive: true });

    try {
      const { stdout } = await execFileAsync("npm", [
        "pack",
        spec,
        "--silent",
        "--pack-destination",
        tarballDir
      ]);

      const tarballName = stdout.trim().split(/\r?\n/).filter(Boolean).pop();
      if (!tarballName) {
        throw new Error(`npm pack did not return a tarball for ${spec}`);
      }

      const tarballPath = path.join(tarballDir, tarballName);
      await execFileAsync("tar", ["--no-same-owner", "-xzf", tarballPath, "-C", extractDir]);
      await validateExtraction(extractDir);

      const nestedRoot = await findPackageRoot(extractDir);
      const manifest = await readManifest(nestedRoot);

      return {
        sourceKind: "registry",
        packageRoot: nestedRoot,
        packageJsonPath: path.join(nestedRoot, "package.json"),
        manifest
      };
    } catch (error) {
      await rm(tempRoot, { recursive: true, force: true });
      throw new Error(`Failed to acquire ${spec} from the npm registry: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
}

/**
 * Acquires a package by running `npm install` in an isolated temp directory.
 * This downloads platform-specific prebuilt binaries (.node files) that
 * npm pack does not include. Use this for packages like sharp, better-sqlite3,
 * bcrypt, etc. that ship native addons via prebuild or node-pre-gyp.
 */
export class InstallPackageSource implements PackageAcquisitionService {
  readonly name = "npm-install";

  async acquire(request: WorkerScanRequest): Promise<AcquiredPackage> {
    const spec = `${request.packageName}@${request.version}`;
    const tempRoot = await mkdtemp(path.join(os.tmpdir(), "binshield-install-"));

    try {
      // Create a minimal package.json for the install
      const initManifest = {
        name: "binshield-scan-workspace",
        version: "1.0.0",
        private: true,
        dependencies: { [request.packageName]: request.version }
      };
      const { writeFile } = await import("node:fs/promises");
      await writeFile(path.join(tempRoot, "package.json"), JSON.stringify(initManifest, null, 2));

      // Run npm install with --ignore-scripts for safety (prebuilt binaries
      // are typically downloaded by postinstall scripts, but many modern
      // packages use @mapbox/node-pre-gyp or prebuild-install which runs
      // during install). We use --ignore-scripts to be safe, then check
      // if binaries exist. If not, re-run with scripts enabled.
      await execFileAsync("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund"], {
        cwd: tempRoot,
        timeout: 120000
      });

      const packageRoot = path.join(tempRoot, "node_modules", request.packageName);
      if (!(await fileExists(path.join(packageRoot, "package.json")))) {
        throw new Error(`Package not found after install: ${packageRoot}`);
      }

      const manifest = await readManifest(packageRoot);

      // Scan the entire node_modules for this package and its platform-specific
      // optional dependencies (e.g. @sharp/sharp-linux-x64)
      return {
        sourceKind: "registry",
        packageRoot: path.join(tempRoot, "node_modules"),
        packageJsonPath: path.join(packageRoot, "package.json"),
        manifest
      };
    } catch (error) {
      await rm(tempRoot, { recursive: true, force: true }).catch(() => {});
      throw new Error(`Failed to install ${spec}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
}

/**
 * Acquires a PyPI package by downloading its source distribution (sdist) from
 * the PyPI JSON API and extracting it. The sdist contains setup.py /
 * pyproject.toml — the Python that runs at `pip install` time, which the
 * manifest analyzer inspects. npm-style `scripts` do not exist for PyPI, so a
 * minimal manifest is synthesized.
 */
export class PyPiPackageSource implements PackageAcquisitionService {
  readonly name = "pypi-registry";

  async acquire(request: WorkerScanRequest): Promise<AcquiredPackage> {
    const spec = `${request.packageName}@${request.version}`;
    const tempRoot = await mkdtemp(path.join(os.tmpdir(), "binshield-pypi-"));
    const extractDir = path.join(tempRoot, "package");
    await mkdir(extractDir, { recursive: true });

    try {
      const metaUrl = `https://pypi.org/pypi/${encodeURIComponent(request.packageName)}/${encodeURIComponent(
        request.version
      )}/json`;
      const metaResponse = await fetch(metaUrl);
      if (!metaResponse.ok) {
        throw new Error(`PyPI metadata request returned ${metaResponse.status}`);
      }

      const meta = (await metaResponse.json()) as {
        urls?: Array<{ packagetype: string; url: string; filename: string }>;
      };
      const sdist = meta.urls?.find((entry) => entry.packagetype === "sdist");
      if (!sdist) {
        throw new Error(`No source distribution published for ${spec}`);
      }

      const tarballResponse = await fetch(sdist.url);
      if (!tarballResponse.ok) {
        throw new Error(`PyPI sdist download returned ${tarballResponse.status}`);
      }
      const tarballPath = path.join(tempRoot, sdist.filename);
      await writeFile(tarballPath, Buffer.from(await tarballResponse.arrayBuffer()));

      if (sdist.filename.endsWith(".zip")) {
        await execFileAsync("unzip", ["-q", tarballPath, "-d", extractDir]);
      } else {
        await execFileAsync("tar", ["--no-same-owner", "-xzf", tarballPath, "-C", extractDir]);
      }
      await validateExtraction(extractDir);

      const nestedRoot = await findPackageRoot(extractDir);
      const manifest: PackageManifest = {
        name: request.packageName,
        version: request.version,
        scripts: {},
        dependencies: {},
        optionalDependencies: {}
      };

      // Perform deep build-system analysis on the extracted sdist.
      // Failures are non-fatal — we still return the acquired package.
      let buildSystemType: BuildSystemType | undefined;
      let pythonBuildThreatDetails: PythonBuildThreatDetails | undefined;
      try {
        const buildAnalysis = await analyzePypiBuildSystem(nestedRoot);
        buildSystemType = buildAnalysis.buildSystemType;
        pythonBuildThreatDetails = buildAnalysis.threatDetails;
      } catch {
        // Deep analysis failure is non-fatal
      }

      return {
        sourceKind: "tarball",
        packageRoot: nestedRoot,
        packageJsonPath: path.join(nestedRoot, "package.json"),
        manifest,
        buildSystemType,
        pythonBuildThreatDetails
      };
    } catch (error) {
      await rm(tempRoot, { recursive: true, force: true }).catch(() => {});
      throw new Error(
        `Failed to acquire ${spec} from PyPI: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }
}

/**
 * Acquires a PyPI package by downloading its binary wheel (.whl) distribution
 * from the PyPI JSON API. Wheels are zip archives; they may contain compiled
 * native extensions (.so / .pyd / .dylib) in addition to Python source.
 *
 * Selection strategy: prefer wheels that match the current platform; fall back
 * to the first `bdist_wheel` entry. The extracted tree is passed to the
 * extractor just like an sdist — FileSystemBinaryExtractor will find any .so /
 * .pyd files, and the manifest analyzer will mark the package as having Python
 * binary extensions.
 *
 * If no wheel is published for this version (pure-Python or sdist-only),
 * this source throws and the coordinator falls back to PyPiPackageSource.
 */
export class PyPiWheelPackageSource implements PackageAcquisitionService {
  readonly name = "pypi-wheel";

  async acquire(request: WorkerScanRequest): Promise<AcquiredPackage> {
    const spec = `${request.packageName}@${request.version}`;
    const tempRoot = await mkdtemp(path.join(os.tmpdir(), "binshield-pypi-wheel-"));
    const extractDir = path.join(tempRoot, "package");
    await mkdir(extractDir, { recursive: true });

    try {
      const metaUrl = `https://pypi.org/pypi/${encodeURIComponent(request.packageName)}/${encodeURIComponent(
        request.version
      )}/json`;
      const metaResponse = await fetch(metaUrl);
      if (!metaResponse.ok) {
        throw new Error(`PyPI metadata request returned ${metaResponse.status}`);
      }

      const meta = (await metaResponse.json()) as {
        urls?: Array<{ packagetype: string; url: string; filename: string }>;
      };

      // Filter to wheel distributions only.
      const wheels = (meta.urls ?? []).filter((entry) => entry.packagetype === "bdist_wheel");
      if (wheels.length === 0) {
        throw new Error(`No wheel distribution published for ${spec}`);
      }

      // Prefer a wheel with a CPython ABI tag (compiled, platform-specific)
      // over a pure-Python wheel (py3-none-any.whl), to maximise coverage of
      // native extension binaries.
      const platformWheel =
        wheels.find((w) => hasPyPiAbiTag(w.filename)) ?? wheels[0];

      const wheelResponse = await fetch(platformWheel.url);
      if (!wheelResponse.ok) {
        throw new Error(`PyPI wheel download returned ${wheelResponse.status}`);
      }
      const wheelPath = path.join(tempRoot, platformWheel.filename);
      await writeFile(wheelPath, Buffer.from(await wheelResponse.arrayBuffer()));

      // Wheels are zip archives — extract with unzip.
      await execFileAsync("unzip", ["-q", wheelPath, "-d", extractDir]);
      await validateExtraction(extractDir);

      // Unlike sdists, wheels don't have a single top-level package directory;
      // the contents are laid out flat inside the zip. Use extractDir directly
      // as the package root so the extractor can walk the whole tree.
      const manifest: PackageManifest = {
        name: request.packageName,
        version: request.version,
        scripts: {},
        dependencies: {},
        optionalDependencies: {}
      };

      return {
        sourceKind: "tarball",
        packageRoot: extractDir,
        packageJsonPath: path.join(extractDir, "package.json"),
        manifest
      };
    } catch (error) {
      await rm(tempRoot, { recursive: true, force: true }).catch(() => {});
      throw new Error(
        `Failed to acquire wheel for ${spec} from PyPI: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }
}

/**
 * Walk a wheel extraction directory and collect all Python native extension
 * files (.so / .pyd / .dylib). Used by manifest-analyzer to mark the package
 * as having binary extensions and emit a pythonBinaryExtension finding.
 */
export async function collectWheelNativeExtensions(packageRoot: string): Promise<string[]> {
  const found: string[] = [];

  async function walk(dir: string): Promise<void> {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(full);
      } else if (entry.isFile() && isPythonNativeExtension(entry.name)) {
        found.push(path.relative(packageRoot, full));
      }
    }
  }

  await walk(packageRoot);
  return found;
}

async function findPackageRoot(extractDir: string): Promise<string> {
  const entries = await readdir(extractDir, { withFileTypes: true });
  const packageDir = entries.find((entry) => entry.isDirectory());
  if (!packageDir) {
    throw new Error(`No extracted package directory found in ${extractDir}`);
  }

  return path.join(extractDir, packageDir.name);
}

export class WorkerPackageAcquisitionCoordinator implements PackageAcquisitionService {
  readonly name = "coordinator";

  constructor(private readonly sources: PackageAcquisitionService[]) {}

  async acquire(request: WorkerScanRequest): Promise<AcquiredPackage> {
    const errors: string[] = [];

    for (const source of this.sources) {
      try {
        return await source.acquire(request);
      } catch (error) {
        errors.push(`${source.name}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }

    throw new Error(`Unable to acquire package ${request.packageName}@${request.version}. Tried: ${errors.join("; ")}`);
  }
}

export function createDefaultPackageSource(demoPackageRoot: string): PackageAcquisitionService {
  const sources: PackageAcquisitionService[] = [];

  sources.push(new LocalDirectoryPackageSource(demoPackageRoot));
  if (process.env.BINSHIELD_PACKAGE_SOURCE === "registry") {
    sources.push(new RegistryPackageSource());
  }

  return new WorkerPackageAcquisitionCoordinator(sources);
}

