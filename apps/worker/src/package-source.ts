import { access, mkdir, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import type { AcquiredPackage, PackageManifest, PackageAcquisitionService, WorkerScanRequest } from "./types";

const execFileAsync = promisify(execFile);

async function fileExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
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
      await execFileAsync("tar", ["-xzf", tarballPath, "-C", extractDir]);

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

