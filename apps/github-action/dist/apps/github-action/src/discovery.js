import { readFile } from "node:fs/promises";
import path from "node:path";
const nativeNameHints = [
    "sharp",
    "bcrypt",
    "sqlite3",
    "canvas",
    "node-sass",
    "better-sqlite3",
    "argon2",
    "isolated-vm",
    "ffi-napi",
    "node-gyp"
];
function isNativeCandidate(name, entry) {
    if (entry.hasInstallScript || entry.gypfile || entry.optional || (entry.cpu?.length ?? 0) > 0 || (entry.os?.length ?? 0) > 0) {
        return true;
    }
    if (entry.bin) {
        return true;
    }
    return nativeNameHints.some((hint) => name === hint || name.startsWith(`${hint}-`) || name.includes(`/${hint}`));
}
function packageNameFromPath(packagePath) {
    const segments = packagePath.split("node_modules/").filter(Boolean);
    return segments[segments.length - 1] ?? "";
}
function collectFromPackagesMap(lockPackages, scanMode, includeDevDependencies) {
    const targets = [];
    for (const [packagePath, entry] of Object.entries(lockPackages)) {
        if (!packagePath.startsWith("node_modules/") || !entry.version) {
            continue;
        }
        if (!includeDevDependencies && entry.dev) {
            continue;
        }
        const name = entry.name ?? packageNameFromPath(packagePath);
        const nativeCandidate = scanMode === "all-dependencies" ? true : isNativeCandidate(name, entry);
        if (scanMode === "native-only" && !nativeCandidate) {
            continue;
        }
        targets.push({
            name,
            version: entry.version,
            path: packagePath,
            source: "lockfile",
            nativeCandidate,
            reason: nativeCandidate ? "heuristic native package" : "dependency"
        });
    }
    return targets.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
}
function collectFromV1Dependencies(dependencies, scanMode, includeDevDependencies, parentPath = "") {
    const targets = [];
    for (const [name, entry] of Object.entries(dependencies ?? {})) {
        if (!includeDevDependencies && entry.dev) {
            continue;
        }
        const packagePath = parentPath ? `${parentPath}/node_modules/${name}` : `node_modules/${name}`;
        const nativeCandidate = scanMode === "all-dependencies" ? true : isNativeCandidate(name, entry);
        if (scanMode === "native-only" && !nativeCandidate) {
            continue;
        }
        if (entry.version) {
            targets.push({
                name,
                version: entry.version,
                path: packagePath,
                source: "lockfile",
                nativeCandidate,
                reason: nativeCandidate ? "heuristic native package" : "dependency"
            });
        }
        if (entry.dependencies) {
            targets.push(...collectFromV1Dependencies(entry.dependencies, scanMode, includeDevDependencies, packagePath));
        }
    }
    return targets;
}
export async function discoverTargets(rootDir, scanMode, includeDevDependencies) {
    const packageJsonPath = path.join(rootDir, "package.json");
    const lockfilePath = path.join(rootDir, "package-lock.json");
    const shrinkwrapPath = path.join(rootDir, "npm-shrinkwrap.json");
    await readFile(packageJsonPath, "utf8");
    let lockfileRaw;
    try {
        lockfileRaw = await readFile(lockfilePath, "utf8");
    }
    catch {
        try {
            lockfileRaw = await readFile(shrinkwrapPath, "utf8");
        }
        catch {
            lockfileRaw = undefined;
        }
    }
    if (!lockfileRaw) {
        return [];
    }
    const lockfile = JSON.parse(lockfileRaw);
    if (lockfile.packages) {
        return collectFromPackagesMap(lockfile.packages, scanMode, includeDevDependencies);
    }
    return collectFromV1Dependencies(lockfile.dependencies, scanMode, includeDevDependencies);
}
