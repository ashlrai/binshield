export const emptyBehaviorSummary = () => ({
    network: { detected: false, details: [] },
    filesystem: { detected: false, details: [] },
    process: { detected: false, details: [] },
    crypto: { detected: false, details: [] },
    obfuscation: { detected: false, details: [] },
    dataExfiltration: { detected: false, details: [] }
});
export const emptyScriptThreatSummary = () => ({
    installHook: { detected: false, details: [] },
    scriptInjection: { detected: false, details: [] },
    environmentTheft: { detected: false, details: [] },
    dependencyConfusion: { detected: false, details: [] },
    wiper: { detected: false, details: [] },
    reverseShell: { detected: false, details: [] },
    remoteCodeExecution: { detected: false, details: [] }
});
export function entitlementForPlan(plan) {
    switch (plan) {
        case "enterprise":
            return {
                canManageBilling: true,
                canCreateApiKeys: true,
                canUseWatchlists: true,
                maxRepos: 1000,
                maxMonthlyScans: 100000
            };
        case "team":
            return {
                canManageBilling: true,
                canCreateApiKeys: true,
                canUseWatchlists: true,
                maxRepos: 50,
                maxMonthlyScans: 10000
            };
        case "pro":
            return {
                canManageBilling: true,
                canCreateApiKeys: true,
                canUseWatchlists: true,
                maxRepos: 25,
                maxMonthlyScans: 2500
            };
        case "free":
        default:
            return {
                canManageBilling: false,
                canCreateApiKeys: true,
                canUseWatchlists: false,
                maxRepos: 3,
                maxMonthlyScans: 50
            };
    }
}
const bcrypt510Behaviors = emptyBehaviorSummary();
bcrypt510Behaviors.filesystem = {
    detected: true,
    details: ["Reads /dev/urandom for entropy."]
};
bcrypt510Behaviors.crypto = {
    detected: true,
    details: ["Uses OpenSSL EVP routines for hashing."]
};
const bcrypt511Behaviors = emptyBehaviorSummary();
bcrypt511Behaviors.filesystem = {
    detected: true,
    details: ["Reads /dev/urandom for entropy and salts."]
};
bcrypt511Behaviors.crypto = {
    detected: true,
    details: ["Uses OpenSSL EVP routines for hashing and key stretching."]
};
const sharp0331Behaviors = emptyBehaviorSummary();
sharp0331Behaviors.filesystem = {
    detected: true,
    details: ["Reads temporary image buffers and system entropy sources."]
};
const sharp0332Behaviors = emptyBehaviorSummary();
sharp0332Behaviors.filesystem = {
    detected: true,
    details: ["Reads temporary image buffers and system entropy sources."]
};
sharp0332Behaviors.process = {
    detected: true,
    details: ["Spawns a helper process when falling back to system codecs."]
};
const sqlite516Behaviors = emptyBehaviorSummary();
sqlite516Behaviors.filesystem = {
    detected: true,
    details: ["Opens database files and journal files on disk."]
};
const sqlite517Behaviors = emptyBehaviorSummary();
sqlite517Behaviors.filesystem = {
    detected: true,
    details: ["Opens database files, journal files, and extension paths on disk."]
};
sqlite517Behaviors.process = {
    detected: true,
    details: ["Performs guarded extension loading before execution."]
};
const canvas2112Behaviors = emptyBehaviorSummary();
canvas2112Behaviors.filesystem = {
    detected: true,
    details: ["Reads font files, image assets, and temporary render surfaces."]
};
canvas2112Behaviors.process = {
    detected: true,
    details: ["Invokes image rendering helpers when hardware acceleration is unavailable."]
};
const argon2411Behaviors = emptyBehaviorSummary();
argon2411Behaviors.filesystem = {
    detected: true,
    details: ["Reads /dev/urandom for password hashing salt generation."]
};
argon2411Behaviors.crypto = {
    detected: true,
    details: ["Uses Argon2 memory-hard hashing primitives."]
};
export const sampleAnalyses = [
    {
        id: "pkg_bcrypt_5_1_0",
        ecosystem: "npm",
        packageName: "bcrypt",
        version: "5.1.0",
        status: "complete",
        riskScore: 11,
        riskLevel: "low",
        summary: "Standard bcrypt native addon with entropy access and no suspicious network activity.",
        sourceMatchConfidence: "high",
        binaryCount: 1,
        totalBinarySize: 194820,
        aiModel: "claude-sonnet",
        createdAt: "2026-03-20T12:00:00.000Z",
        updatedAt: "2026-03-20T12:00:00.000Z",
        binaries: [
            {
                id: "bin_bcrypt_lib_510",
                filename: "bcrypt_lib.node",
                architecture: "x86_64",
                format: "ELF",
                fileSize: 194820,
                functionCount: 41,
                importCount: 16,
                riskScore: 11,
                riskLevel: "low",
                decompiledPreview: "int bcrypt_hash(...) { /* native hashing flow */ }",
                aiExplanation: "The binary performs native password hashing and seed generation using expected runtime libraries.",
                imports: ["EVP_sha512", "uv_queue_work", "node_module_register"],
                strings: ["/dev/urandom", "Invalid salt version"],
                fingerprint: {
                    sha256: "sha256-bcrypt-510",
                    packageVersionKey: "npm:bcrypt@5.1.0",
                    binaryKey: "bcrypt_lib.node"
                },
                behaviors: bcrypt510Behaviors,
                findings: [
                    {
                        severity: "info",
                        title: "Entropy source access",
                        description: "Reads system entropy for password hashing.",
                        location: "bcrypt_gensalt",
                        recommendation: "No action needed."
                    }
                ]
            }
        ]
    },
    {
        id: "pkg_bcrypt_5_1_1",
        ecosystem: "npm",
        packageName: "bcrypt",
        version: "5.1.1",
        status: "complete",
        riskScore: 12,
        riskLevel: "low",
        summary: "Standard bcrypt native addon with expected entropy access and no suspicious network activity.",
        sourceMatchConfidence: "high",
        binaryCount: 1,
        totalBinarySize: 198451,
        aiModel: "claude-sonnet",
        createdAt: "2026-03-21T12:00:00.000Z",
        updatedAt: "2026-03-21T12:00:00.000Z",
        binaries: [
            {
                id: "bin_bcrypt_lib_511",
                filename: "bcrypt_lib.node",
                architecture: "x86_64",
                format: "ELF",
                fileSize: 198451,
                functionCount: 43,
                importCount: 17,
                riskScore: 12,
                riskLevel: "low",
                decompiledPreview: "int bcrypt_hash(...) { /* native hashing flow */ }",
                aiExplanation: "The binary performs native password hashing and seed generation using expected runtime libraries.",
                imports: ["EVP_sha512", "uv_queue_work", "node_module_register"],
                strings: ["/dev/urandom", "Invalid salt version"],
                fingerprint: {
                    sha256: "sha256-bcrypt-511",
                    packageVersionKey: "npm:bcrypt@5.1.1",
                    binaryKey: "bcrypt_lib.node"
                },
                behaviors: bcrypt511Behaviors,
                findings: [
                    {
                        severity: "info",
                        title: "Entropy source access",
                        description: "Reads system entropy for password hashing.",
                        location: "bcrypt_gensalt",
                        recommendation: "No action needed."
                    }
                ]
            }
        ]
    },
    {
        id: "pkg_sharp_0_33_1",
        ecosystem: "npm",
        packageName: "sharp",
        version: "0.33.1",
        status: "complete",
        riskScore: 7,
        riskLevel: "low",
        summary: "Image processing addon with expected filesystem operations and no outbound network behavior.",
        sourceMatchConfidence: "high",
        binaryCount: 2,
        totalBinarySize: 702130,
        aiModel: "claude-sonnet",
        createdAt: "2026-03-20T12:00:00.000Z",
        updatedAt: "2026-03-20T12:00:00.000Z",
        binaries: [
            {
                id: "bin_sharp_linux_x64_331",
                filename: "sharp-linux-x64.node",
                architecture: "x86_64",
                format: "ELF",
                fileSize: 612845,
                functionCount: 87,
                importCount: 30,
                riskScore: 7,
                riskLevel: "low",
                decompiledPreview: "void process_image(...) { /* libvips wrapper */ }",
                aiExplanation: "The binary wraps libvips routines for image transforms and disk-backed image IO.",
                imports: ["vips_resize", "vips_jpegsave", "napi_create_function"],
                strings: ["/tmp", "Unsupported image format"],
                fingerprint: {
                    sha256: "sha256-sharp-0331-node",
                    packageVersionKey: "npm:sharp@0.33.1",
                    binaryKey: "sharp-linux-x64.node"
                },
                behaviors: sharp0331Behaviors,
                findings: [
                    {
                        severity: "info",
                        title: "Temporary file access",
                        description: "Uses temp files during image processing operations.",
                        location: "process_image",
                        recommendation: "Validate temp directory policies in hardened environments."
                    }
                ]
            },
            {
                id: "bin_sharp_vips_331",
                filename: "vendor/libvips.so",
                architecture: "x86_64",
                format: "ELF",
                fileSize: 89285,
                functionCount: 31,
                importCount: 14,
                riskScore: 5,
                riskLevel: "low",
                decompiledPreview: "int vips_entry(...) { /* image codec helper */ }",
                aiExplanation: "The helper shared library provides codec and resize primitives used by the addon.",
                imports: ["vips_init", "vips_image_new", "vips_error_buffer_copy"],
                strings: ["libvips", "image buffer"],
                fingerprint: {
                    sha256: "sha256-sharp-0331-vips",
                    packageVersionKey: "npm:sharp@0.33.1",
                    binaryKey: "vendor/libvips.so"
                },
                behaviors: {
                    ...sharp0331Behaviors,
                    crypto: { detected: false, details: [] }
                },
                findings: []
            }
        ]
    },
    {
        id: "pkg_sharp_0_33_2",
        ecosystem: "npm",
        packageName: "sharp",
        version: "0.33.2",
        status: "complete",
        riskScore: 8,
        riskLevel: "low",
        summary: "Image processing addon with expected filesystem and memory operations, plus a helper path guarded by process spawning.",
        sourceMatchConfidence: "high",
        binaryCount: 2,
        totalBinarySize: 718510,
        aiModel: "claude-sonnet",
        createdAt: "2026-03-21T12:00:00.000Z",
        updatedAt: "2026-03-21T12:00:00.000Z",
        binaries: [
            {
                id: "bin_sharp_linux_x64_332",
                filename: "sharp-linux-x64.node",
                architecture: "x86_64",
                format: "ELF",
                fileSize: 620145,
                functionCount: 91,
                importCount: 31,
                riskScore: 8,
                riskLevel: "low",
                decompiledPreview: "void process_image(...) { /* libvips wrapper */ }",
                aiExplanation: "The binary wraps libvips routines for image transforms and disk-backed image IO.",
                imports: ["vips_resize", "vips_jpegsave", "napi_create_function"],
                strings: ["/tmp", "Unsupported image format", "vips"],
                fingerprint: {
                    sha256: "sha256-sharp-0332-node",
                    packageVersionKey: "npm:sharp@0.33.2",
                    binaryKey: "sharp-linux-x64.node"
                },
                behaviors: sharp0332Behaviors,
                findings: [
                    {
                        severity: "info",
                        title: "Temporary file access",
                        description: "Uses temp files during image processing operations.",
                        location: "process_image",
                        recommendation: "Validate temp directory policies in hardened environments."
                    }
                ]
            },
            {
                id: "bin_sharp_vips_332",
                filename: "vendor/libvips.so",
                architecture: "x86_64",
                format: "ELF",
                fileSize: 98365,
                functionCount: 35,
                importCount: 15,
                riskScore: 6,
                riskLevel: "low",
                decompiledPreview: "int vips_entry(...) { /* image codec helper */ }",
                aiExplanation: "The helper shared library provides codec and resize primitives used by the addon.",
                imports: ["vips_init", "vips_image_new", "vips_error_buffer_copy"],
                strings: ["libvips", "image buffer", "helper process"],
                fingerprint: {
                    sha256: "sha256-sharp-0332-vips",
                    packageVersionKey: "npm:sharp@0.33.2",
                    binaryKey: "vendor/libvips.so"
                },
                behaviors: {
                    ...sharp0332Behaviors,
                    crypto: { detected: false, details: [] }
                },
                findings: [
                    {
                        severity: "info",
                        title: "Helper process invocation",
                        description: "Spawns a helper process when codec negotiation requires fallback behavior.",
                        location: "codec_bootstrap",
                        recommendation: "Confirm sandbox rules for process spawning are acceptable."
                    }
                ]
            }
        ]
    },
    {
        id: "pkg_sqlite3_5_1_6",
        ecosystem: "npm",
        packageName: "sqlite3",
        version: "5.1.6",
        status: "complete",
        riskScore: 21,
        riskLevel: "medium",
        summary: "SQLite native binding with filesystem access to database files and guarded extension loading paths.",
        sourceMatchConfidence: "high",
        binaryCount: 1,
        totalBinarySize: 502130,
        aiModel: "claude-sonnet",
        createdAt: "2026-03-20T12:00:00.000Z",
        updatedAt: "2026-03-20T12:00:00.000Z",
        binaries: [
            {
                id: "bin_sqlite3_516",
                filename: "sqlite3.node",
                architecture: "x86_64",
                format: "ELF",
                fileSize: 502130,
                functionCount: 73,
                importCount: 24,
                riskScore: 21,
                riskLevel: "medium",
                decompiledPreview: "int sqlite_init(...) { /* database binding */ }",
                aiExplanation: "The native binding opens database files and manages transaction-safe journals.",
                imports: ["sqlite3_open_v2", "napi_create_function", "sqlite3_prepare_v2"],
                strings: ["journal", "busy_timeout", "database is locked"],
                fingerprint: {
                    sha256: "sha256-sqlite3-516",
                    packageVersionKey: "npm:sqlite3@5.1.6",
                    binaryKey: "sqlite3.node"
                },
                behaviors: sqlite516Behaviors,
                findings: [
                    {
                        severity: "medium",
                        title: "Extension loading path",
                        description: "Binary exposes an extension path that should be gated in production.",
                        location: "sqlite3_load_extension",
                        recommendation: "Disable extension loading unless explicitly required."
                    }
                ]
            }
        ]
    },
    {
        id: "pkg_sqlite3_5_1_7",
        ecosystem: "npm",
        packageName: "sqlite3",
        version: "5.1.7",
        status: "complete",
        riskScore: 25,
        riskLevel: "medium",
        summary: "SQLite native binding with filesystem access to database files and stricter extension gating.",
        sourceMatchConfidence: "high",
        binaryCount: 1,
        totalBinarySize: 507860,
        aiModel: "claude-sonnet",
        createdAt: "2026-03-21T12:00:00.000Z",
        updatedAt: "2026-03-21T12:00:00.000Z",
        binaries: [
            {
                id: "bin_sqlite3_517",
                filename: "sqlite3.node",
                architecture: "x86_64",
                format: "ELF",
                fileSize: 507860,
                functionCount: 78,
                importCount: 25,
                riskScore: 25,
                riskLevel: "medium",
                decompiledPreview: "int sqlite_init(...) { /* database binding */ }",
                aiExplanation: "The native binding opens database files and validates extension loading more aggressively.",
                imports: ["sqlite3_open_v2", "napi_create_function", "sqlite3_prepare_v2"],
                strings: ["journal", "busy_timeout", "extension path restricted"],
                fingerprint: {
                    sha256: "sha256-sqlite3-517",
                    packageVersionKey: "npm:sqlite3@5.1.7",
                    binaryKey: "sqlite3.node"
                },
                behaviors: sqlite517Behaviors,
                findings: [
                    {
                        severity: "medium",
                        title: "Extension loading gate",
                        description: "Binary validates extension loading paths before use.",
                        location: "sqlite3_load_extension",
                        recommendation: "Review whether extension support is required in production."
                    }
                ]
            }
        ]
    },
    {
        id: "pkg_canvas_2_11_2",
        ecosystem: "npm",
        packageName: "canvas",
        version: "2.11.2",
        status: "complete",
        riskScore: 34,
        riskLevel: "medium",
        summary: "Canvas binding with font file access, rasterization helpers, and native rendering support.",
        sourceMatchConfidence: "high",
        binaryCount: 2,
        totalBinarySize: 1146011,
        aiModel: "claude-sonnet",
        createdAt: "2026-03-21T12:00:00.000Z",
        updatedAt: "2026-03-21T12:00:00.000Z",
        binaries: [
            {
                id: "bin_canvas_node_2112",
                filename: "canvas.node",
                architecture: "x86_64",
                format: "ELF",
                fileSize: 701244,
                functionCount: 102,
                importCount: 38,
                riskScore: 34,
                riskLevel: "medium",
                decompiledPreview: "void render_canvas(...) { /* node-canvas binding */ }",
                aiExplanation: "The binding consumes images, fonts, and rendering surfaces to draw raster output.",
                imports: ["cairo_image_surface_create", "napi_create_function", "freetype_init"],
                strings: ["fontconfig", "/usr/share/fonts", "canvas surface"],
                fingerprint: {
                    sha256: "sha256-canvas-2112-node",
                    packageVersionKey: "npm:canvas@2.11.2",
                    binaryKey: "canvas.node"
                },
                behaviors: canvas2112Behaviors,
                findings: [
                    {
                        severity: "medium",
                        title: "Font file access",
                        description: "Binary reads local font files to build render surfaces.",
                        location: "font_loader",
                        recommendation: "Confirm font directories are constrained in containerized deployments."
                    }
                ]
            },
            {
                id: "bin_canvas_cairo_2112",
                filename: "vendor/libcairo.so",
                architecture: "x86_64",
                format: "ELF",
                fileSize: 444767,
                functionCount: 58,
                importCount: 21,
                riskScore: 29,
                riskLevel: "medium",
                decompiledPreview: "int cairo_surface_create(...) { /* rendering helper */ }",
                aiExplanation: "The shared library handles vector drawing and low-level rasterization work.",
                imports: ["cairo_surface_create", "cairo_set_source_rgba", "cairo_show_text"],
                strings: ["cairo", "render surface"],
                fingerprint: {
                    sha256: "sha256-canvas-2112-cairo",
                    packageVersionKey: "npm:canvas@2.11.2",
                    binaryKey: "vendor/libcairo.so"
                },
                behaviors: {
                    ...canvas2112Behaviors,
                    crypto: { detected: false, details: [] }
                },
                findings: [
                    {
                        severity: "info",
                        title: "Rasterization helper library",
                        description: "Shared library is limited to rendering primitives with no network behavior.",
                        location: "rasterizer",
                        recommendation: "No action needed."
                    }
                ]
            }
        ]
    },
    {
        id: "pkg_argon2_0_41_1",
        ecosystem: "npm",
        packageName: "argon2",
        version: "0.41.1",
        status: "complete",
        riskScore: 14,
        riskLevel: "low",
        summary: "Argon2 binding with expected entropy access and memory-hard hashing primitives.",
        sourceMatchConfidence: "high",
        binaryCount: 1,
        totalBinarySize: 257340,
        aiModel: "claude-sonnet",
        createdAt: "2026-03-21T12:00:00.000Z",
        updatedAt: "2026-03-21T12:00:00.000Z",
        binaries: [
            {
                id: "bin_argon2_0411",
                filename: "argon2.node",
                architecture: "x86_64",
                format: "ELF",
                fileSize: 257340,
                functionCount: 49,
                importCount: 18,
                riskScore: 14,
                riskLevel: "low",
                decompiledPreview: "int argon2_hash(...) { /* memory-hard hashing */ }",
                aiExplanation: "The binary performs password hashing using memory-hard primitives and runtime entropy.",
                imports: ["argon2_ctx", "napi_create_function", "getrandom"],
                strings: ["argon2", "memory cost"],
                fingerprint: {
                    sha256: "sha256-argon2-0411",
                    packageVersionKey: "npm:argon2@0.41.1",
                    binaryKey: "argon2.node"
                },
                behaviors: argon2411Behaviors,
                findings: [
                    {
                        severity: "info",
                        title: "Entropy source access",
                        description: "Reads system entropy as part of hashing setup.",
                        location: "argon2_hash",
                        recommendation: "No action needed."
                    }
                ]
            }
        ]
    }
];
export const sampleDiff = {
    packageName: "sqlite3",
    ecosystem: "npm",
    fromVersion: "5.1.6",
    toVersion: "5.1.7",
    riskDelta: 4,
    summary: "Version 5.1.7 adds stricter extension loading checks and a slightly larger native payload.",
    addedBehaviors: ["Additional filesystem path validation before extension loading.", "Guarded extension loading before execution."],
    removedBehaviors: []
};
export const sampleOrganization = {
    id: "org_ashlrai",
    name: "Ashlr AI",
    plan: "pro",
    role: "owner",
    createdAt: "2026-03-21T12:00:00.000Z"
};
export const sampleRepos = [
    {
        id: "repo_1",
        orgId: sampleOrganization.id,
        githubRepo: "ashlrai/platform-web",
        nativeDependencyCount: 4,
        aggregateRiskScore: 22,
        lastScanAt: "2026-03-21T13:30:00.000Z"
    },
    {
        id: "repo_2",
        orgId: sampleOrganization.id,
        githubRepo: "ashlrai/agent-runtime",
        nativeDependencyCount: 9,
        aggregateRiskScore: 43,
        lastScanAt: "2026-03-21T14:00:00.000Z"
    }
];
export const sampleApiKeys = [
    {
        id: "key_1",
        orgId: sampleOrganization.id,
        label: "GitHub Actions",
        preview: "bsh_live_****7A91",
        createdAt: "2026-03-21T12:30:00.000Z"
    }
];
export const sampleWatchlist = [
    {
        id: "watch_1",
        orgId: sampleOrganization.id,
        packageName: "bcrypt",
        ecosystem: "npm",
        createdAt: "2026-03-21T13:00:00.000Z"
    }
];
export const sampleAlerts = [
    {
        id: "alert_1",
        orgId: sampleOrganization.id,
        channel: "email",
        destination: "security@ashlr.ai",
        deliveryStatus: "sent",
        packageName: "bcrypt",
        createdAt: "2026-03-21T15:00:00.000Z"
    }
];
export const sampleSubscription = {
    id: "sub_1",
    orgId: sampleOrganization.id,
    plan: "pro",
    status: "active",
    stripeCustomerId: "cus_demo",
    stripeSubscriptionId: "sub_demo",
    currentPeriodEndsAt: "2026-04-21T00:00:00.000Z",
    createdAt: "2026-03-21T12:00:00.000Z"
};
export const sampleDashboard = {
    organization: sampleOrganization,
    repos: sampleRepos,
    watchlist: sampleWatchlist,
    alerts: sampleAlerts,
    apiKeys: sampleApiKeys,
    subscription: sampleSubscription,
    entitlements: entitlementForPlan(sampleSubscription.plan)
};
export const sampleActionSummaries = sampleAnalyses.map((analysis) => ({
    packageName: analysis.packageName,
    version: analysis.version,
    riskLevel: analysis.riskLevel,
    riskScore: analysis.riskScore,
    binaryFilenames: analysis.binaries.map((binary) => binary.filename),
    summary: analysis.summary
}));
export function getSamplePackageHistory(packageName, ecosystem) {
    return sampleAnalyses
        .filter((analysis) => analysis.packageName === packageName && (!ecosystem || analysis.ecosystem === ecosystem))
        .sort((a, b) => a.version.localeCompare(b.version));
}
export function getSamplePackageDiff(packageName, fromVersion, toVersion) {
    const history = getSamplePackageHistory(packageName);
    const from = history.find((analysis) => analysis.version === fromVersion);
    const to = history.find((analysis) => analysis.version === toVersion);
    if (!from || !to) {
        return undefined;
    }
    const fromBehaviors = new Set(from.binaries.flatMap((binary) => Object.entries(binary.behaviors).filter(([, signal]) => signal.detected).map(([name]) => name)));
    const toBehaviors = new Set(to.binaries.flatMap((binary) => Object.entries(binary.behaviors).filter(([, signal]) => signal.detected).map(([name]) => name)));
    const addedBehaviors = Array.from(toBehaviors).filter((behavior) => !fromBehaviors.has(behavior));
    const removedBehaviors = Array.from(fromBehaviors).filter((behavior) => !toBehaviors.has(behavior));
    return {
        packageName,
        ecosystem: to.ecosystem,
        fromVersion,
        toVersion,
        riskDelta: to.riskScore - from.riskScore,
        summary: to.riskScore > from.riskScore
            ? `${packageName}@${toVersion} is riskier than ${fromVersion} and introduces additional behavior families.`
            : to.riskScore < from.riskScore
                ? `${packageName}@${toVersion} is less risky than ${fromVersion} and removes some prior behavior.`
                : `${packageName}@${toVersion} retains the same aggregate posture as ${fromVersion}.`,
        addedBehaviors,
        removedBehaviors
    };
}
export function getSampleActionSummaries(packageName) {
    return packageName ? sampleActionSummaries.filter((summary) => summary.packageName === packageName) : sampleActionSummaries;
}
export function getSampleAnalysis(packageName, version) {
    return sampleAnalyses.find((analysis) => {
        if (analysis.packageName !== packageName) {
            return false;
        }
        return version ? analysis.version === version : true;
    });
}
