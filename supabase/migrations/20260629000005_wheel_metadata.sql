-- Wheel Metadata Table
--
-- Stores structured metadata extracted from PyPI wheel .dist-info files:
--   WHEEL    — build tag, python implementation, python versions, platforms, tags
--   METADATA — package name, version, requires-dist, classifiers
--   RECORD   — file count, embedded native binary names
--
-- This table is populated by the `PyPiWheelMetadataParser` during wheel analysis
-- and serves as the authoritative record of what metadata was extracted from each
-- wheel at scan time.  It is separate from `binary_fingerprint_registry` which
-- stores per-binary fingerprints for similarity clustering.
--
-- The combination (ecosystem, package_name, version, wheel_filename) is unique
-- so that metadata from multiple wheel variants (different platforms) for the
-- same package version can coexist.

create table if not exists wheel_metadata (
  id                  uuid         primary key default gen_random_uuid(),

  -- Package identity
  ecosystem           text         not null default 'pypi'
    check (ecosystem in ('pypi')),
  package_name        text         not null,   -- normalised lowercase
  version             text         not null,

  -- Wheel file identification
  wheel_filename      text         not null,   -- e.g. numpy-1.26.4-cp311-cp311-linux_x86_64.whl
  dist_info_dir       text         not null,   -- e.g. numpy-1.26.4.dist-info

  -- WHEEL file fields (PEP 427)
  wheel_version       text,                    -- e.g. "1.0"
  build_tag           text,                    -- optional build tag (empty = absent)
  python_implementation text,                  -- e.g. "cp", "pp"
  python_versions     text[],                  -- e.g. ARRAY['311', '310']
  platforms           text[],                  -- e.g. ARRAY['linux_x86_64', 'manylinux_2_17_x86_64']
  root_is_purelib     boolean,

  -- METADATA file fields (PEP 566)
  metadata_version    text,
  summary             text,
  requires_dist       text[],                  -- PEP 508 specifiers
  provides_extra      text[],
  classifiers         text[],
  license             text,
  home_page           text,

  -- RECORD-derived fields
  record_entry_count  integer not null default 0,

  -- Embedded native binary names (.so / .pyd / .dylib)
  -- Stored as relative paths inside the wheel (forward-slash separated)
  embedded_binary_paths text[],               -- e.g. ARRAY['numpy_core/_multiarray_umath.cpython-311-x86_64-linux-gnu.so']
  embedded_binary_count integer not null default 0,

  -- Scan timestamp
  scanned_at          timestamptz  not null default now(),

  -- Uniqueness: one metadata record per wheel variant per package version
  constraint wheel_metadata_uniq
    unique (ecosystem, package_name, version, wheel_filename)
);

-- Lookup by package name + version (most common query pattern)
create index if not exists wm_package_version_idx
  on wheel_metadata (ecosystem, package_name, version);

-- Lookup wheels containing native binaries (for binary-heavy package detection)
create index if not exists wm_has_binaries_idx
  on wheel_metadata (ecosystem, package_name)
  where embedded_binary_count > 0;

-- Platform-specific wheel lookups
create index if not exists wm_platform_idx
  on wheel_metadata using gin (platforms);

-- Python version compatibility lookups
create index if not exists wm_python_versions_idx
  on wheel_metadata using gin (python_versions);

-- Requires-dist dependency graph traversal
create index if not exists wm_requires_dist_idx
  on wheel_metadata using gin (requires_dist);

comment on table wheel_metadata is
  'Structured metadata extracted from PyPI wheel .dist-info files during scanning. '
  'One row per wheel variant (different platform/python/abi tags) per package version. '
  'Populated by PyPiWheelMetadataParser; used for dependency graph analysis, '
  'platform risk assessment, and embedded C extension inventory.';

comment on column wheel_metadata.embedded_binary_paths is
  'Relative paths (forward-slash) of native extension binaries (.so/.pyd/.dylib) '
  'found in the wheel archive. Empty array for pure-Python wheels.';

comment on column wheel_metadata.requires_dist is
  'PEP 508 dependency specifiers from the wheel METADATA file. '
  'Used for EPSS/CVE enrichment: when these packages have known vulnerabilities, '
  'their EPSS percentile boosts the C extension risk score.';

comment on column wheel_metadata.build_tag is
  'Optional PEP 427 build tag from the WHEEL file. '
  'Non-empty values indicate a rebuild (e.g. "1" for first rebuild). '
  'Multiple builds of the same source/version are unusual and may warrant scrutiny.';
