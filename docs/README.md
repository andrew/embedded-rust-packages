# Scripts

Each script is one stage of the pipeline. All read and write `rustdeps.db` (sqlite, WAL) in the repo root and cache network responses under `cache/` so a re-run after a code change is local-only.

| script | reads | writes | doc |
|---|---|---|---|
| `fetch.rb` | packages.ecosyste.ms API | `packages`, `repos` tables | [fetch.md](fetch.md) |
| `scan.rb` | `repos`; clones each | `repos` scan columns; `cache/brief/`, `cache/scan/` | [scan.md](scan.md) |
| `dedupe.rb` | `repos` (github redirects) | merges alias rows | [dedupe.md](dedupe.md) |
| `crates.rb` | `repos` where has_rust; clones | `crate_deps` table; `cache/crates/` | [crates.md](crates.md) |
| `report.rb` | `packages`, `repos`, `crate_deps` | `out/embedded-rust.csv`, `scrutineer.txt`, `crate-deps.csv`, `brief-gaps.md`, `no-lock.csv` | [report.md](report.md) |
| `native.rb` | `cache/brief/` | `repos` C/C++ columns; `out/native-compare.csv`, `c-repos.csv`, `nested-c.csv`, `submodule-repos.csv` | [native.md](native.md) |
| `advisories.rb` | `crate_deps`; OSV, NVD | `out/nested-advisories.csv`, `upstream-c-advisories.csv`; `cache/nvd/` | [advisories.md](advisories.md) |
| `upstream_version.rb` | crates.io tarballs | stdout table; `cache/upstream/` | [upstream_version.md](upstream_version.md) |
| `crate_cve_ranges.rb` | `upstream_version.rb`, Repology, OSV, NVD | `out/sys-advisories/*.json` | [crate_cve_ranges.md](crate_cve_ranges.md) |

Shared modules and shims are covered in [helpers.md](helpers.md).
