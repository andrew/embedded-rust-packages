# Scripts

The pipeline answers three questions in order: which packages in non-Rust registries ship Rust, which crates that Rust pulls in, and which of those crates carry advisories that host-ecosystem tooling misses. A fourth stage repeats the advisory check against the C libraries those crates vendor. Every stage reads and writes `rustdeps.db` (sqlite, WAL) in the repo root and caches network responses under `cache/`, so a re-run after a code change is local-only.

## Building the corpus

[`fetch.rb`](fetch.md) pulls package metadata from packages.ecosyste.ms into the `packages` and `repos` tables. By default it takes the `critical=true` set across fifteen registries; `--top N` widens to the top N per registry by dependent-repo count, which is how the corpus was extended to top-5000 pypi/npm/rubygems/hex plus (optionally) crates.io.

[`scan.rb`](scan.md) shallow-clones each repo, runs `brief --json` on the working tree, and records which Rust and C signals fired: languages, package managers, bridge tools, `Cargo.toml`/`Cargo.lock` paths, line counts. It also does a best-effort shallow submodule fetch so vendored source is visible. Raw brief output is cached per repo so later stages can re-read it without re-cloning.

[`dedupe.rb`](dedupe.md) follows GitHub redirects and merges alias rows so a repo that moved orgs is counted once.

## The Rust layer

[`crates.rb`](crates.md) runs brief on each `Cargo.toml` directory in every `has_rust` repo and writes the resolved crate dependencies to `crate_deps`. brief parses both `Cargo.toml` (constraint strings, direct) and `Cargo.lock` (resolved versions, transitive), and the table keeps every distinct version so a lockfile with two `h2` majors stores both.

[`report.rb`](report.md) turns the tables into the handoff files: `out/scrutineer.txt` (one URL per embedded-Rust repo, ready for scrutineer's bulk import), `out/embedded-rust.csv` (per-package context), `out/crate-deps.csv` (which crates appear in the most embedding repos), `out/no-lock.csv` (repos that ship Rust but commit no `Cargo.lock`), and `out/brief-gaps.md` (repos where brief under-reported).

## The C layer

[`native.rb`](native.md) re-reads the cached brief output for every scanned repo and derives C/C++ columns alongside the Rust ones: `has_c`, LOC, bridge tools (setuptools Extension, mkmf, node-gyp), build tools (CMake, Meson, Autotools), and submodule presence. It writes `out/native-compare.csv` (Rust vs C/C++ adoption per ecosystem), `out/c-repos.csv`, `out/submodule-repos.csv`, and `out/nested-c.csv` (host packages whose Rust dependency tree pulls in a crate that vendors C).

## Advisories

[`advisories.rb`](advisories.md) batches every resolved `(crate, version)` from `crate_deps` through OSV and writes `out/nested-advisories.csv`: one row per (host purl, crate@version, advisory), with RUSTSEC/GHSA aliases collapsed and `informational` (unmaintained/unsound) tagged. These are advisories `npm audit` / `pip-audit` / `bundle audit` miss because they are filed against `ecosystem: crates.io`. A second pass in the same script maps `-sys` crates to their vendored C version (where known) and cross-checks upstream CVEs against NVD's CPE ranges, writing `out/upstream-c-advisories.csv`.

[`upstream_version.rb`](upstream_version.md) supplies the crate-version -> C-version map that second pass needs. For crates that encode the upstream version in `+metadata` (`zstd-sys@2.0.10+zstd.1.5.6`) it parses the version string; for the rest it downloads the crates.io tarball and greps the vendored header for a `#define VERSION` macro. `--full <crate>` walks every published release so the map covers the whole history.

[`crate_cve_ranges.rb`](crate_cve_ranges.md) is the layer below RUSTSEC. Given a `-sys` crate, it takes the full crate-version -> C-version map, discovers CVE candidates for the upstream C library via Repology-mapped distro packages, filters each against NVD's CPE version bounds and `data/rejected.txt`, and emits an OSV JSON record per CVE with the crate-version range that bundles an affected C version. `out/sys-advisories/SYSCRATE-libz-sys-CVE-2022-37434.json` and similar are the shape a RUSTSEC advisory would need for crates that currently have none.

## Shared code

[`helpers.md`](helpers.md) covers `http.rb` (Faraday connection factory), `c_vendoring.rb` (the C-vendoring crate classifier and upstream-version map), `repology.rb` (upstream project -> distro srcnames, ported from Homebrew/advisory-database), `bin/scc` (adds `--no-gitmodule` to brief's scc invocation), and `data/rejected.txt` (component-mismatch CVE filter).
