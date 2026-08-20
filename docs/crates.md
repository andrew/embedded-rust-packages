# crates.rb

For each `has_rust` repo that publishes to a non-cargo registry, run `brief --json` on every directory containing a `Cargo.toml` and record the `pkg:cargo/*` dependencies into `crate_deps`. brief parses both `Cargo.toml` (constraint strings, `direct=1`) and `Cargo.lock` (resolved versions, `direct=0` since Cargo.lock has no root marker), so a direct dep appears twice with different `requirement` values.

    ruby crates.rb            # cache-first
    ruby crates.rb --refresh  # ignore cache, re-clone

Results are cached under `cache/crates/<sha>.json`. For a repo whose only `Cargo.toml` is at the root, the `cache/brief/` entry from `scan.rb` is reused and no clone happens; otherwise the repo is shallow-cloned once and brief runs per crate directory.

The `crate_deps` primary key includes `requirement`, so a `Cargo.lock` with two majors of the same crate (`h2` 0.3.x and 0.4.x) stores both. `direct` is `MAX(direct)` on conflict so a Cargo.toml row's `direct=1` survives when the Cargo.lock row for the same version arrives after.

Cargo-only repos are excluded: their dependency tree is what cargo-audit already covers. A repo that publishes to both crates.io and another registry stays in via the non-cargo purl.

brief 0.11's nested-manifest discovery merges every `Cargo.lock` it finds into one flat `dependencies[]`, so a root-dir invocation on a repo with an ancillary `scripts/foo/Cargo.lock` records that lockfile's crates at `cargo_dir="."`. [`advisories.rb`](advisories.md) filters those by dropping any `cargo_dir="."` row whose `(crate, requirement)` also appears at a non-root `cargo_dir`. [`report.rb`](report.md) aggregates `crate_deps` into `out/crate-deps.csv`.
