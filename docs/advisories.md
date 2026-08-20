# advisories.rb

For every resolved `(crate, version)` in `crate_deps`, query OSV for advisories filed against `ecosystem: crates.io` and write one row per `(host purl, crate@version, advisory)` to `out/nested-advisories.csv`. Host-ecosystem tooling (`npm audit`, `pip-audit`, `bundle audit`, `mix hex.audit`) misses these because the advisory is filed against the crate rather than the host purl.

    ruby advisories.rb
    NVD_API_KEY=xxx ruby advisories.rb   # 10x faster upstream-C pass

Only `requirement` values matching `x.y.z` are queried (Cargo.lock rows); constraint strings from Cargo.toml are skipped. Root-`cargo_dir` rows that duplicate a nested lockfile's version are dropped (see [crates.md](crates.md)). RUSTSEC and GHSA aliases for the same advisory are collapsed to one canonical id; the RUSTSEC record's `database_specific.informational` (unmaintained/unsound/notice) is propagated across the group so a GHSA copy of an unsound advisory is tagged too. `vendors_c` is set from `CVendoring.vendors_c?`.

A second pass covers the layer below RUSTSEC: for `-sys` crates whose vendored C version is known (via `+metadata` or `CVendoring::UPSTREAM_TABLE`), CVE candidates are discovered from Debian/Alpine/Ubuntu OSV entries and each is checked against NVD's CPE version ranges. Rows with `vulnStatus: Rejected` or an out-of-range CPE are dropped; `no_cpe` (NVD analysis pending or product-name mismatch) is kept and tagged. Output is `out/upstream-c-advisories.csv`.

NVD responses are cached under `cache/nvd/<CVE>.json`. Without `NVD_API_KEY` the rate limit is 5 requests per 30 seconds, so a first run over ~175 CVEs takes ~18 minutes; with a key it is 50 per 30 seconds. Re-runs read the cache.

The upstream-C pass covers only crates with a mapped upstream version; use [`crate_cve_ranges.rb`](crate_cve_ranges.md) to build full crate-version -> CVE range records for a specific crate. Input comes from [`crates.rb`](crates.md); the C-vendoring classifier and upstream-version map are in [`c_vendoring.rb`](helpers.md#c_vendoringrb).
