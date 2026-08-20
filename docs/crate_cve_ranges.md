# crate_cve_ranges.rb

Computes which crate versions bundle a vendored C library version in each upstream CVE's affected range, and writes an OSV-format record per `(crate, CVE)` to `out/sys-advisories/SYSCRATE-<crate>-<CVE>.json`. The records carry the crate-version range a RUSTSEC advisory would need.

    ruby crate_cve_ranges.rb libz-sys
    ruby crate_cve_ranges.rb libz-sys curl-sys zstd-sys lzma-sys
    NVD_API_KEY=xxx ruby crate_cve_ranges.rb ...

Pipeline per crate:

1. [`upstream_version.rb --full <crate>`](upstream_version.md) builds the crate-version -> C-version map (cached under `cache/upstream/maps/`).
2. [`Repology.osv_packages(upstream)`](helpers.md#repologyrb) returns the distro source-package names OSV keys on (`zlib` -> `Debian:zlib`, `Alpine:zlib`, `Ubuntu:zlib`; `zstd` -> `Debian:libzstd`; `oniguruma` -> `Debian:libonig`). Cached under `cache/repology/`.
3. OSV `querybatch` on those packages returns candidate CVE ids.
4. Each CVE's NVD record (cached under `cache/nvd/`) supplies CPE version bounds; `rejected` CVEs and versions outside the CPE range are dropped.
5. [`data/rejected.txt`](helpers.md#datarejectedtxt) drops component-mismatch CVEs (MiniZip in zlib, xzgrep in xz, bzip2recover) that pass the CPE range check but are in code the crate's build.rs skips.
6. Crate versions whose bundled C version falls in range become `affected[].ranges[].events`.

The emitted record has `upstream: [CVE-xxx]`, `ecosystem: crates.io`, `purl: pkg:cargo/<crate>`, and `ecosystem_specific.bundled_versions` listing the affected C versions. CVEs already covered by an existing RUSTSEC/GHSA for the crate are printed with `(already: ...)` and skipped.

The `SYSCRATE-` id prefix is a placeholder pending a decision on whether these become RUSTSEC submissions or a separate feed. `introduced` is the earliest crate release the tarball probe succeeded on, which may be later than the true first-affected version; a submitted advisory should use `"0"` unless earlier releases are confirmed clean. Crates that link a system library by default (`libz-sys`, `curl-sys`, `libsqlite3-sys` on Linux without the `static`/`bundled` feature) are only affected when built with the vendored source; the record does not currently encode that condition, so a submitted advisory needs it added by hand.

First run per crate is dominated by tarball downloads and NVD rate limit; both are cached.
