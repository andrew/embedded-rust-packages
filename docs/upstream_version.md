# upstream_version.rb

Extracts the vendored upstream C library version from a crates.io release. For crates that encode it in the semver `+metadata` suffix (`zstd-sys@2.0.10+zstd.1.5.6`) the version string alone is parsed. For crates that don't, the `.crate` tarball is downloaded from `static.crates.io` and grepped for the vendored header's `#define VERSION` macro; `cargo publish` bundles submodule content, so the tarball has the header even when the git repo only has a submodule pointer.

    ruby upstream_version.rb libsqlite3-sys 0.30.1 0.37.0
    ruby upstream_version.rb --all             # every mappable (crate,version) in crate_deps
    ruby upstream_version.rb --full libz-sys   # every published version of the crate

Output is Ruby-hash lines suitable for pasting into [`CVendoring::UPSTREAM_TABLE`](helpers.md#c_vendoringrb). [`crate_cve_ranges.rb`](crate_cve_ranges.md) shells to `--full` and caches the map. `--full` also prints a range summary (`libz-sys [1.0.17 .. 1.1.8] -> zlib 1.2.11`) to stderr.

Tarballs are cached under `cache/upstream/<crate>-<ver>.crate`; a `--full libsqlite3-sys` first run downloads ~300 MB (60 releases at ~5 MB) once. `--full` version -> upstream maps are cached by `crate_cve_ranges.rb` under `cache/upstream/maps/<crate>.json`.

## How the tarball probe works

`cargo publish` builds a `.crate` tarball from the working tree with git submodules resolved, so a crate whose repo vendors OpenSSL via a submodule pointer ships the actual OpenSSL headers in the tarball. `static.crates.io/crates/<name>/<name>-<ver>.crate` serves that tarball for every published version.

The probe downloads the tarball, streams `tar -xzO` (all file bytes concatenated to stdout), and runs each regex in `PROBES[crate]` against the stream. Whichever pattern matches first supplies the upstream version. For crates that bundle two variants (libmimalloc-sys ships mimalloc v2 and v3; libsqlite3-sys ships plain SQLite and SQLCipher), the highest matched version is kept.

Adding a crate means finding one file in its vendored source that carries a version string and writing a regex that captures it:

```ruby
"libsqlite3-sys" => ["sqlite3", [/#define SQLITE_VERSION\s+"([\d.]+)"/]],
```

The tarball for `libsqlite3-sys-0.30.1` contains `sqlite3/sqlite3.h` with `#define SQLITE_VERSION "3.46.0"`, so the probe returns `["sqlite3", "3.46.0"]`. Multi-part macros work with a multiline regex:

```ruby
"onig_sys" => ["oniguruma", [/ONIGURUMA_VERSION_MAJOR\s+(\d+).*?_MINOR\s+(\d+).*?_TEENY\s+(\d+)/m]],
```

Capture groups are joined with `.` so that returns `["oniguruma", "6.9.10"]`.
`brotli-sys` is the exception: Brotli stores `(major << 24) | (minor << 12) |
patch` as a hexadecimal integer, so `version_from_match` decodes that packed
value after the regex matches it.

Crates whose vendored source has no version macro (`ring` vendors a BoringSSL commit; the only identifier is the git SHA in `ring`'s own `Cargo.toml.orig`) are outside this method and need a per-release lookup table built by other means.
