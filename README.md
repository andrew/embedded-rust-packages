# embedded-rust-packages

Find critical open-source packages that ship Rust code inside a non-Rust ecosystem (pypi, npm, rubygems, hex, etc.) so [rustsec](https://rustsec.org/) tooling can be pointed at them. Pulls the `critical=true` set from [packages.ecosyste.ms](https://packages.ecosyste.ms), shallow-clones each backing repo, runs [`brief`](https://github.com/git-pkgs/brief) plus a `git ls-files` sweep for `Cargo.toml` / `Cargo.lock`, and records which bridge tool (maturin, napi-rs, rb-sys, neon, rustler, setuptools-rust, magnus) is in use.

crates.io is deliberately excluded: those packages are already Rust and already covered by cargo-audit. The interesting cases are the pypi wheel with 30k lines of PyO3, or the npm package whose `.node` binary is built from a napi-rs crate, where the Rust dependency tree never passes through cargo-audit on the consumer's machine.

## Setup

    bundle install

Needs `brief` and `git` on PATH.

## Pipeline

    ruby fetch.rb            # critical packages -> rustdeps.db (packages + repos tables)
    ruby scan.rb             # shallow-clone each repo, brief + Cargo.* detection
    ruby dedupe.rb           # follow github redirects and merge alias repo rows
    ruby crates.rb           # brief on each Cargo.toml dir -> crate_deps table
    ruby report.rb           # stats + out/*.csv + out/brief-gaps.md

`fetch.rb` defaults to fifteen registries (everything except crates.io); pass names to limit (`ruby fetch.rb pypi.org npmjs.org`). By default it pulls the `critical=true` set; pass `--top N` to instead take the top N per registry by `dependent_repos_count`, which is how the corpus expands beyond critical. Every HTTP response is cached under `cache/packages/` and every scan result under `cache/scan/`, so re-runs are local-only and the db can be rebuilt after schema changes. `scan.rb` skips repos it has already touched, takes an optional row limit, and processes repos in `dependent_repos` order so a partial run covers the highest-impact packages first. Pass `--force` to re-scan.

## Signals

A repo is flagged `has_rust=1` when, after excluding `vendor/`, `node_modules/`, `test*/`, `fixtures/`, `examples/` and similar directories, either a `Cargo.toml` is tracked in git or `brief` reports a Rust bridge tool. Non-zero Rust LOC on its own is recorded but does not flag: stray `.rs` fixtures with no `Cargo.toml` have no dependency tree to point scrutineer at.

The `signals` column records which of `brief:lang`, `brief:cargo`, `brief:bridge`, `cargo.toml`, `cargo.lock`, `rust_loc` fired, and the raw per-repo scan result is cached under `cache/scan/`, so the flag can be re-derived with different rules via `ruby scan.rb --rederive` (re-reads cache, no cloning) or ad-hoc `SELECT`. `--refresh` ignores the cache and re-clones.

## Output

  * `out/scrutineer.txt`: one HTTPS URL per repo with embedded Rust, ready to paste into [scrutineer](https://github.com/alpha-omega-security/scrutineer)'s **Add multiple** dialog. When the crate lives below the repo root the line carries a `#sub/dir` suffix so scrutineer scopes the scan to the Rust code; workspaces get the shallowest `Cargo.toml` directory and scrutineer's own subprojects discovery handles the members. Sorted by `dependent_repos`.
  * `out/embedded-rust.csv`: one row per package (not per repo) with purl, ecosystem, dependent counts, downloads, repo URL, Rust LOC, bridge tool, and the `Cargo.toml` / `Cargo.lock` paths inside the repo. Supporting context for the URL list.
  * `out/crate-deps.csv`: one row per distinct cargo crate across all embedding repos, with the count of repos that depend on it, the set of requirement strings seen, and the repo URLs. Direct deps only until brief also parses `Cargo.lock`.
  * `out/brief-gaps.md`: repos where the filesystem shows Rust but `brief` reported none of the Rust signals. Each is a candidate missing knowledge entry or detection bug in brief; the note includes the cached `brief --json` path for inspection.

## Database

`rustdeps.db` (sqlite, WAL mode):

  * `packages`: one row per critical package (purl). Registry, ecosystem, dependent counts, downloads, latest release, `rankings_avg`.
  * `repos`: one row per repository_url. `has_rust`, `rust_loc`, `bridge_tools`, `cargo_toml_paths`, `cargo_lock_paths`, `signals`, plus the raw `brief_languages` list.

    sqlite3 rustdeps.db "SELECT p.ecosystem, COUNT(*) FROM packages p
                         JOIN repos r USING (repository_url)
                         WHERE r.has_rust=1 GROUP BY 1 ORDER BY 2 DESC"

    sqlite3 rustdeps.db "SELECT p.name, p.dependent_repos, r.bridge_tools, r.rust_loc
                         FROM packages p JOIN repos r USING (repository_url)
                         WHERE p.ecosystem='pypi' AND r.has_rust=1
                         ORDER BY p.dependent_repos DESC LIMIT 20"

## License

This project is licensed under the [MIT License](LICENSE).
