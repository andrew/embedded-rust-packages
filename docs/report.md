# report.rb

Reads `packages`, `repos`, and `crate_deps` and writes the handoff outputs. Cargo-only repos are excluded from every output since a repo that publishes only to crates.io is plain Rust rather than Rust embedded in a host language.

    ruby report.rb

Outputs:

- `out/embedded-rust.csv`: one row per non-cargo package whose repo has Rust. Purl, ecosystem, dependent counts, downloads, repo URL, Rust LOC, bridge tool, `sibling_runtime` flag, `Cargo.toml`/`Cargo.lock` paths, signals.
- `out/scrutineer.txt`: one HTTPS URL per repo, `#sub/dir` when the crate is below the root, sorted by `dependent_repos`. A `sibling_runtime` section at the bottom lists polyglot repos where `rust/` is one language target among many rather than compiled into the host artefact.
- `out/crate-deps.csv`: one row per distinct crate name across all embedding repos, with the count of repos, the set of version strings, and the repo URLs.
- `out/no-lock.csv`: embedded-Rust repos with a `Cargo.toml` but no committed `Cargo.lock`. [`advisories.rb`](advisories.md) has only constraint strings for these.

The C/C++ and submodule outputs come from [`native.rb`](native.md) rather than here.
- `out/brief-gaps.md`: repos where `git ls-files` finds `Cargo.*` but brief reported no Rust signal.

`sibling_runtime?` fires when a repo has five or more languages, no bridge tool, and the shallowest `Cargo.toml` directory name looks like a language binding (`rust/`, `lib/rs/`, `rust_port/`). Those repos publish `pkg:cargo/*` to crates.io independently, so a bug there affects cargo consumers rather than the pypi/npm purl the row is attributed to.
