# scan.rb

Shallow-clones each repo in `repos`, runs `brief --json` on the working tree, records which Rust and C/C++ signals fired, and deletes the clone. Results are cached per-repo under `cache/scan/<sha>.json` (derived signals) and `cache/brief/<sha>.json` (raw brief output) so re-runs skip cloning.

    ruby scan.rb                  # unscanned rows only, dependent_repos order
    ruby scan.rb 500              # first 500 unscanned rows
    ruby scan.rb --refresh        # ignore cache, re-clone everything
    ruby scan.rb --refresh --only-rust        # re-clone just has_rust=1 rows
    ruby scan.rb --refresh --only-submodules  # re-clone just has_submodules=1 rows
    ruby scan.rb --rederive       # rewrite has_rust from cache, no cloning

The clone is `git clone --depth 1 --filter=blob:none` followed by a best-effort `git submodule update --init --depth 1 --jobs 4` when a `.gitmodules` is present, so vendored source in submodules is visible to brief. A dead or private submodule fails silently rather than aborting the scan. `bin/scc` is prepended to `PATH` for the brief invocation so scc's line counts include submodule content (see [helpers.md](helpers.md)).

`has_rust` is derived at write time (any tracked `Cargo.toml` after excluding `vendor/`, `test*/`, `fixtures/`, `examples/`; or a Rust bridge tool in brief's `native_extension` list) so the rule can change without re-cloning: edit `has_rust?` and run `--rederive`. `signals` records which of `brief:lang`, `brief:cargo`, `brief:bridge`, `cargo.toml`, `cargo.lock`, `rust_loc` fired for later filtering.

The clone hosts are `github.com`, `gitlab.com`, `codeberg.org`, `gitea.com`, `sr.ht`, `git.sr.ht`; other hosts are skipped.

`cache/brief/` is read by [`native.rb`](native.md) to derive C/C++ columns without re-cloning; `cargo_toml_paths` drives [`crates.rb`](crates.md).
