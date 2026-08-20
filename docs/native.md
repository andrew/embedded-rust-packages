# native.rb

Derives C/C++ presence for every scanned repo from the cached `brief --json` output written by `scan.rb`, adds `has_c`, `c_loc`, `cpp_loc`, `c_bridge_tools`, `c_build_tools`, `c_signals`, `has_submodules` columns to `repos`, and prints a Rust-vs-C/C++ adoption comparison per ecosystem.

    ruby native.rb

No cloning: everything is read from `cache/brief/` written by [`scan.rb`](scan.md). `has_c` is set when brief's `languages[]` includes C or C++, or a C bridge (`setuptools Extension`, `mkmf`, `node-gyp`, `phpize`, `meson-python`) or build tool (`CMake`, `Autotools`, `Meson`) is detected. `c_loc` and `cpp_loc` come from brief's scc counts (`C` + `C Header`, `C++` + `C++ Header`).

Outputs:

- `out/native-compare.csv`: per-ecosystem repo counts for Rust vs C/C++ (loose and tight).
- `out/c-repos.csv`: every `has_c` repo with LOC, bridge, build tool, ecosystems, dependent_repos.
- `out/nested-c.csv`: host packages whose `crate_deps` include a crate [`CVendoring.vendors_c?`](helpers.md#c_vendoringrb) classifies as C-vendoring; the host -> Rust -> vendored C chain.
- `out/submodule-repos.csv`: every scanned repo with `.gitmodules`. 413 of 657 have `has_c=0` before submodule content is fetched; run `scan.rb --refresh --only-submodules` first if accurate C LOC matters.

`has_rust` uses a filesystem `Cargo.toml` check; `has_c` uses brief's language detection alone (there is no single C manifest to look for). The two are asymmetric, so the report shows both a loose count (language present) and a tight count (bridge or build tool detected).
