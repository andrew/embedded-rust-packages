# fetch.rb

Populates `rustdeps.db` from the [packages.ecosyste.ms](https://packages.ecosyste.ms) API. Creates the `packages` table (one row per purl) and seeds `repos` (one row per distinct `repository_url`) from the embedded `repo_metadata`.

    ruby fetch.rb                      # critical=true across all default registries
    ruby fetch.rb pypi.org npmjs.org   # limit to named registries
    ruby fetch.rb --top 5000 crates.io # top N by dependent_repos_count instead of critical

The default registry list is fifteen ecosystems (npm, pypi, rubygems, hex, packagist, nuget, maven, go, pub, cocoapods, conda, swift, hackage, julia, cpan). crates.io is excluded from the default because those packages are already Rust; pass it explicitly to compare C/C++ embedding inside Rust crates against Rust embedding elsewhere.

Every API page is cached under `cache/packages/<sha>.json` keyed on the request URL, so a re-run after a schema change reads local files. Rows upsert on purl and repository_url; running again after new releases refreshes counts without dropping scan results.

`repository_url` is normalised (https, no trailing slash, no `.git`, lowercase) before insert so [`scan.rb`](scan.md) and [`dedupe.rb`](dedupe.md) can key on it.
