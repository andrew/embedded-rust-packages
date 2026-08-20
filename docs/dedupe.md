# dedupe.rb

Follows GitHub redirects for `has_rust` repos and merges alias rows in `repos` and `packages`. A repo that moved from `facebook/react` to `react/react` appears under both URLs after `fetch.rb` (different registries record different snapshots); this collapses them so `scan.rb` results and `crate_deps` attach to one row.

    ruby dedupe.rb

Only `has_rust=1` rows are checked to keep the request count low. Run over the full `repos` table if the wider corpus shows more org-rename noise.
