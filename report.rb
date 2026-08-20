#!/usr/bin/env ruby
# List packages whose repos contain Rust, ranked by dependent_repos, and
# write out/embedded-rust.csv for handoff. One row per package (not per
# repo) so multi-package monorepos appear once per published artefact.
#
# Usage: ruby report.rb

require "sqlite3"
require "csv"
require "fileutils"
require "digest"

WORKDIR = __dir__
DB_PATH = File.join(WORKDIR, "rustdeps.db")
OUT     = File.join(WORKDIR, "out")

FileUtils.mkdir_p(OUT)

# Directory names that mark a Rust dir as one language runtime among siblings
# rather than native code compiled into the host-language package.
SIBLING_DIR_RE = %r{\A(rust|lib/rs|lib/rust|src/rust|rust_port|release_crates|crates)\z}i

# A repo is treated as sibling-runtime when brief reports many languages, no
# Rust bridge tool, and the shallowest Cargo.toml lives under a directory
# whose name says "this is the Rust binding" rather than "this is the native
# extension". Such repos publish pkg:cargo/* independently; a bug there
# affects cargo consumers, not the pypi/npm purl we attribute it to.
def sibling_runtime?(brief_languages, bridge_tools, cargo_toml_paths)
  return false unless (bridge_tools || "").empty?
  return false if (brief_languages || "").split(",").size < 5
  tomls = (cargo_toml_paths || "").split("\n").reject(&:empty?)
  return false if tomls.empty?
  dir = File.dirname(tomls.min_by { |p| p.count("/") })
  return false if dir == "."
  segs = dir.split("/")
  segs.any? { |s| s.match?(/\Arust\b|\Ars\z/i) } || dir.match?(SIBLING_DIR_RE)
end

db = SQLite3::Database.new(DB_PATH)
db.results_as_hash = true

total_repos   = db.get_first_value("SELECT COUNT(*) FROM repos")
scanned_repos = db.get_first_value("SELECT COUNT(*) FROM repos WHERE scanned_at IS NOT NULL")
# A cargo-only repo is just a Rust crate, not Rust embedded in a host language.
# Repos that publish to cargo AND another registry stay in via the other purl.
HOST = "EXISTS (SELECT 1 FROM packages hp WHERE hp.repository_url = r.repository_url AND hp.ecosystem <> 'cargo')"
RUST = "has_rust = 1 AND (cargo_toml_count > 0 OR COALESCE(bridge_tools,'') <> '') AND #{HOST}"
rust_repos    = db.get_first_value("SELECT COUNT(*) FROM repos r WHERE #{RUST}")

puts "repos:   #{total_repos} total, #{scanned_repos} scanned, #{rust_repos} with rust"
puts

puts "by ecosystem:"
db.execute(<<~SQL).each do |r|
  SELECT p.ecosystem, COUNT(DISTINCT p.purl) AS n
  FROM packages p JOIN repos r ON r.repository_url = p.repository_url
  WHERE r.has_rust = 1 AND (r.cargo_toml_count > 0 OR COALESCE(r.bridge_tools,'') <> '')
    AND p.ecosystem <> 'cargo'
  GROUP BY p.ecosystem ORDER BY n DESC
SQL
  puts "  #{r["ecosystem"].ljust(12)} #{r["n"]}"
end
puts

puts "by bridge tool:"
db.execute("SELECT bridge_tools FROM repos r WHERE #{RUST}")
  .flat_map { |r| (r["bridge_tools"] || "").split(",") }
  .reject(&:empty?)
  .tally
  .sort_by { |_, n| -n }
  .each { |tool, n| puts "  #{tool.ljust(18)} #{n}" }
none = db.get_first_value("SELECT COUNT(*) FROM repos r WHERE #{RUST} AND (bridge_tools IS NULL OR bridge_tools = '')")
puts "  #{"(none detected)".ljust(18)} #{none}"
puts

rows = db.execute(<<~SQL)
  SELECT
    p.purl, p.ecosystem, p.name, p.registry,
    p.dependent_repos, p.dependent_packages, p.downloads, p.downloads_period,
    p.latest_release, p.latest_release_at,
    r.repository_url, r.stars,
    r.rust_loc, r.total_loc, r.brief_languages,
    r.bridge_tools, r.has_cargo_lock, r.cargo_toml_count,
    r.cargo_toml_paths, r.cargo_lock_paths, r.signals
  FROM packages p
  JOIN repos r ON r.repository_url = p.repository_url
  WHERE r.has_rust = 1 AND (r.cargo_toml_count > 0 OR COALESCE(r.bridge_tools,'') <> '')
    AND p.ecosystem <> 'cargo'
  ORDER BY COALESCE(p.dependent_repos, 0) DESC, COALESCE(p.downloads, 0) DESC
SQL
rows.each do |r|
  r["sibling_runtime"] = sibling_runtime?(r["brief_languages"], r["bridge_tools"], r["cargo_toml_paths"]) ? 1 : 0
end

csv_path = File.join(OUT, "embedded-rust.csv")
CSV.open(csv_path, "w") do |csv|
  csv << %w[
    purl ecosystem name registry dependent_repos dependent_packages downloads downloads_period
    latest_release latest_release_at repository_url stars rust_loc total_loc
    bridge_tools sibling_runtime has_cargo_lock cargo_toml_count cargo_toml_paths cargo_lock_paths signals
  ]
  rows.each do |r|
    csv << [
      r["purl"], r["ecosystem"], r["name"], r["registry"],
      r["dependent_repos"], r["dependent_packages"], r["downloads"], r["downloads_period"],
      r["latest_release"], r["latest_release_at"], r["repository_url"], r["stars"],
      r["rust_loc"], r["total_loc"],
      r["bridge_tools"], r["sibling_runtime"], r["has_cargo_lock"], r["cargo_toml_count"],
      (r["cargo_toml_paths"] || "").tr("\n", ";"), (r["cargo_lock_paths"] || "").tr("\n", ";"),
      r["signals"],
    ]
  end
end

puts "top 20 by dependent_repos:"
rows.first(20).each do |r|
  bridge = (r["bridge_tools"] || "").empty? ? "-" : r["bridge_tools"]
  lock   = r["has_cargo_lock"] == 1 ? "lock" : "    "
  printf "  %-42s %8s deps  %6s rloc  %-16s %s  %s\n",
         r["purl"][0, 42], r["dependent_repos"], r["rust_loc"], bridge[0, 16], lock, r["repository_url"]
end
puts
puts "wrote #{rows.size} packages -> #{csv_path}"

# Scrutineer bulk-import list: one https URL per line, optionally with a
# `#sub/dir` suffix when the Rust crate lives below the repo root. For
# workspaces (multiple Cargo.toml) we emit the shallowest crate directory
# and let scrutineer's own subprojects skill discover the members.
repo_rows = db.execute(<<~SQL)
  SELECT r.repository_url, r.cargo_toml_paths, r.brief_languages, r.bridge_tools,
         MAX(COALESCE(p.dependent_repos, 0)) AS dep_repos
  FROM repos r JOIN packages p ON p.repository_url = r.repository_url
  WHERE r.has_rust = 1 AND (r.cargo_toml_count > 0 OR COALESCE(r.bridge_tools,'') <> '')
    AND p.ecosystem <> 'cargo'
  GROUP BY r.repository_url
  ORDER BY dep_repos DESC
SQL

def scrutineer_line(url, tomls)
  return url if tomls.empty?
  dir = File.dirname(tomls.min_by { |p| p.count("/") })
  dir == "." ? url : "#{url}##{dir}"
end

embedded, sibling = repo_rows.partition do |r|
  !sibling_runtime?(r["brief_languages"], r["bridge_tools"], r["cargo_toml_paths"])
end

scrutineer_path = File.join(OUT, "scrutineer.txt")
File.open(scrutineer_path, "w") do |f|
  embedded.each do |r|
    f.puts scrutineer_line(r["repository_url"], (r["cargo_toml_paths"] || "").split("\n").reject(&:empty?))
  end
  unless sibling.empty?
    f.puts
    f.puts "# sibling-runtime: rust/ published to crates.io independently, not compiled into the host package"
    sibling.each do |r|
      f.puts scrutineer_line(r["repository_url"], (r["cargo_toml_paths"] || "").split("\n").reject(&:empty?))
    end
  end
end
puts "wrote #{embedded.size} embedded + #{sibling.size} sibling-runtime repos -> #{scrutineer_path}"

# Repos that ship Rust into a host package but commit no Cargo.lock. The wheel
# / .node / NIF was built from a resolved tree that isn't recorded in the repo,
# so advisories.rb has only constraint strings to query and the shipped crate
# versions are unknowable without unpacking the artefact or its CI build log.
nolock = db.execute(<<~SQL)
  SELECT r.repository_url, r.cargo_toml_count, r.bridge_tools, r.cargo_toml_paths, r.brief_languages,
         MAX(COALESCE(p.dependent_repos, 0)) AS dep_repos,
         GROUP_CONCAT(DISTINCT p.ecosystem) AS ecosystems,
         GROUP_CONCAT(DISTINCT p.purl) AS purls
  FROM repos r JOIN packages p ON p.repository_url = r.repository_url
  WHERE r.has_rust = 1 AND r.cargo_toml_count > 0 AND r.has_cargo_lock = 0
    AND p.ecosystem <> 'cargo' AND #{HOST}
  GROUP BY r.repository_url
  ORDER BY dep_repos DESC
SQL
nolock.each do |r|
  r["sibling_runtime"] = sibling_runtime?(r["brief_languages"], r["bridge_tools"], r["cargo_toml_paths"]) ? 1 : 0
end
nolock_path = File.join(OUT, "no-lock.csv")
CSV.open(nolock_path, "w") do |csv|
  csv << %w[repository_url ecosystems dependent_repos cargo_toml_count bridge_tools sibling_runtime purls]
  nolock.each do |r|
    csv << [r["repository_url"], r["ecosystems"], r["dep_repos"], r["cargo_toml_count"],
            r["bridge_tools"], r["sibling_runtime"], r["purls"]]
  end
end
nolock_embedded = nolock.count { |r| r["sibling_runtime"] == 0 }
puts "wrote #{nolock.size} no-Cargo.lock repos (#{nolock_embedded} embedded, #{nolock.size - nolock_embedded} sibling-runtime) -> #{nolock_path}"

# Repos where the filesystem says Rust but brief under-reported. Two shapes:
#   hard: Cargo.toml / Cargo.lock / Rust LOC on disk, brief reported nothing
#         Rust-related at all. Missing knowledge entry or detection bug.
#   soft: Cargo.toml on disk, brief reported the Rust language but not Cargo
#         and not a bridge tool. Usually a scan-depth issue (crate lives in a
#         subdirectory brief didn't reach).
gaps = db.execute(<<~SQL)
  SELECT repository_url, rust_loc, cargo_toml_count, has_cargo_lock,
         cargo_toml_paths, brief_languages, signals,
         CASE WHEN signals NOT LIKE '%brief:%' THEN 'hard' ELSE 'soft' END AS kind
  FROM repos r
  WHERE #{RUST}
    AND (signals NOT LIKE '%brief:%'
         OR (cargo_toml_count > 0
             AND signals NOT LIKE '%brief:cargo%'
             AND signals NOT LIKE '%brief:bridge%'))
  ORDER BY kind, rust_loc DESC
SQL

gaps_path = File.join(OUT, "brief-gaps.md")
File.open(gaps_path, "w") do |f|
  f.puts "# brief detection gaps"
  f.puts
  f.puts "Repos with Cargo.toml / Cargo.lock / Rust LOC on disk where `brief` reported"
  f.puts "no Rust language, no Cargo package manager, and no Rust bridge tool. Each is"
  f.puts "either a missing knowledge entry or a detection bug."
  f.puts
  f.puts "Generated by rust-deps/report.rb from #{rust_repos} rust repos."
  f.puts
  if gaps.empty?
    f.puts "None found."
  else
    gaps.each do |g|
      f.puts "## #{g["repository_url"]} (#{g["kind"]})"
      f.puts
      f.puts "- rust_loc: #{g["rust_loc"]}"
      f.puts "- cargo_toml: #{g["cargo_toml_count"]} (#{(g["cargo_toml_paths"] || "").tr("\n", " ")})"
      f.puts "- cargo_lock: #{g["has_cargo_lock"] == 1 ? "yes" : "no"}"
      f.puts "- brief languages: #{g["brief_languages"]}"
      f.puts "- signals: #{g["signals"]}"
      f.puts "- brief cache: cache/brief/#{Digest::SHA256.hexdigest(g["repository_url"])[0, 32]}.json"
      f.puts
    end
  end
end
puts "wrote #{gaps.size} brief gaps -> #{gaps_path}"

# Crate dependency aggregate: which cargo crates appear in the most
# embedding repos. Direct deps only until brief also parses Cargo.lock.
if db.get_first_value("SELECT name FROM sqlite_master WHERE type='table' AND name='crate_deps'")
  crate_rows = db.execute(<<~SQL)
    SELECT c.crate,
           COUNT(DISTINCT c.repository_url) AS repos,
           GROUP_CONCAT(DISTINCT c.requirement) AS requirements,
           GROUP_CONCAT(DISTINCT c.scope) AS scopes,
           GROUP_CONCAT(DISTINCT c.repository_url) AS repo_urls
    FROM crate_deps c
    JOIN repos r ON r.repository_url = c.repository_url
    WHERE r.has_rust = 1 AND #{HOST}
    GROUP BY c.crate
    ORDER BY repos DESC, c.crate
  SQL

  crates_path = File.join(OUT, "crate-deps.csv")
  CSV.open(crates_path, "w") do |csv|
    csv << %w[crate embedding_repos requirements scopes repo_urls]
    crate_rows.each do |r|
      csv << [r["crate"], r["repos"], r["requirements"], r["scopes"], r["repo_urls"]]
    end
  end

  puts
  puts "top 20 crates by embedding repos:"
  crate_rows.first(20).each do |r|
    printf "  %-24s %3d repos  %s\n", r["crate"], r["repos"], (r["scopes"] || "")[0, 20]
  end
  puts
  puts "wrote #{crate_rows.size} crates -> #{crates_path}"
end
