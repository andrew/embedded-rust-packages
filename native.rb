#!/usr/bin/env ruby
# Derive C/C++ presence for every scanned repo from the cached `brief --json`
# output written by scan.rb, store it alongside the Rust columns in repos, and
# print a Rust vs C/C++ adoption comparison per ecosystem.
#
# No cloning: everything comes from cache/brief/<hkey>.json. That cache was
# written by whichever brief version scan.rb ran at the time; C/C++ language
# detection was not touched by the 0.11 fixes so 0.10 output is fine here.
#
# has_rust in the db comes from a filesystem Cargo.toml check. There is no
# equivalent filesystem check for C build files, so has_c is derived purely
# from brief signals: language present, or a known C/C++ bridge / build tool.
# The two are not perfectly symmetric; the report shows both the loose
# (language seen) and tight (bridge or build tool seen) counts so the
# comparison can be read either way.
#
# Usage: ruby native.rb

require "json"
require "sqlite3"
require "digest"
require "csv"
require "set"
require "fileutils"
require_relative "c_vendoring"

WORKDIR = __dir__
DB_PATH = File.join(WORKDIR, "rustdeps.db")
BRIEF   = File.join(WORKDIR, "cache", "brief")
OUT     = File.join(WORKDIR, "out")

FileUtils.mkdir_p(OUT)

def hkey(url) = Digest::SHA256.hexdigest(url)[0, 32]

# brief tool names that indicate C/C++ is compiled into the host-language
# artefact. brief has no knowledge entries for pybind11/Cython/cffi/SWIG/
# nanobind yet, so this undercounts relative to the Rust bridge list.
# meson-python is included: it builds C, C++, Fortran or Rust, but a
# meson-python project without a Cargo.toml is building non-Rust native code.
C_BRIDGE_TOOLS = [
    "setuptools Extension", "mkmf", "node-gyp", "phpize", "meson-python",
]

# Build-system tools that imply compiled C/C++ somewhere in the tree. Make is
# excluded: too many pure-Ruby/Python/JS projects use it as a task runner.
C_BUILD_TOOLS = ["CMake", "Autotools", "Meson"]

# Ecosystems where the package artefact is itself native C/C++, so "contains
# C/C++" is not a signal. None of these are currently fetched; listed so the
# exclusion is explicit if the corpus widens.
C_NATIVE_ECOSYSTEMS = %w[conan vcpkg homebrew spack]

db = SQLite3::Database.new(DB_PATH)
db.busy_timeout = 30_000
db.results_as_hash = true

cols = db.execute("PRAGMA table_info(repos)").map { |r| r["name"] }
{
    "has_c"          => "INTEGER",
    "c_loc"          => "INTEGER",
    "cpp_loc"        => "INTEGER",
    "c_bridge_tools" => "TEXT",
    "c_build_tools"  => "TEXT",
    "c_signals"      => "TEXT",
    "has_submodules" => "INTEGER",
}.each do |col, type|
    db.execute("ALTER TABLE repos ADD COLUMN #{col} #{type}") unless cols.include?(col)
end
db.execute("CREATE INDEX IF NOT EXISTS idx_repos_has_c ON repos(has_c)")

upd = db.prepare("UPDATE repos SET has_c=?, c_loc=?, cpp_loc=?, c_bridge_tools=?, c_build_tools=?, c_signals=?, has_submodules=? WHERE repository_url=?")

urls = db.execute("SELECT repository_url FROM repos WHERE scanned_at IS NOT NULL").map { |r| r["repository_url"] }
puts "#{urls.size} scanned repos"

hit = c = 0
db.transaction
urls.each_with_index do |url, i|
    path = File.join(BRIEF, "#{hkey(url)}.json")
    unless File.exist?(path)
        upd.execute(0, nil, nil, nil, nil, nil, nil, url)
        next
    end
    b = JSON.parse(File.read(path)) rescue {}

    langs   = (b["languages"] || []).map { |l| l["name"] }
    tools   = (b["tools"] || {}).values.flatten.map { |t| t["name"] }
    by_lang = b.dig("lines", "by_language") || {}

    c_loc   = by_lang.values_at("C", "C Header").compact.sum
    cpp_loc = by_lang.values_at("C++", "C++ Header").compact.sum
    bridges = tools & C_BRIDGE_TOOLS
    builds  = tools & C_BUILD_TOOLS

    submod = tools.include?("Git Submodules") ? 1 : 0

    signals = []
    signals << "brief:lang"   if (langs & %w[C C++]).any?
    signals << "brief:bridge" if bridges.any?
    signals << "brief:build"  if builds.any?
    signals << "c_loc"        if c_loc > 0
    signals << "cpp_loc"      if cpp_loc > 0
    signals << "submod"       if submod == 1

    # Language alone is enough for has_c: C/C++ source in a pypi/npm/gem repo
    # almost always ships in the wheel/tarball. The bridge/build columns let
    # the report distinguish "definitely compiled in" from "source present".
    has_c = ((langs & %w[C C++]).any? || bridges.any? || builds.any?) ? 1 : 0

    upd.execute(has_c, c_loc, cpp_loc, bridges.join(","), builds.join(","), signals.join(","), submod, url)
    hit += 1
    c += has_c
    print "\r[#{i + 1}/#{urls.size}] brief=#{hit} c=#{c}" if (i % 200).zero?
end
db.commit
upd.close
puts "\r[#{urls.size}/#{urls.size}] brief=#{hit} c=#{c}"
puts

# --- comparison report -------------------------------------------------------

# has_rust as stored (filesystem Cargo.toml || rust bridge). For a symmetric
# view alongside has_c, also count "rust language seen by brief" separately.
scanned = db.get_first_value("SELECT COUNT(*) FROM repos WHERE scanned_at IS NOT NULL")
rust_fs = db.get_first_value("SELECT COUNT(*) FROM repos WHERE has_rust = 1")
rust_lang = db.get_first_value("SELECT COUNT(*) FROM repos WHERE brief_languages LIKE '%Rust%'")
c_any   = db.get_first_value("SELECT COUNT(*) FROM repos WHERE has_c = 1")
c_tight = db.get_first_value("SELECT COUNT(*) FROM repos WHERE has_c = 1 AND (c_bridge_tools <> '' OR c_build_tools <> '')")
both    = db.get_first_value("SELECT COUNT(*) FROM repos WHERE has_c = 1 AND has_rust = 1")

puts "totals (repos, of #{scanned} scanned):"
puts "  rust (Cargo.toml on disk)         #{rust_fs}"
puts "  rust (brief language)             #{rust_lang}"
puts "  c/c++ (brief language or tool)    #{c_any}"
puts "  c/c++ (bridge or build tool)      #{c_tight}"
puts "  both rust and c/c++               #{both}"
puts

eco_excl = C_NATIVE_ECOSYSTEMS.map { |e| "'#{e}'" }.join(",")
by_eco = db.execute(<<~SQL)
    SELECT p.ecosystem,
           COUNT(DISTINCT r.repository_url) AS repos,
           COUNT(DISTINCT CASE WHEN r.has_rust = 1 THEN r.repository_url END) AS rust,
           COUNT(DISTINCT CASE WHEN r.has_c = 1 THEN r.repository_url END)    AS c_any,
           COUNT(DISTINCT CASE WHEN r.has_c = 1 AND (r.c_bridge_tools <> '' OR r.c_build_tools <> '') THEN r.repository_url END) AS c_tight,
           COUNT(DISTINCT CASE WHEN r.has_rust = 1 AND r.has_c = 1 THEN r.repository_url END) AS both
    FROM packages p
    JOIN repos r ON r.repository_url = p.repository_url
    WHERE r.scanned_at IS NOT NULL
      AND p.ecosystem NOT IN (#{eco_excl})
    GROUP BY p.ecosystem
    ORDER BY repos DESC
SQL

puts "by ecosystem (distinct repos):"
printf "  %-12s %8s %8s %8s %8s %8s %8s %8s\n", "ecosystem", "repos", "rust", "rust%", "c/c++", "c%", "c-tight", "both"
by_eco.each do |r|
    n = r["repos"].to_f
    printf "  %-12s %8d %8d %7.1f%% %8d %7.1f%% %8d %8d\n",
           r["ecosystem"], r["repos"], r["rust"], 100.0 * r["rust"] / n,
           r["c_any"], 100.0 * r["c_any"] / n, r["c_tight"], r["both"]
end
puts

puts "c/c++ bridge tools:"
db.execute("SELECT c_bridge_tools FROM repos WHERE has_c = 1")
    .flat_map { |r| (r["c_bridge_tools"] || "").split(",") }
    .reject(&:empty?).tally.sort_by { |_, n| -n }
    .each { |t, n| puts "  #{t.ljust(24)} #{n}" }
puts

puts "c/c++ build tools:"
db.execute("SELECT c_build_tools FROM repos WHERE has_c = 1")
    .flat_map { |r| (r["c_build_tools"] || "").split(",") }
    .reject(&:empty?).tally.sort_by { |_, n| -n }
    .each { |t, n| puts "  #{t.ljust(24)} #{n}" }
puts

csv_path = File.join(OUT, "native-compare.csv")
CSV.open(csv_path, "w") do |csv|
    csv << %w[ecosystem repos rust rust_pct c_any c_pct c_tight both]
    by_eco.each do |r|
        n = r["repos"].to_f
        csv << [r["ecosystem"], r["repos"], r["rust"], (100.0 * r["rust"] / n).round(2),
                r["c_any"], (100.0 * r["c_any"] / n).round(2), r["c_tight"], r["both"]]
    end
end
puts "wrote #{csv_path}"

if db.get_first_value("SELECT name FROM sqlite_master WHERE type='table' AND name='crate_deps'")
    all = db.execute(<<~SQL)
        SELECT p.purl, p.ecosystem, p.dependent_repos, r.repository_url, r.bridge_tools,
               GROUP_CONCAT(DISTINCT c.crate) AS crates
        FROM crate_deps c
        JOIN repos r ON r.repository_url = c.repository_url
        JOIN packages p ON p.repository_url = r.repository_url
        WHERE p.ecosystem <> 'cargo'
        GROUP BY p.purl
        ORDER BY COALESCE(p.dependent_repos, 0) DESC
    SQL
    doll_rows = all.filter_map do |r|
        vc = r["crates"].split(",").select { |n| CVendoring.vendors_c?(n) }
        next if vc.empty?
        r.merge("c_crates" => vc.sort.join(","))
    end
    doll_repos = doll_rows.map { |r| r["repository_url"] }.uniq

    puts "nested C via -sys crates (host pkg -> rust -> vendored C):"
    puts "  #{doll_repos.size} repos, #{doll_rows.size} packages"
    doll_rows.first(15).each do |r|
        printf "  %-42s %8s deps  %-16s  %s\n",
               r["purl"][0, 42], r["dependent_repos"], (r["bridge_tools"] || "-")[0, 16], r["c_crates"][0, 60]
    end
    puts

    doll_csv = File.join(OUT, "nested-c.csv")
    CSV.open(doll_csv, "w") do |csv|
        csv << %w[purl ecosystem dependent_repos repository_url bridge_tools c_crates]
        doll_rows.each { |r| csv << [r["purl"], r["ecosystem"], r["dependent_repos"], r["repository_url"], r["bridge_tools"], r["c_crates"]] }
    end
    puts "wrote #{doll_rows.size} nested-C packages -> #{doll_csv}"

    puts
    puts "vendored-C crates by embedding-repo count:"
    tally = Hash.new { |h, k| h[k] = Set.new }
    doll_rows.each { |r| r["c_crates"].split(",").each { |c| tally[c] << r["repository_url"] } }
    tally.sort_by { |_, s| -s.size }.first(30).each { |c, s| printf "  %-24s %3d repos\n", c, s.size }
    puts
end

submod_rows = db.execute(<<~SQL)
    SELECT r.repository_url, GROUP_CONCAT(DISTINCT p.ecosystem) AS ecosystems,
           MAX(COALESCE(p.dependent_repos,0)) AS dependent_repos,
           r.has_rust, r.has_c, r.c_loc, r.cpp_loc, r.c_build_tools, r.brief_languages
    FROM repos r JOIN packages p ON p.repository_url = r.repository_url
    WHERE r.has_submodules = 1
    GROUP BY r.repository_url
    ORDER BY dependent_repos DESC
SQL
submod_csv = File.join(OUT, "submodule-repos.csv")
CSV.open(submod_csv, "w") do |csv|
    csv << %w[repository_url ecosystems dependent_repos has_rust has_c c_loc cpp_loc c_build_tools brief_languages]
    submod_rows.each { |r| csv << r.values_at(*%w[repository_url ecosystems dependent_repos has_rust has_c c_loc cpp_loc c_build_tools brief_languages]) }
end
puts "wrote #{submod_rows.size} submodule repos -> #{submod_csv}"
puts "  has_c=0 among them: #{submod_rows.count { |r| r["has_c"] != 1 }} (submodule content not fetched, may hide vendored source)"
puts

repo_csv = File.join(OUT, "c-repos.csv")
c_rows = db.execute(<<~SQL)
    SELECT r.repository_url, r.c_loc, r.cpp_loc, r.c_bridge_tools, r.c_build_tools,
           r.has_rust, r.rust_loc, r.brief_languages,
           GROUP_CONCAT(DISTINCT p.ecosystem) AS ecosystems,
           MAX(COALESCE(p.dependent_repos, 0)) AS dependent_repos
    FROM repos r JOIN packages p ON p.repository_url = r.repository_url
    WHERE r.has_c = 1 AND p.ecosystem NOT IN (#{eco_excl})
    GROUP BY r.repository_url
    ORDER BY dependent_repos DESC
SQL
CSV.open(repo_csv, "w") do |csv|
    csv << %w[repository_url ecosystems dependent_repos c_loc cpp_loc c_bridge_tools c_build_tools has_rust rust_loc brief_languages]
    c_rows.each do |r|
        csv << [r["repository_url"], r["ecosystems"], r["dependent_repos"], r["c_loc"], r["cpp_loc"],
                r["c_bridge_tools"], r["c_build_tools"], r["has_rust"], r["rust_loc"], r["brief_languages"]]
    end
end
puts "wrote #{c_rows.size} c/c++ repos -> #{repo_csv}"
