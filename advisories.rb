#!/usr/bin/env ruby
# For every embedded-Rust repo, take the resolved crate versions from
# crate_deps (Cargo.lock rows written by crates.rb) and query OSV for known
# advisories. Any hit is a Rust-ecosystem advisory that host-language tooling
# (npm audit, bundler-audit, pip-audit, mix hex.audit) will not report because
# the advisory is filed against ecosystem=crates.io, not the host purl.
#
# Writes out/nested-advisories.csv: one row per (host purl, crate, advisory).
#
# Usage: ruby advisories.rb

require "sqlite3"
require "json"
require "csv"
require "fileutils"
require_relative "http"
require_relative "c_vendoring"

WORKDIR = __dir__
DB_PATH = File.join(WORKDIR, "rustdeps.db")
OUT     = File.join(WORKDIR, "out")
OSV     = conn("https://api.osv.dev")

FileUtils.mkdir_p(OUT)

db = SQLite3::Database.new(DB_PATH)
db.busy_timeout = 30_000
db.results_as_hash = true

# Resolved versions only. Cargo.lock always writes full x.y.z; a two-part "1.0"
# is almost always a Cargo.toml constraint from a crate dir with no lockfile,
# and OSV would treat it as literal 1.0.0. zstd-sys pins like
# "2.0.10+zstd.1.5.6" keep the build-metadata suffix.
RESOLVED = /\A\d+\.\d+\.\d+(\.\d+)?([+\-][\w.+-]+)?\z/

deps = db.execute(<<~SQL)
    SELECT DISTINCT c.crate, c.requirement
    FROM crate_deps c
    JOIN packages p ON p.repository_url = c.repository_url
    WHERE p.ecosystem <> 'cargo' AND c.requirement IS NOT NULL
SQL
deps = deps.select { |d| d["requirement"].match?(RESOLVED) }
puts "#{deps.size} distinct (crate, version) to query"

# OSV batch: returns only ids per query; fetch full records for hits after.
vulns_for = {}
deps.each_slice(500).with_index do |batch, i|
    body = { queries: batch.map { |d| { package: { ecosystem: "crates.io", name: d["crate"] }, version: d["requirement"] } } }
    res = OSV.post("/v1/querybatch", JSON.generate(body), "Content-Type" => "application/json")
    raise "osv #{res.status}" unless res.success?
    JSON.parse(res.body)["results"].each_with_index do |r, j|
        ids = (r["vulns"] || []).map { |v| v["id"] }
        vulns_for[[batch[j]["crate"], batch[j]["requirement"]]] = ids unless ids.empty?
    end
    print "\r[#{[(i + 1) * 500, deps.size].min}/#{deps.size}] #{vulns_for.size} vulnerable (crate,version) pairs"
    sleep 0.3
end
puts

vuln_detail = {}
vulns_for.values.flatten.uniq.each_slice(50) do |ids|
    ids.each do |id|
        res = OSV.get("/v1/vulns/#{id}")
        next unless res.success?
        v = JSON.parse(res.body)
        sev = (v["severity"] || []).map { |s| s["score"] }.first
        info = v.dig("database_specific", "informational") ||
               (v["affected"] || []).map { |a| a.dig("database_specific", "informational") }.compact.first
        vuln_detail[id] = { "summary" => v["summary"] || (v["details"] || "")[0, 120],
                            "aliases" => (v["aliases"] || []) + (v["related"] || []),
                            "severity" => sev, "published" => v["published"],
                            "informational" => info }
    end
    sleep 0.3
end

# OSV returns the RUSTSEC record and its GHSA alias as separate hits for the
# same (crate, version). Only RUSTSEC carries database_specific.informational,
# so without grouping the GHSA copy of an "unsound" advisory reads as a vuln.
# Group by alias closure, pick one canonical id (RUSTSEC > GHSA > CVE > other),
# and merge informational/severity across the group.
def canonicalise(details)
    parent = {}
    find = ->(x) { parent[x] == x ? x : parent[x] = find.call(parent[x]) }
    details.each_key { |id| parent[id] = id }
    details.each do |id, d|
        d["aliases"].each do |a|
            parent[a] ||= a
            ra, rb = find.call(id), find.call(a)
            parent[ra] = rb unless ra == rb
        end
    end
    groups = Hash.new { |h, k| h[k] = [] }
    parent.each_key { |id| groups[find.call(id)] << id }

    rank = ->(id) { [%w[RUSTSEC GHSA CVE].index { |p| id.start_with?(p) } || 9, id] }
    canon = {}
    groups.each_value do |ids|
        c = ids.min_by(&rank)
        members = ids.filter_map { |i| details[i] }
        merged = {
            "summary"       => members.map { |m| m["summary"] }.compact.first,
            "aliases"       => (ids - [c]).sort_by(&rank).join(" "),
            "severity"      => members.map { |m| m["severity"] }.compact.max,
            "published"     => members.map { |m| m["published"] }.compact.min,
            "informational" => members.map { |m| m["informational"] }.compact.first,
        }
        ids.each { |i| canon[i] = [c, merged] }
    end
    canon
end

canon = canonicalise(vuln_detail)
vulns_for.transform_values! { |ids| ids.map { |i| canon[i]&.first || i }.uniq }

# brief-on-root parses every Cargo.lock it discovers (root + nested standalone
# tools) and merges their deps into one flat dependencies[] with no source
# path per row. crates.rb records all of them at cargo_dir=".", and separately
# records the nested lockfile's deps at cargo_dir=<subdir> from its own brief
# invocation. Drop the root duplicate so an ancillary tool's stale pin isn't
# attributed to the shipped artefact.
rows = db.execute(<<~SQL)
    SELECT c.repository_url, c.cargo_dir, c.crate, c.requirement, c.direct,
           p.purl, p.ecosystem, p.name, p.dependent_repos
    FROM crate_deps c
    JOIN packages p ON p.repository_url = c.repository_url
    WHERE p.ecosystem <> 'cargo' AND c.requirement IS NOT NULL
      AND NOT (c.cargo_dir = '.' AND EXISTS (
          SELECT 1 FROM crate_deps n
          WHERE n.repository_url = c.repository_url AND n.cargo_dir <> '.'
            AND n.crate = c.crate AND n.requirement = c.requirement))
SQL

hits = []
rows.each do |r|
    ids = vulns_for[[r["crate"], r["requirement"]]] or next
    ids.each do |id|
        _, d = canon[id] || [id, {}]
        hits << r.merge("advisory" => id, "summary" => d["summary"], "aliases" => d["aliases"],
                        "severity" => d["severity"], "published" => d["published"],
                        "informational" => d["informational"],
                        "vendors_c" => CVendoring.vendors_c?(r["crate"]) ? 1 : 0)
    end
end
hits.uniq! { |h| [h["purl"], h["cargo_dir"], h["crate"], h["requirement"], h["advisory"]] }
hits.sort_by! { |h| [-(h["dependent_repos"] || 0), h["purl"], h["crate"]] }

csv_path = File.join(OUT, "nested-advisories.csv")
CSV.open(csv_path, "w") do |csv|
    csv << %w[purl ecosystem dependent_repos repository_url cargo_dir crate version direct vendors_c advisory aliases severity informational published summary]
    hits.each do |h|
        csv << [h["purl"], h["ecosystem"], h["dependent_repos"], h["repository_url"], h["cargo_dir"],
                h["crate"], h["requirement"], h["direct"], h["vendors_c"],
                h["advisory"], h["aliases"], h["severity"], h["informational"], h["published"], h["summary"]]
    end
end

real = hits.reject { |h| h["informational"] }
puts
puts "#{hits.size} (purl, crate@version, advisory) rows"
puts "  #{real.size} non-informational (excluding unmaintained/unsound/notice)"
puts "  #{real.map { |h| h["purl"] }.uniq.size} host packages, #{real.map { |h| h["repository_url"] }.uniq.size} repos"
puts "  #{real.map { |h| [h["crate"], h["requirement"]] }.uniq.size} distinct vulnerable crate@version"
puts "  #{real.count { |h| h["vendors_c"] == 1 }} rows via C-vendoring -sys crates"
puts
puts "top non-informational by host dependent_repos:"
seen = {}
real.each do |h|
    key = [h["purl"], h["crate"]]
    next if seen[key]
    seen[key] = true
    printf "  %-40s  %-24s %-10s  %s  %s\n",
           h["purl"][0, 40], "#{h["crate"]}@#{h["requirement"]}"[0, 24],
           (h["vendors_c"] == 1 ? "vendors-C" : ""), h["advisory"], (h["summary"] || "")[0, 60]
    break if seen.size >= 25
end
puts
puts "informational tallies:"
hits.map { |h| h["informational"] || "vuln" }.tally.sort_by { |_, n| -n }
    .each { |k, n| puts "  #{k.ljust(16)} #{n}" }
puts
puts "wrote #{csv_path}"

# --- upstream C layer -------------------------------------------------------
# For -sys crates that encode the vendored C version in +metadata, query OSV's
# distro ecosystems for CVEs against that upstream version. These are advisories
# that would only reach the crate if someone re-filed them as a RUSTSEC, which
# for most C libraries nobody does.

up_targets = deps.filter_map do |d|
    up = CVendoring.upstream_for(d["crate"], d["requirement"])
    up && [d["crate"], d["requirement"], *up]
end.uniq
puts
puts "#{up_targets.size} (crate, version) with extractable upstream C version"

up_vulns = {}
up_targets.each do |crate, req, up_name, up_ver|
    cves = {}
    CVendoring::UPSTREAM_ECOSYSTEMS.each do |eco|
        res = OSV.post("/v1/query",
                       JSON.generate(package: { ecosystem: eco, name: up_name }, version: up_ver),
                       "Content-Type" => "application/json")
        next unless res.success?
        (JSON.parse(res.body)["vulns"] || []).each do |v|
            ids = [v["id"], *(v["aliases"] || []), *(v["upstream"] || [])].compact
            cve = ids.join(" ")[/CVE-\d{4}-\d{3,}/]
            next unless cve
            cves[cve] ||= { "summary" => v["summary"] || (v["details"] || "")[0, 120],
                            "severity" => (v["severity"] || []).map { |s| s["score"] }.first,
                            "sources" => [] }
            cves[cve]["sources"] << v["id"]
        end
    end
    up_vulns[[crate, req, up_name, up_ver]] = cves unless cves.empty?
    sleep 0.2
end

# Distro trackers over-match (introduced=0, unrejected candidates, wrong
# component). Cross-check each CVE against NVD: drop if rejected, and drop if
# NVD has CPE version bounds and the vendored version is outside them.
NVD = conn("https://services.nvd.nist.gov")
NVD_CACHE = File.join(WORKDIR, "cache", "nvd")
# OSV distro package name -> NVD CPE product name(s) where they differ.
CPE_PRODUCT_ALIAS = {
    "sqlite3"  => "sqlite",
    "xz"       => %w[xz xz-utils xz_utils],
    "zlib"     => %w[zlib zlib1g],
    "curl"     => %w[curl libcurl],
    "openssl"  => "openssl",
    "libwebp"  => %w[libwebp webp],
    "aws-lc"   => %w[aws-lc aws_lc aws-lc-rs],
    "rocksdb"  => "rocksdb",
    "jemalloc" => "jemalloc",
    "mimalloc" => "mimalloc",
    "c-blosc2" => %w[c-blosc2 c_blosc2 blosc2],
}
FileUtils.mkdir_p(NVD_CACHE)
def nvd_record(cve)
    path = File.join(NVD_CACHE, "#{cve}.json")
    return JSON.parse(File.read(path)) if File.exist?(path)
    sleep 6.1
    res = NVD.get("/rest/json/cves/2.0", cveId: cve)
    return nil unless res.success?
    data = (JSON.parse(res.body)["vulnerabilities"] || []).first
    File.write(path, JSON.generate(data)) if data
    data
end
def nvd_applies?(cve, upstream_name, upstream_ver)
    data = nvd_record(cve)
    return :unknown unless data
    c = data["cve"]
    return :rejected if c["vulnStatus"] == "Rejected" || (c["descriptions"] || []).any? { |d| d["value"].to_s.start_with?("Rejected reason:") }
    matches = (c["configurations"] || []).flat_map { |cfg| cfg["nodes"] || [] }.flat_map { |n| n["cpeMatch"] || [] }
    names = [upstream_name, upstream_name.tr("-", "_"), *Array(CPE_PRODUCT_ALIAS[upstream_name])]
    relevant = matches.select { |m| names.any? { |n| m["criteria"].to_s.include?(":#{n}:") } }
    return :no_cpe if relevant.empty?
    v = Gem::Version.new(upstream_ver) rescue (return :unknown)
    gv = ->(s) { Gem::Version.new(s) rescue nil }
    in_range = relevant.any? do |m|
        # cpe:2.3:a:vendor:product:version:update:...
        cpe_ver = m["criteria"].to_s.split(":")[5]
        lo_i = m["versionStartIncluding"]; lo_e = m["versionStartExcluding"]
        hi_i = m["versionEndIncluding"];   hi_e = m["versionEndExcluding"]
        if [lo_i, lo_e, hi_i, hi_e].all?(&:nil?)
            # No range fields: NVD encoded an exact version in the CPE string.
            # `*` or `-` there means "all versions" (rare on modern entries).
            next true if cpe_ver == "*" || cpe_ver == "-"
            cv = gv[cpe_ver]
            next cv && v == cv
        end
        (lo_i.nil? || (gv[lo_i] && v >= gv[lo_i])) &&
        (lo_e.nil? || (gv[lo_e] && v >  gv[lo_e])) &&
        (hi_i.nil? || (gv[hi_i] && v <= gv[hi_i])) &&
        (hi_e.nil? || (gv[hi_e] && v <  gv[hi_e]))
    end
    in_range ? :in_range : :out_of_range
end

all_cves = up_vulns.values.flat_map(&:keys).uniq
puts "cross-checking #{all_cves.size} CVEs against NVD (cache/nvd, ~6s/uncached)"
up_vulns.each do |(crate, req, up_name, up_ver), cves|
    cves.each { |cve, d| d["nvd"] = nvd_applies?(cve, up_name, up_ver).to_s }
    cves.reject! { |_, d| %w[rejected out_of_range].include?(d["nvd"]) }
end
up_vulns.reject! { |_, v| v.empty? }

up_rows = []
rows.each do |r|
    v = up_vulns[[r["crate"], r["requirement"], *CVendoring.upstream_for(r["crate"], r["requirement"])].compact]
    next unless v
    v.each do |cve, d|
        up_rows << r.merge("upstream" => CVendoring.upstream_for(r["crate"], r["requirement"]).join("@"),
                           "advisory" => cve, "summary" => d["summary"],
                           "severity" => d["severity"], "nvd" => d["nvd"],
                           "sources" => d["sources"].uniq.join(" "))
    end
end
up_rows.uniq! { |h| [h["purl"], h["cargo_dir"], h["crate"], h["requirement"], h["advisory"]] }
up_rows.sort_by! { |h| [-(h["dependent_repos"] || 0), h["purl"], h["crate"]] }

up_csv = File.join(OUT, "upstream-c-advisories.csv")
CSV.open(up_csv, "w") do |csv|
    csv << %w[purl ecosystem dependent_repos repository_url cargo_dir crate version upstream advisory nvd severity sources summary]
    up_rows.each do |h|
        csv << [h["purl"], h["ecosystem"], h["dependent_repos"], h["repository_url"], h["cargo_dir"],
                h["crate"], h["requirement"], h["upstream"], h["advisory"], h["nvd"], h["severity"], h["sources"], h["summary"]]
    end
end

puts
puts "upstream C: #{up_vulns.map { |k, v| [k[2], k[3]] }.uniq.size} vulnerable upstream@version, " \
     "#{up_vulns.values.flat_map(&:keys).uniq.size} distinct CVEs"
puts "  #{up_rows.map { |h| h["repository_url"] }.uniq.size} repos, #{up_rows.map { |h| h["purl"] }.uniq.size} host packages"
up_vulns.sort_by { |_, v| -v.size }.each do |(crate, req, up_name, up_ver), cves|
    printf "  %-32s -> %-18s %2d CVEs: %s\n", "#{crate}@#{req}"[0, 32], "#{up_name}@#{up_ver}", cves.size, cves.keys.first(4).join(", ") + (cves.size > 4 ? " …" : "")
end
puts "wrote #{up_csv}"
