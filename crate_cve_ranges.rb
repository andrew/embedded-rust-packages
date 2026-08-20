#!/usr/bin/env ruby
# For a -sys crate that vendors a C library, compute which crate versions
# bundle a C version in each upstream CVE's affected range, and emit an
# OSV-format record per (crate, CVE) with the crate-version range that a
# RUSTSEC advisory would carry.
#
# Pipeline: crate name -> upstream_version.rb tarball probes (crate-ver ->
# C-ver map) -> Repology (upstream project -> distro srcnames) -> OSV distro
# querybatch (CVE candidate discovery) -> NVD CPE (range applicability) ->
# data/rejected.txt (component-mismatch filter) -> out/sys-advisories/*.json.
#
# Usage: ruby crate_cve_ranges.rb libz-sys
#        ruby crate_cve_ranges.rb libz-sys curl-sys zstd-sys lzma-sys
#        NVD_API_KEY=xxx ruby crate_cve_ranges.rb ...   # 10x faster NVD

require "json"
require "fileutils"
require "open3"
require_relative "http"
require_relative "c_vendoring"
require_relative "repology"

WORKDIR   = __dir__
OUT       = File.join(WORKDIR, "out", "sys-advisories")
NVD_CACHE = File.join(WORKDIR, "cache", "nvd")
MAP_CACHE = File.join(WORKDIR, "cache", "upstream", "maps")
OSV       = conn("https://api.osv.dev")
NVD       = conn("https://services.nvd.nist.gov")
NVD_KEY   = ENV["NVD_API_KEY"]
FileUtils.mkdir_p(OUT)
FileUtils.mkdir_p(NVD_CACHE)
FileUtils.mkdir_p(MAP_CACHE)

# NVD CPE product names where they differ from the Repology project name.
CPE_PRODUCT_ALIAS = {
    "sqlite3"   => %w[sqlite sqlite3],
    "sqlite"    => %w[sqlite sqlite3],
    "xz"        => %w[xz xz-utils xz_utils],
    "curl"      => %w[curl libcurl],
    "libwebp"   => %w[libwebp webp],
    "c-blosc2"  => %w[c-blosc2 c_blosc2 blosc2],
    "libgit2"   => %w[libgit2],
    "oniguruma" => %w[oniguruma onig],
    "zstd"      => %w[zstandard zstd],
    "rocksdb"   => %w[rocksdb],
}.freeze

REJECTED = File.readlines(File.join(WORKDIR, "data", "rejected.txt"))
               .grep_v(/^\s*(#|$)/).map { |l| l.strip.split(/\s+/, 2) }
               .group_by(&:first).transform_values { |v| v.map(&:last) }

def gv(s) = (Gem::Version.new(s.to_s.sub(/\+.*/, "")) rescue nil)
def vsort(a) = a.sort_by { |v| gv(v) || Gem::Version.new("0") }

def crate_map(crate)
    path = File.join(MAP_CACHE, "#{crate}.json")
    return JSON.parse(File.read(path)) if File.exist?(path)
    warn "  building crate->upstream map for #{crate} (downloads every release tarball once)"
    out, = Open3.capture3("ruby", File.join(WORKDIR, "upstream_version.rb"), "--full", crate)
    map = {}
    out.each_line do |l|
        m = l.match(/\["#{Regexp.escape(crate)}",\s*"([^"]+)"\s*\]\s*=>\s*\["([^"]+)",\s*"([^"]+)"\]/)
        map[m[1]] = { "upstream" => m[2], "version" => m[3] } if m
    end
    File.write(path, JSON.generate(map)) unless map.empty?
    map
end

def discover_cves(upstream)
    ids = {}
    pkgs = Repology.osv_packages(upstream)
    return ids if pkgs.empty?
    # Repology gives per-distro srcnames; OSV wants ecosystem strings with a
    # release suffix. Query the newest two releases per distro so recently-
    # published CVEs are covered without exploding the query count.
    releases = { "Debian" => %w[13 12], "Ubuntu" => %w[24.04:LTS 22.04:LTS], "Alpine" => %w[v3.22 v3.20] }
    queries = pkgs.uniq.flat_map { |eco, name| releases.fetch(eco, []).map { |r| { package: { ecosystem: "#{eco}:#{r}", name: name } } } }
    queries.each_slice(50) do |batch|
        res = OSV.post("/v1/querybatch", JSON.generate(queries: batch), "Content-Type" => "application/json")
        next unless res.success?
        JSON.parse(res.body)["results"].each_with_index do |r, j|
            (r["vulns"] || []).each do |v|
                cve = v["id"].to_s[/CVE-\d{4}-\d{3,}/]
                (ids[cve] ||= []) << batch[j][:package] if cve
            end
        end
    end
    ids
end

def nvd_record(cve)
    path = File.join(NVD_CACHE, "#{cve}.json")
    return JSON.parse(File.read(path)) if File.exist?(path)
    sleep(NVD_KEY ? 0.7 : 6.1)
    res = NVD.get("/rest/json/cves/2.0", { cveId: cve }, NVD_KEY ? { "apiKey" => NVD_KEY } : {})
    return nil unless res.success?
    data = (JSON.parse(res.body)["vulnerabilities"] || []).first
    File.write(path, JSON.generate(data)) if data
    data
end

def nvd_range(cve, upstream)
    data = nvd_record(cve) or return :unknown
    c = data["cve"]
    return :rejected if c["vulnStatus"] == "Rejected" || (c["descriptions"] || []).any? { |d| d["value"].to_s.start_with?("Rejected reason:") }
    matches = (c["configurations"] || []).flat_map { |cfg| cfg["nodes"] || [] }.flat_map { |n| n["cpeMatch"] || [] }
    names = ([upstream, upstream.tr("-", "_")] + Array(CPE_PRODUCT_ALIAS[upstream])).uniq
    relevant = matches.select { |m| names.any? { |n| m["criteria"].to_s.include?(":#{n}:") } }
    return :no_cpe if relevant.empty?
    lambda do |ver|
        v = gv(ver) or return false
        relevant.any? do |m|
            cpe_ver = m["criteria"].to_s.split(":")[5]
            lo_i, lo_e = m["versionStartIncluding"], m["versionStartExcluding"]
            hi_i, hi_e = m["versionEndIncluding"],   m["versionEndExcluding"]
            if [lo_i, lo_e, hi_i, hi_e].all?(&:nil?)
                next true if cpe_ver == "*" || cpe_ver == "-"
                cv = gv(cpe_ver); next cv && v == cv
            end
            (lo_i.nil? || (gv(lo_i) && v >= gv(lo_i))) &&
            (lo_e.nil? || (gv(lo_e) && v >  gv(lo_e))) &&
            (hi_i.nil? || (gv(hi_i) && v <= gv(hi_i))) &&
            (hi_e.nil? || (gv(hi_e) && v <  gv(hi_e)))
        end
    end
end

def existing_rustsec(crate)
    res = OSV.post("/v1/query", JSON.generate(package: { ecosystem: "crates.io", name: crate }),
                   "Content-Type" => "application/json")
    return {} unless res.success?
    (JSON.parse(res.body)["vulns"] || []).each_with_object({}) do |v, h|
        cve = ([v["id"], *(v["aliases"] || [])].compact.join(" "))[/CVE-\d{4}-\d{3,}/]
        h[cve] = v["id"] if cve
    end
end

def spans(all_versions, affected)
    runs = []
    run = []
    all_versions.each do |v|
        if affected.include?(v)
            run << v
        elsif run.any?
            runs << run; run = []
        end
    end
    runs << run if run.any?
    runs
end

def osv_record(crate, cve, upstream, affected_up, spans, all_versions, nvd, discovered_via)
    fixed_after = ->(last) { i = all_versions.index(last); all_versions[i + 1] }
    events = spans.flat_map do |s|
        ev = [{ "introduced" => s.first }]
        (fx = fixed_after.call(s.last)) ? ev << { "fixed" => fx } : ev << { "last_affected" => s.last }
        ev
    end
    cvss = (nvd.dig("cve", "metrics") || {}).values.flatten.map { |m| m.dig("cvssData", "vectorString") }.compact.first
    {
        "schema_version" => "1.7.3",
        "id"             => "SYSCRATE-#{crate}-#{cve}",
        "upstream"       => [cve],
        "summary"        => "#{crate} bundles #{upstream} affected by #{cve}",
        "details"        => (nvd.dig("cve", "descriptions", 0, "value") || "").strip,
        "severity"       => cvss ? [{ "type" => cvss[/CVSS:(\d\.\d)/, 1] ? "CVSS_V#{cvss[/CVSS:(\d)/, 1]}" : "CVSS_V3", "score" => cvss }] : [],
        "affected"       => [{
            "package" => { "ecosystem" => "crates.io", "name" => crate, "purl" => "pkg:cargo/#{crate}" },
            "ranges"  => [{ "type" => "SEMVER", "events" => events }],
            "ecosystem_specific" => {
                "bundles"           => upstream,
                "bundled_versions"  => affected_up,
                "discovered_via"    => discovered_via.map { |p| "#{p[:ecosystem]}/#{p[:name]}" }.uniq,
            },
        }],
        "references" => [
            { "type" => "ADVISORY", "url" => "https://nvd.nist.gov/vuln/detail/#{cve}" },
        ],
        "database_specific" => { "source" => "crate_cve_ranges.rb" },
    }
end

crates = ARGV.empty? ? abort("usage: #{$0} <crate>...") : ARGV
crates.each do |crate|
    map = crate_map(crate)
    if map.empty?
        warn "#{crate}: no upstream version map (add a PROBES entry in upstream_version.rb)"
        next
    end
    upstream = map.values.first["upstream"]
    all_vers = map.keys.then { |a| vsort(a) }
    have = existing_rustsec(crate)
    rejected = REJECTED[crate] || []
    candidates = discover_cves(upstream)

    puts "== #{crate} (#{map.size} releases) -> #{upstream}  [#{candidates.size} candidate CVEs, #{have.size} in RUSTSEC, #{rejected.size} rejected]"

    emitted = 0
    candidates.sort.each do |cve, via|
        next if rejected.include?(cve)
        rng = nvd_range(cve, upstream)
        next if rng == :rejected
        if rng.is_a?(Symbol)
            warn "   #{cve}  [nvd:#{rng}]"
            next
        end
        affected_up = map.values.map { |v| v["version"] }.uniq.select { |uv| rng.call(uv) }
        next if affected_up.empty?
        affected_crate = map.select { |_, v| affected_up.include?(v["version"]) }.keys
        s = spans(all_vers, affected_crate)
        span_str = s.map { |r| r.size == 1 ? "= #{r.first}" : ">= #{r.first}, <= #{r.last}" }.join(" | ")
        already = have[cve] ? " (already: #{have[cve]})" : ""
        puts "   #{cve}#{already}  #{upstream} #{affected_up.then { |a| vsort(a) }.join(",")}  ->  #{crate} #{span_str}"

        next if have[cve]
        rec = osv_record(crate, cve, upstream, affected_up.sort, s, all_vers, nvd_record(cve) || {}, via)
        File.write(File.join(OUT, "#{rec["id"]}.json"), JSON.pretty_generate(rec))
        emitted += 1
    end
    puts "   wrote #{emitted} OSV records to out/sys-advisories/"
    puts
end
