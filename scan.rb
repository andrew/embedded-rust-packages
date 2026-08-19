#!/usr/bin/env ruby
# Detect embedded Rust in each repo. Shallow-clone the working tree, run
# `brief --json` for toolchain detection, `scc` for Rust LOC, and `find`
# for Cargo.toml / Cargo.lock locations. Records the bridge tool (maturin,
# napi-rs, rb-sys, rustler, neon, setuptools-rust, magnus) when brief sees
# one, but a Cargo.toml or *.rs anywhere in the tree is enough to flag the
# repo since not every project uses a known bridge.
#
# Results cached under cache/scan (per-repo JSON) and cache/brief (raw brief
# output) so re-runs are local-only. The clone is deleted after inspection.
#
# Usage: ruby scan.rb [LIMIT]
#        ruby scan.rb --rederive               # rewrite has_rust from cache, no cloning
#        ruby scan.rb --refresh [--only-rust]  # ignore cache, re-clone (optionally just has_rust=1 rows)

require "json"
require "sqlite3"
require "fileutils"
require "digest"
require "tmpdir"
require "open3"
require "time"

WORKDIR = __dir__
DB_PATH = File.join(WORKDIR, "rustdeps.db")
CACHE   = File.join(WORKDIR, "cache", "scan")
BRIEF   = File.join(WORKDIR, "cache", "brief")
LIMIT     = ARGV.grep(/\A\d+\z/).first&.to_i
REDERIVE  = ARGV.include?("--rederive")
REFRESH   = ARGV.include?("--refresh")
ONLY_RUST = ARGV.include?("--only-rust")

CLONE_HOSTS = %w[github.com gitlab.com codeberg.org gitea.com sr.ht git.sr.ht]

# brief tool names that indicate Rust is compiled into the host-language artefact.
RUST_BRIDGE_TOOLS = [
  "Maturin", "setuptools-rust", "napi-rs", "Neon", "rb-sys", "Magnus", "Rustler",
]

# Directories that hold vendored, generated or example Rust we don't want to
# count as "this package ships Rust". Still recorded, but excluded from the
# has_rust decision.
SKIP_DIRS = %w[vendor node_modules target .git test tests spec fixtures fixture testdata examples example docs benches]

FileUtils.mkdir_p(CACHE)
FileUtils.mkdir_p(BRIEF)

def hkey(url) = Digest::SHA256.hexdigest(url)[0, 32]

def run(*cmd, dir: nil)
  out, _, st = Open3.capture3(*cmd, chdir: dir || Dir.pwd)
  st.success? ? out : nil
end

def clone(url, dir)
  env = { "GIT_TERMINAL_PROMPT" => "0", "GIT_ASKPASS" => "/bin/true", "SSH_ASKPASS" => "/bin/true" }
  cfg = ["-c", "credential.helper=", "-c", "core.askPass=",
         "-c", "http.lowSpeedLimit=1000", "-c", "http.lowSpeedTime=30"]
  _, _, st = Open3.capture3(env, "git", *cfg, "clone", "--quiet", "--depth", "1",
                             "--filter=blob:none", "#{url}.git", dir)
  return true if st.success?
  _, _, st = Open3.capture3(env, "git", *cfg, "clone", "--quiet", "--depth", "1",
                             "--filter=blob:none", url, dir)
  st.success?
end

def find_cargo(dir)
  # git ls-files avoids untracked build artefacts and respects .gitignore.
  out = run("git", "-C", dir, "ls-files", "--", "**/Cargo.toml", "Cargo.toml",
            "**/Cargo.lock", "Cargo.lock")
  return [[], []] unless out
  toml = []
  lock = []
  out.each_line do |line|
    path = line.chomp
    parts = path.split("/")
    next if parts.any? { |p| SKIP_DIRS.include?(p.downcase) }
    toml << path if path.end_with?("Cargo.toml")
    lock << path if path.end_with?("Cargo.lock")
  end
  [toml.sort, lock.sort]
end

def scan(url)
  cache = File.join(CACHE, "#{hkey(url)}.json")
  if File.exist?(cache) && !REFRESH
    body = File.read(cache)
    return body == "null" ? nil : JSON.parse(body)
  end
  return nil if REDERIVE

  result = nil
  Dir.mktmpdir("rustdeps-") do |dir|
    unless clone(url, dir)
      File.write(cache, "null")
      return nil
    end

    brief_out = run("brief", "--json", dir)
    brief = brief_out ? (JSON.parse(brief_out) rescue {}) : {}
    File.write(File.join(BRIEF, "#{hkey(url)}.json"), brief_out) if brief_out

    langs   = (brief["languages"] || []).map { |l| l["name"] }
    pkgmgrs = (brief["package_managers"] || []).map { |p| p["name"] }
    tools   = (brief["tools"] || {}).values.flatten.map { |t| t["name"] }
    bridges = tools & RUST_BRIDGE_TOOLS

    lines_by_lang = (brief.dig("lines", "by_language") || {})
    rust_loc  = lines_by_lang["Rust"] || 0
    total_loc = brief.dig("lines", "total_lines") || 0

    toml, lock = find_cargo(dir)

    signals = []
    signals << "brief:lang"   if langs.include?("Rust")
    signals << "brief:cargo"  if pkgmgrs.include?("Cargo")
    signals << "brief:bridge" if bridges.any?
    signals << "cargo.toml"   if toml.any?
    signals << "cargo.lock"   if lock.any?
    signals << "rust_loc"     if rust_loc > 0

    result = {
      "rust_loc"         => rust_loc,
      "total_loc"        => total_loc,
      "brief_languages"  => langs,
      "bridge_tools"     => bridges,
      "cargo_toml_paths" => toml,
      "cargo_lock_paths" => lock,
      "signals"          => signals,
    }
  end

  File.write(cache, JSON.generate(result))
  result
rescue => e
  warn "  #{url}: #{e.class}: #{e.message}"
  nil
end

db = SQLite3::Database.new(DB_PATH)
db.busy_timeout = 5000
db.results_as_hash = true

where = (REDERIVE || REFRESH) ? "" : "AND r.scanned_at IS NULL"
where += " AND r.has_rust = 1" if ONLY_RUST
urls = db.execute(<<~SQL).map { |r| r["repository_url"] }
  SELECT r.repository_url,
         MAX(COALESCE(p.dependent_repos, 0)) AS dep_repos,
         MIN(p.rankings_avg)                 AS rank
  FROM repos r JOIN packages p ON p.repository_url = r.repository_url
  WHERE r.host IN (#{CLONE_HOSTS.map { |h| "'#{h}'" }.join(",")})
    #{where}
  GROUP BY r.repository_url
  ORDER BY dep_repos DESC, rank ASC NULLS LAST
  #{"LIMIT #{LIMIT}" if LIMIT}
SQL

puts "#{urls.size} repos to scan"

upd = db.prepare <<~SQL
  UPDATE repos SET
    has_rust=?, rust_loc=?, total_loc=?, brief_languages=?, bridge_tools=?,
    cargo_toml_paths=?, cargo_lock_paths=?, cargo_toml_count=?, has_cargo_lock=?,
    signals=?, scanned_at=?
  WHERE repository_url=?
SQL

# has_rust is derived here rather than cached so the rule can change without
# re-cloning. rust_loc alone does not qualify: stray *.rs fixtures with no
# Cargo.toml have no dependency tree to analyse.
def has_rust?(r)
  r["cargo_toml_paths"].any? || r["bridge_tools"].any?
end

now = Time.now.utc.iso8601
hit = miss = rust = 0
urls.each_with_index do |url, i|
  r = scan(url)
  if r
    hr = has_rust?(r) ? 1 : 0
    upd.execute(
      hr, r["rust_loc"], r["total_loc"],
      r["brief_languages"].join(","), r["bridge_tools"].join(","),
      r["cargo_toml_paths"].join("\n"), r["cargo_lock_paths"].join("\n"),
      r["cargo_toml_paths"].size, r["cargo_lock_paths"].any? ? 1 : 0,
      r["signals"].join(","), now, url
    )
    hit += 1
    rust += 1 if hr == 1
  else
    upd.execute(0, nil, nil, nil, nil, nil, nil, nil, nil, nil, now, url)
    miss += 1
  end
  print "\r[#{i + 1}/#{urls.size}] scanned=#{hit} rust=#{rust} failed=#{miss}"
end
upd.close
puts
puts "scanned #{hit}, #{rust} with embedded rust, #{miss} clone failures"
