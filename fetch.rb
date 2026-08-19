#!/usr/bin/env ruby
# Pull critical packages from packages.ecosyste.ms into rustdeps.db.
# Creates the packages table (one row per purl) and seeds the repos table
# (one row per unique repository_url) from embedded repo_metadata.
#
# crates.io is excluded: those are already Rust and already covered by
# rustsec. We're looking for Rust that ships inside other ecosystems.
#
# Responses cached under cache/packages so re-runs are cheap.
#
# Usage: ruby fetch.rb [registry ...]
#        ruby fetch.rb --top 5000 [registry ...]   # top N by dependent_repos instead of critical

require "json"
require "sqlite3"
require "digest"
require "fileutils"
require "time"
require_relative "http"

WORKDIR = __dir__
DB_PATH = File.join(WORKDIR, "rustdeps.db")
CACHE   = File.join(WORKDIR, "cache", "packages")
CONN    = conn("https://packages.ecosyste.ms")

REGISTRIES = %w[
  npmjs.org
  pypi.org
  rubygems.org
  hex.pm
  packagist.org
  nuget.org
  repo1.maven.org
  proxy.golang.org
  pub.dev
  cocoapods.org
  conda-forge.org
  swiftpackageindex.com
  hackage.haskell.org
  juliahub.com
  metacpan.org
]

FileUtils.mkdir_p(CACHE)

def get(url)
  key = Digest::SHA256.hexdigest(url)[0, 32]
  path = File.join(CACHE, "#{key}.json")
  if File.exist?(path)
    data = JSON.parse(File.read(path))
    return [data["packages"], data["next"]]
  end

  res = CONN.get(url)
  raise "#{res.status} for #{url}" unless res.success?

  packages = JSON.parse(res.body)
  link = res.headers["link"] || ""
  next_url = link[/<([^>]+)>;\s*rel="next"/, 1]

  File.write(path, JSON.generate(packages: packages, next: next_url))
  sleep 0.2
  [packages, next_url]
end

def norm_repo(url)
  return nil if url.nil? || url.strip.empty?
  u = url.strip.sub(%r{^http://}, "https://")
  return nil unless u.start_with?("https://")
  u.sub(%r{://www\.}, "://").chomp("/").chomp(".git").downcase
end

def owner_from(url)
  return [nil, nil] if url.nil?
  parts = url.sub(%r{^https?://}, "").split("/")
  [parts[0], parts[1]]
end

db = SQLite3::Database.new(DB_PATH)
db.execute_batch <<~SQL
  PRAGMA journal_mode=WAL;

  CREATE TABLE IF NOT EXISTS packages (
    purl                TEXT PRIMARY KEY,
    registry            TEXT NOT NULL,
    ecosystem           TEXT NOT NULL,
    name                TEXT NOT NULL,
    repository_url      TEXT,
    dependent_repos     INTEGER,
    dependent_packages  INTEGER,
    downloads           INTEGER,
    downloads_period    TEXT,
    latest_release      TEXT,
    latest_release_at   TEXT,
    status              TEXT,
    rankings_avg        REAL,
    fetched_at          TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_packages_repo     ON packages(repository_url);
  CREATE INDEX IF NOT EXISTS idx_packages_registry ON packages(registry);

  CREATE TABLE IF NOT EXISTS repos (
    repository_url      TEXT PRIMARY KEY,
    host                TEXT,
    owner               TEXT,
    stars               INTEGER,
    archived            INTEGER,
    language            TEXT,
    default_branch      TEXT,
    pushed_at           TEXT,

    -- scan.rb (brief + filesystem inspection of a shallow clone)
    has_rust            INTEGER,
    rust_loc            INTEGER,
    total_loc           INTEGER,
    brief_languages     TEXT,
    bridge_tools        TEXT,
    cargo_toml_paths    TEXT,
    cargo_lock_paths    TEXT,
    cargo_toml_count    INTEGER,
    has_cargo_lock      INTEGER,
    signals             TEXT,
    scanned_at          TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_repos_has_rust ON repos(has_rust);
  CREATE INDEX IF NOT EXISTS idx_repos_host     ON repos(host, owner);
SQL

PKG_COLS = %w[
  purl registry ecosystem name repository_url
  dependent_repos dependent_packages downloads downloads_period
  latest_release latest_release_at status rankings_avg fetched_at
]
ins_pkg = db.prepare <<~SQL
  INSERT INTO packages (#{PKG_COLS.join(",")}) VALUES (#{(["?"] * PKG_COLS.size).join(",")})
  ON CONFLICT(purl) DO UPDATE SET
    #{(PKG_COLS - %w[purl registry ecosystem name]).map { |c| "#{c}=excluded.#{c}" }.join(",")}
SQL

REPO_COLS = %w[
  repository_url host owner stars archived language default_branch pushed_at
]
ins_repo = db.prepare <<~SQL
  INSERT INTO repos (#{REPO_COLS.join(",")}) VALUES (#{(["?"] * REPO_COLS.size).join(",")})
  ON CONFLICT(repository_url) DO UPDATE SET
    #{(REPO_COLS - %w[repository_url host owner]).map { |c| "#{c}=COALESCE(excluded.#{c}, #{c})" }.join(",")}
SQL

TOP = (i = ARGV.index("--top")) && ARGV.delete_at(i) && ARGV.delete_at(i).to_i
now = Time.now.utc.iso8601
targets = ARGV.empty? ? REGISTRIES : ARGV
b = ->(v) { v.nil? ? nil : (v ? 1 : 0) }

targets.each do |registry|
  base = "https://packages.ecosyste.ms/api/v1/registries/#{registry}/packages"
  url = if TOP
    "#{base}?sort=dependent_repos_count&order=desc&per_page=100&page=1"
  else
    "#{base}?critical=true&per_page=100&page=1"
  end
  page = 0
  total = 0
  db.transaction
  while url && (TOP.nil? || total < TOP)
    page += 1
    packages, url = get(url)
    packages.each do |p|
      purl = p["purl"] or next
      repo = norm_repo(p["repository_url"])
      ins_pkg.execute(
        purl, registry, p["ecosystem"], p["name"], repo,
        p["dependent_repos_count"], p["dependent_packages_count"],
        p["downloads"], p["downloads_period"],
        p["latest_release_number"], p["latest_release_published_at"],
        p["status"], (p["rankings"] || {})["average"],
        now
      )
      if repo
        host, owner = owner_from(repo)
        m = p["repo_metadata"] || {}
        ins_repo.execute(
          repo, host, owner,
          m["stargazers_count"], b[m["archived"]],
          m["language"], m["default_branch"], m["pushed_at"]
        )
      end
      total += 1
    end
    print "\r#{registry.ljust(24)} page #{page}  (#{total} pkgs)"
  end
  db.commit
  puts
rescue => e
  db.rollback rescue nil
  warn "\n#{registry}: #{e.class}: #{e.message}"
end

ins_pkg.close
ins_repo.close

n = db.get_first_value("SELECT COUNT(*) FROM packages")
r = db.get_first_value("SELECT COUNT(*) FROM repos")
puts
puts "#{n} packages, #{r} repos in #{DB_PATH}"
