#!/usr/bin/env ruby
# Extract cargo dependencies from each has_rust repo by running `brief --json`
# on every directory that holds a Cargo.toml. brief parses Cargo.toml via
# git-pkgs/manifests and emits a `dependencies` array with pkg:cargo/* purls;
# once brief also feeds Cargo.lock to manifests (see brief-issues.md) the same
# invocation will return the resolved transitive tree with direct=false rows.
#
# For repos whose only Cargo.toml is at the root, the top-level brief output
# from scan.rb is reused from cache/brief and no clone happens. For nested
# crates the repo is shallow-cloned once and brief is run per crate directory.
#
# Usage: ruby crates.rb [LIMIT] [--refresh]

require "json"
require "sqlite3"
require "fileutils"
require "digest"
require "tmpdir"
require "open3"
require "time"

WORKDIR = __dir__
DB_PATH = File.join(WORKDIR, "rustdeps.db")
BRIEF   = File.join(WORKDIR, "cache", "brief")
CACHE   = File.join(WORKDIR, "cache", "crates")
LIMIT   = ARGV.grep(/\A\d+\z/).first&.to_i
REFRESH = ARGV.include?("--refresh")

FileUtils.mkdir_p(CACHE)

def hkey(*parts) = Digest::SHA256.hexdigest(parts.join("|"))[0, 32]

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

def cargo_deps_from_brief(json)
  return [] unless json
  d = JSON.parse(json) rescue {}
  (d["dependencies"] || []).select { |x| x["purl"].to_s.start_with?("pkg:cargo/") }
end

# Returns [{cargo_dir, crate, requirement, purl, scope, direct}] for one repo.
def crate_deps(url, toml_paths)
  cache = File.join(CACHE, "#{hkey(url)}.json")
  if File.exist?(cache) && !REFRESH
    return JSON.parse(File.read(cache))
  end

  dirs = toml_paths.map { |p| File.dirname(p) }.uniq
  # Drop crate dirs whose parent is also a crate dir with a [workspace]; brief
  # on the parent already parses declared members, so scanning both would
  # double-count. We can't read the file here (no clone yet), so approximate:
  # keep every dir but dedupe deps by (crate, requirement, scope) at the end.
  rows = []

  root_brief = File.join(BRIEF, "#{hkey(url)}.json")
  need_clone = dirs.any? { |d| d != "." } || !File.exist?(root_brief)

  collect = lambda do |root|
    dirs.each do |d|
      target = d == "." ? root : File.join(root, d)
      next unless Dir.exist?(target)
      out = if d == "." && File.exist?(root_brief) && !REFRESH
        File.read(root_brief)
      else
        run("brief", "--json", target)
      end
      cargo_deps_from_brief(out).each do |dep|
        rows << {
          "cargo_dir"   => d,
          "crate"       => dep["name"],
          "requirement" => dep["version"] || "",
          "purl"        => dep["purl"],
          "scope"       => dep["scope"],
          "direct"      => dep["direct"] ? 1 : 0,
        }
      end
    end
  end

  if need_clone
    Dir.mktmpdir("rustdeps-crates-") do |dir|
      unless clone(url, dir)
        File.write(cache, "[]")
        return []
      end
      collect.call(dir)
    end
  else
    # Only a root Cargo.toml and we already have brief output for it.
    cargo_deps_from_brief(File.read(root_brief)).each do |dep|
      rows << {
        "cargo_dir"   => ".",
        "crate"       => dep["name"],
        "requirement" => dep["version"] || "",
        "purl"        => dep["purl"],
        "scope"       => dep["scope"],
        "direct"      => dep["direct"] ? 1 : 0,
      }
    end
  end

  rows.uniq! { |r| [r["crate"], r["requirement"], r["scope"], r["cargo_dir"]] }
  File.write(cache, JSON.generate(rows))
  rows
rescue => e
  warn "  #{url}: #{e.class}: #{e.message}"
  []
end

db = SQLite3::Database.new(DB_PATH)
db.busy_timeout = 5000
db.results_as_hash = true
# requirement is part of the PK: a single Cargo.lock can resolve multiple
# major versions of the same crate (h2 0.3.x and 0.4.x side by side), and each
# is a distinct compiled artefact with its own advisory exposure.
db.execute_batch <<~SQL
  CREATE TABLE IF NOT EXISTS crate_deps (
    repository_url TEXT NOT NULL,
    cargo_dir      TEXT NOT NULL,
    crate          TEXT NOT NULL,
    requirement    TEXT NOT NULL DEFAULT '',
    purl           TEXT,
    scope          TEXT,
    direct         INTEGER,
    PRIMARY KEY (repository_url, cargo_dir, crate, requirement, scope)
  );
  CREATE INDEX IF NOT EXISTS idx_crate_deps_crate ON crate_deps(crate);
SQL

repos = db.execute(<<~SQL)
  SELECT r.repository_url, r.cargo_toml_paths
  FROM repos r
  WHERE r.has_rust = 1 AND r.cargo_toml_count > 0
    AND EXISTS (SELECT 1 FROM packages p WHERE p.repository_url = r.repository_url AND p.ecosystem <> 'cargo')
  ORDER BY r.repository_url
  #{"LIMIT #{LIMIT}" if LIMIT}
SQL

puts "#{repos.size} repos to extract crate deps from"

ins = db.prepare <<~SQL
  INSERT INTO crate_deps (repository_url, cargo_dir, crate, requirement, purl, scope, direct)
  VALUES (?,?,?,?,?,?,?)
  ON CONFLICT(repository_url, cargo_dir, crate, requirement, scope) DO UPDATE SET
    purl=excluded.purl, direct=MAX(direct, excluded.direct)
SQL

total = 0
repos.each_with_index do |r, i|
  url = r["repository_url"]
  tomls = (r["cargo_toml_paths"] || "").split("\n").reject(&:empty?)
  deps = crate_deps(url, tomls)
  db.transaction do
    db.execute("DELETE FROM crate_deps WHERE repository_url = ?", url) if REFRESH
    deps.each do |d|
      ins.execute(url, d["cargo_dir"], d["crate"], d["requirement"] || "", d["purl"], d["scope"], d["direct"])
    end
  end
  total += deps.size
  print "\r[#{i + 1}/#{repos.size}] #{total} crate deps"
end
ins.close
puts

n_repos  = db.get_first_value("SELECT COUNT(DISTINCT repository_url) FROM crate_deps")
n_crates = db.get_first_value("SELECT COUNT(DISTINCT crate) FROM crate_deps")
puts "#{total} rows, #{n_crates} distinct crates across #{n_repos} repos"
