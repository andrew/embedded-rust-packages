#!/usr/bin/env ruby
# Resolve GitHub redirect aliases among has_rust repos and merge them.
# packages.ecosyste.ms carries whatever repository_url each package
# declared, so an org rename (react/react -> facebook/react,
# ockam-network -> build-trust) lands as two repo rows that both scan
# to the same tree. This follows the HTTP redirect for each has_rust
# github.com URL, then repoints packages and crate_deps at the canonical
# URL and drops the alias repos row.
#
# Usage: ruby dedupe.rb [--dry-run]

require "sqlite3"
require "open3"

WORKDIR = __dir__
DB_PATH = File.join(WORKDIR, "rustdeps.db")
DRY     = ARGV.include?("--dry-run")

def norm(url)
  url.strip.sub(%r{^http://}, "https://").sub(%r{://www\.}, "://").chomp("/").chomp(".git").downcase
end

def canonical(url)
  out, st = Open3.capture2("curl", "-sIL", "-o", "/dev/null", "-w", "%{url_effective}", url)
  return nil unless st.success?
  final = norm(out)
  return nil unless final.start_with?("https://github.com/")
  # A deleted repo redirects to a 404 page or the org root; require owner/repo shape.
  return nil unless final.count("/") == 4
  final
end

db = SQLite3::Database.new(DB_PATH)
db.busy_timeout = 5000
db.results_as_hash = true

urls = db.execute(<<~SQL).map { |r| r["repository_url"] }
  SELECT repository_url FROM repos
  WHERE has_rust = 1 AND host = 'github.com'
  ORDER BY repository_url
SQL

puts "resolving #{urls.size} github.com has_rust URLs"

aliases = {}
urls.each_with_index do |u, i|
  c = canonical(u)
  aliases[u] = c if c && c != u
  print "\r[#{i + 1}/#{urls.size}] aliases=#{aliases.size}"
end
puts

if aliases.empty?
  puts "no redirect aliases found"
  exit 0
end

aliases.each { |a, c| puts "  #{a} -> #{c}" }
exit 0 if DRY

db.transaction do
  aliases.each do |ali, canon|
    # Make sure the canonical row exists; if not, rename the alias in place.
    unless db.get_first_value("SELECT 1 FROM repos WHERE repository_url = ?", [canon])
      db.execute("UPDATE repos SET repository_url = ?, owner = ? WHERE repository_url = ?",
                 [canon, canon.split("/")[3], ali])
    else
      db.execute("DELETE FROM repos WHERE repository_url = ?", [ali])
    end
    db.execute("UPDATE packages SET repository_url = ? WHERE repository_url = ?", [canon, ali])
    db.execute("UPDATE OR IGNORE crate_deps SET repository_url = ? WHERE repository_url = ?", [canon, ali])
    db.execute("DELETE FROM crate_deps WHERE repository_url = ?", [ali])
  end
end

puts "merged #{aliases.size} alias(es)"
