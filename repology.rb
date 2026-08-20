# frozen_string_literal: true
# Map an upstream project name (as used in c_vendoring.rb UPSTREAM/PROBES) to
# the distro source-package names OSV keys on, via the Repology API. Port of
# Homebrew/advisory-database lib/repology_index.rb, but keyed on upstream
# project rather than Homebrew formula, and queried on demand rather than by
# paginating a whole repository.
#
# Repology groups every distro's packaging of e.g. zlib under one project and
# records each distro's srcname (Debian `zlib1g`, Alpine `zlib`, ...). Those
# srcnames are what OSV distro-ecosystem queries take. Repology also splits
# sub-components into separate srcnames within the same project (Alpine has
# `zlib` and `minizip` under project `zlib`), which lets a caller drop a
# component-mismatch CVE by srcname rather than by hand.

require "json"
require "fileutils"
require_relative "http"

module Repology
    CACHE = File.join(__dir__, "cache", "repology")
    FileUtils.mkdir_p(CACHE)
    CONN = conn("https://repology.org")

    # Repology repo-name prefix => OSV ecosystem string. Mirrors
    # Homebrew/advisory-database RepologyIndex::OSV_DISTROS. Debian and Ubuntu
    # cover most C libraries; Alpine catches a few Debian doesn't package;
    # openSUSE/Rocky/Mageia add mostly duplicate CVE ids so are left off.
    OSV_DISTROS = {
        "debian_"             => "Debian",
        "ubuntu_"             => "Ubuntu",
        "alpine_"             => "Alpine",
    }.freeze

    # Upstream names used in this repo -> Repology project name where they
    # differ. Most match; xz is `xz` not `xz-utils`, sqlite3 is `sqlite`.
    PROJECT_ALIAS = {
        "sqlite3"    => "sqlite",
        "xz"         => "xz",
        "libwebp"    => "libwebp",
        "aws-lc"     => "aws-lc",
        "c-blosc2"   => "c-blosc2",
        "libgit2"    => "libgit2",
        "libssh2"    => "libssh2",
        "libdeflate" => "libdeflate",
        "mimalloc"   => "mimalloc",
        "jemalloc"   => "jemalloc",
        "rocksdb"    => "rocksdb",
    }.freeze

    def self.project(upstream)
        name = PROJECT_ALIAS[upstream] || upstream
        path = File.join(CACHE, "#{name}.json")
        return JSON.parse(File.read(path)) if File.exist?(path) && File.mtime(path) > Time.now - 7 * 86_400
        sleep 1.1
        res = CONN.get("/api/v1/project/#{name}")
        return {} unless res.success?
        rows = JSON.parse(res.body)
        out = Hash.new { |h, k| h[k] = [] }
        rows.each do |r|
            prefix, eco = OSV_DISTROS.find { |p, _| r["repo"].to_s.start_with?(p) }
            next unless eco
            src = r["srcname"] || r["binname"]
            out[eco] << src if src
        end
        out.transform_values! { |v| v.uniq.sort }
        File.write(path, JSON.generate(out))
        out
    end

    # Distinct (osv_ecosystem, srcname) pairs to query for CVE discovery.
    # `only:` restricts to srcnames matching the upstream (drops sub-components
    # like `minizip`, `sqlite-tcl`) unless the caller wants everything.
    def self.osv_packages(upstream, only: nil)
        project(upstream).flat_map do |eco, names|
            names = names.grep(Regexp.new(only)) if only
            names.map { |n| [eco, n] }
        end
    end
end
