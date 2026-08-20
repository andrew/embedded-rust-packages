#!/usr/bin/env ruby
# Extract the vendored upstream C library version from a crates.io tarball.
# `cargo publish` bundles submodule content, so the .crate file has the actual
# vendored headers even when the git repo only has a submodule pointer.
#
# Prints ruby-hash lines suitable for pasting into CVendoring::UPSTREAM_TABLE.
#
# Usage: ruby upstream_version.rb libsqlite3-sys 0.30.1 0.37.0
#        ruby upstream_version.rb --all   # every C-vendoring crate@version in crate_deps

require "sqlite3"
require "open3"
require "fileutils"
require_relative "c_vendoring"

WORKDIR = __dir__
CACHE   = File.join(WORKDIR, "cache", "upstream")
UA      = "embedded-rust-packages (github.com/andrew/embedded-rust-packages)"
FileUtils.mkdir_p(CACHE)

# crate -> [upstream OSV package name, [regexes to try against tarball bytes]]
# First regex capture group is the version. Multiple patterns because some
# crates bundle two variants (sqlcipher + sqlite3, mimalloc v2 + v3).
PROBES = {
    "libsqlite3-sys"  => ["sqlite3",   [/#define SQLITE_VERSION\s+"([\d.]+)"/]],
    "libz-sys"        => ["zlib",      [/#define ZLIB_VERSION\s+"([\d.]+)"/]],
    "libmimalloc-sys" => ["mimalloc",  [/#define MI_MALLOC_VERSION\s+(\d)0?(\d)0?(\d)\b/,
                                        /#define MI_MALLOC_VERSION\s+(\d+)/]],
    "aws-lc-sys"      => ["aws-lc",    [/#define AWSLC_VERSION_NUMBER_STRING\s+"([\d.]+)"/]],
    "aws-lc-fips-sys" => ["aws-lc",    [/#define AWSLC_VERSION_NUMBER_STRING\s+"([\d.]+)"/]],
    "onig_sys"        => ["oniguruma", [/ONIGURUMA_VERSION_MAJOR\s+(\d+).*?_MINOR\s+(\d+).*?_TEENY\s+(\d+)/m]],
    "librocksdb-sys"  => ["rocksdb",   [/ROCKSDB_MAJOR\s+(\d+).*?ROCKSDB_MINOR\s+(\d+).*?ROCKSDB_PATCH\s+(\d+)/m]],
    "libgit2-sys"     => ["libgit2",   [/#define LIBGIT2_VERSION\s+"([\d.]+)"/]],
    "libssh2-sys"     => ["libssh2",   [/#define LIBSSH2_VERSION\s+"([\d.]+)"/]],
    "libnghttp2-sys"  => ["nghttp2",   [/#define NGHTTP2_VERSION\s+"([\d.]+)"/]],
    "lzma-sys"        => ["xz",        [/#define LZMA_VERSION_MAJOR\s+(\d+).*?_MINOR\s+(\d+).*?_PATCH\s+(\d+)/m,
                                        /PACKAGE_VERSION\s+"([\d.]+)"/]],
    "liblzma-sys"     => ["xz",        [/#define LZMA_VERSION_MAJOR\s+(\d+).*?_MINOR\s+(\d+).*?_PATCH\s+(\d+)/m]],
    "mozjpeg-sys"     => ["mozjpeg",   [/set\(VERSION\s+([\d.]+)\)/, /#define JPEG_LIB_VERSION\s+(\d+)/]],
    "libwebp-sys"     => ["libwebp",   [/AC_INIT\(\[libwebp\],\s*\[([\d.]+)\]/]],
    "libdeflate-sys"  => ["libdeflate",[/#define LIBDEFLATE_VERSION_STRING\s+"([\d.]+)"/]],
}

def fetch(crate, ver)
    cache = File.join(CACHE, "#{crate}-#{ver}.crate")
    return cache if File.exist?(cache) && File.size(cache) > 0
    url = "https://static.crates.io/crates/#{crate}/#{crate}-#{ver}.crate"
    out, _, st = Open3.capture3("curl", "-sfL", "-A", UA, "-o", cache, url)
    st.success? ? cache : nil
end

def extract(crate, ver)
    up_name, probes = PROBES[crate]
    return nil unless up_name
    path = fetch(crate, ver) or return nil
    body, = Open3.capture3("tar", "-xzOf", path)
    body = body.force_encoding("BINARY").scrub
    probes.each do |re|
        # For crates bundling multiple variants, take the highest version.
        matches = body.scan(re)
        next if matches.empty?
        ver_str = matches.map { |m| Array(m).join(".") }.max_by { |v| v.split(".").map(&:to_i) }
        return [up_name, ver_str]
    end
    nil
end

targets = if ARGV == ["--all"]
    db = SQLite3::Database.new(File.join(WORKDIR, "rustdeps.db"))
    db.execute("SELECT DISTINCT crate, requirement FROM crate_deps WHERE requirement GLOB '[0-9]*.[0-9]*.[0-9]*'")
      .select { |c, _| PROBES.key?(c) && !CVendoring::UPSTREAM.key?(c) }
else
    crate = ARGV.shift or abort "usage: #{$0} <crate> <version>... | --all"
    ARGV.map { |v| [crate, v] }
end

targets.sort.each do |crate, ver|
    up = extract(crate, ver)
    if up
        printf "        [%-18s %-10s] => [%-12s %s],\n",
               "\"#{crate}\",", "\"#{ver}\"", "\"#{up[0]}\",", "\"#{up[1]}\""
    else
        warn "  # #{crate}@#{ver}: no match"
    end
end
