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
    "libwebp-sys"     => ["libwebp",   [/AC_INIT\(\[libwebp\],\s*\[([\d.]+)\]/,
                                        /#define WEBP_DECODER_ABI_VERSION\s+0x0*(\w+)/]],
    "libdeflate-sys"  => ["libdeflate",[/#define LIBDEFLATE_VERSION_STRING\s+"([\d.]+)"/]],
    "curl-sys"        => ["curl",      [/#define LIBCURL_VERSION\s+"([\d.]+)"/]],
    "tree-sitter"     => ["tree-sitter",[/#define TREE_SITTER_LANGUAGE_VERSION\s+(\d+)/]],
    "blake3"          => ["blake3",    [/#define BLAKE3_VERSION_STRING\s+"([\d.]+)"/]],
    "libfuzzer-sys"   => ["llvm",      [/LLVM_VERSION_STRING\s+"([\d.]+)"/,
                                        /Part of LLVM (\d+)/]],
    "mozjpeg-sys"     => ["mozjpeg",   [/set\(VERSION\s+([\d.]+)\)/,
                                        /"mozjpeg version ([\d.]+)/,
                                        /#define LIBJPEG_TURBO_VERSION\s+([\d.]+)/]],
    "secp256k1-sys"   => ["libsecp256k1", [/SECP256K1_VERSION_(?:STRING\s+"([\d.]+)"|MAJOR\s+(\d+).*?_MINOR\s+(\d+).*?_PATCH\s+(\d+))/m]],
    "lua-src"         => ["lua",       [/#define LUA_VERSION_RELEASE\s+"(\d+)".*?LUA_VERSION_MINOR\s+"(\d+)".*?LUA_VERSION_MAJOR\s+"(\d+)"/m,
                                        /#define LUA_RELEASE\s+"Lua ([\d.]+)"/]],
    "hidapi"          => ["hidapi",    [/HID_API_VERSION_MAJOR\s+(\d+).*?_MINOR\s+(\d+).*?_PATCH\s+(\d+)/m]],
}

def fetch(crate, ver)
    cache = File.join(CACHE, "#{crate}-#{ver}.crate")
    return cache if File.exist?(cache) && File.size(cache) > 0
    url = "https://static.crates.io/crates/#{crate}/#{crate}-#{ver}.crate"
    out, _, st = Open3.capture3("curl", "-sfL", "-A", UA, "-o", cache, url)
    st.success? ? cache : nil
end

def extract(crate, ver)
    # +metadata is authoritative and free; only fall back to tarball probing
    # for crates or versions that don't encode it there.
    if (m = CVendoring.upstream_for(crate, ver)) && ver.include?("+")
        return m
    end
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

def all_versions(crate)
    require "json"
    out, = Open3.capture3("curl", "-s", "-A", UA, "https://crates.io/api/v1/crates/#{crate}/versions")
    (JSON.parse(out)["versions"] || []).reject { |v| v["yanked"] }.map { |v| v["num"] }
rescue
    []
end

targets = case
when ARGV == ["--all"]
    db = SQLite3::Database.new(File.join(WORKDIR, "rustdeps.db"))
    db.execute("SELECT DISTINCT crate, requirement FROM crate_deps WHERE requirement GLOB '[0-9]*.[0-9]*.[0-9]*'")
      .select { |c, _| PROBES.key?(c) && !CVendoring::UPSTREAM.key?(c) }
when ARGV[0] == "--full"
    # Every published version of each named crate (or every mappable crate).
    crates = ARGV[1..].empty? ? (PROBES.keys | CVendoring::UPSTREAM.keys) : ARGV[1..]
    crates.flat_map { |c| all_versions(c).map { |v| [c, v] } }
else
    crate = ARGV.shift or abort "usage: #{$0} <crate> <version>... | --all | --full [crate...]"
    ARGV.map { |v| [crate, v] }
end

seen = Hash.new { |h, k| h[k] = [] }
targets.sort.each do |crate, ver|
    up = extract(crate, ver)
    if up
        seen[[crate, up[0]]] << [ver, up[1]]
        printf "        [%-18s %-10s] => [%-12s %s],\n",
               "\"#{crate}\",", "\"#{ver}\"", "\"#{up[0]}\",", "\"#{up[1]}\""
    else
        warn "  # #{crate}@#{ver}: no match"
    end
end

# Collapse to ranges: for each upstream version, the crate-version span that
# bundles it. This is what a RUSTSEC advisory range would target.
if targets.size > 3
    warn ""
    warn "# crate-version ranges per upstream version:"
    seen.each do |(crate, up_name), pairs|
        by_up = pairs.group_by { |_, uv| uv }
        by_up.sort_by { |uv, _| Gem::Version.new(uv) rescue uv }.each do |uv, vs|
            cvs = vs.map(&:first).sort_by { |v| Gem::Version.new(v) rescue v }
            warn "#   #{crate} [#{cvs.first} .. #{cvs.last}] -> #{up_name} #{uv}"
        end
    end
end
