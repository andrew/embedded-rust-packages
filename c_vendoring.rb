# Classify a crate name as one that vendors and compiles C/C++ (or asm) into
# the built artefact, as opposed to one that only declares FFI to a system
# library. Used to tag "Russian doll" rows: host package -> Rust -> vendored C.
#
# The `-sys` suffix is the convention but covers well under half of C-compiling
# crates in the top-5000 crates.io corpus; `-src`, `tree-sitter-*`, and a set
# of well-known one-offs make up most of the rest.

module CVendoring
    # -sys crates that are pure FFI declarations to a system/platform library
    # with no vendored source. Matching these on name alone would over-tag.
    FFI_ONLY_SYS = %w[
        windows-sys linux-raw-sys js-sys web-sys wasm-bindgen-shared
        core-foundation-sys security-framework-sys system-configuration-sys
        core-graphics-sys core-text-sys core-video-sys
        jni-sys ndk-sys napi-sys node-sys
        dirs-sys dirs-sys-next
        fsevent-sys inotify-sys kqueue-sys
        erlang_nif-sys
        clang-sys llvm-sys
        wayland-sys x11-dl xcb-sys gio-sys glib-sys gobject-sys gdk-sys gtk-sys
        pango-sys cairo-sys-rs gdk-pixbuf-sys atk-sys
        objc-sys android_log-sys android_system_properties
        fuchsia-zircon-sys cloudabi-sys hermit-abi-sys
        libloading-sys
        winapi winapi-util ntapi mach mach2 mach_o_sys cty ash
        libc bindgen cbindgen cesu8-sys tree-sitter-language
        webview2-com-sys webkit2gtk-sys soup3-sys javascriptcore-rs-sys
        gdkwayland-sys gdkx11-sys gdk4-sys gtk4-sys gsk4-sys
        glutin_egl_sys glutin_glx_sys glutin_wgl_sys glutin_gles2_sys
        libappindicator-sys jack-sys alsa-sys pulse-sys
        netlink-sys nvml-wrapper-sys renderdoc-sys hdfs-sys
        libudev-sys udev-sys dbus-sys
    ].freeze

    # retep998/winapi-rs split crates: pure FFI to Win32 DLLs.
    WINAPI_SYS = /\A(kernel32|user32|advapi32|shell32|ole32|oleaut32|ws2_32|gdi32|winmm|secur32|crypt32|netapi32|userenv|psapi|dbghelp|shlwapi|comdlg32|comctl32|uuid|version|iphlpapi|setupapi|cfgmgr32|ntdll|bcrypt|schannel|winspool|dwmapi|uxtheme|d3d\w*|dxgi\w*|winhttp|wininet|wtsapi32|pdh|powrprof)-sys\z/.freeze

    # Pure-Rust reimplementations that expose a C-compatible ABI. The `-rs-sys`
    # suffix is the memorysafety.org / Trifecta pattern.
    RS_SYS = /-rs-sys\z|_rs_sys\z/.freeze

    # Crates that compile C/C++/asm without a `-sys` or `-src` name.
    EXPLICIT = %w[
        ring blake3 blst cxx cxx-build psm stacker esaxx-rs
        sys-info android-activity link-cplusplus
        symbolic-demangle imagequant tinyfiledialogs
        blake2b-rs pqc_kyber reed-solomon-erasure reed-solomon-novelpoly
        sha2-asm md5-asm sha1-asm whirlpool-asm
        generator rav1e
        lodepng mimalloc-rust
        secp256k1 rusqlite curl rocksdb onig
        wasmtime-jit-icache-coherence
    ].freeze

    def self.vendors_c?(name)
        return false if name.match?(RS_SYS)
        return false if name.match?(WINAPI_SYS)
        return false if name.start_with?("objc2-")
        return false if FFI_ONLY_SYS.include?(name)
        return true  if name.match?(/[-_]sys\z/) || name.end_with?("-src")
        return true  if name.start_with?("tree-sitter-") || name == "tree-sitter"
        EXPLICIT.include?(name)
    end

    # crate name -> [OSV package name, regex to extract upstream version from
    # the crate's semver +metadata]. Only crates that encode the upstream
    # version there; others (ring, libsqlite3-sys, aws-lc-sys, ...) need
    # per-release lookup and are not covered by this pass.
    UPSTREAM = {
        "zstd-sys"           => ["zstd",     /\+zstd\.([\d.]+)/],
        "zstd-safe"          => ["zstd",     /\+zstd\.([\d.]+)/],
        "zstd"               => ["zstd",     /\+zstd\.([\d.]+)/],
        "curl-sys"           => ["curl",     /\+curl-([\d.]+)/],
        "openssl-src"        => ["openssl",  /\+([\d][\w.]+)/],
        "bzip2-sys"          => ["bzip2",    /\+([\d.]+)/],
        "lz4-sys"            => ["lz4",      /\+lz4-([\d.]+)/],
        "jemalloc-sys"       => ["jemalloc", /\+([\d.]+)/],
        "tikv-jemalloc-sys"  => ["jemalloc", /\+([\d.]+)/],
        "blosc2-sys"         => ["c-blosc2", /\+([\d.]+)/],
        "blosc2-rs"          => ["c-blosc2", /\+([\d.]+)/],
        "liblzma-sys"        => ["xz",       /\+([\d.]+)/],
        "rdkafka-sys"        => ["librdkafka", /\+([\d.]+)/],
        "protobuf-src"       => ["protobuf",   /\+([\d.]+)/],
        "grpcio-sys"         => ["grpc",       /\+([\d.]+)/],
        "sasl2-sys"          => ["cyrus-sasl", /\+([\d.]+)/],
        "libgit2-sys"        => ["libgit2",    /\+([\d.]+)/],
        "libssh2-sys"        => ["libssh2",    /\+([\d.]+)/],
        "libnghttp2-sys"     => ["nghttp2",    /\+([\d.]+)/],
    }.freeze

    # OSV ecosystems to query for upstream C CVEs. Distro trackers cover most
    # C libraries; hits are deduped by CVE alias so querying several is cheap.
    UPSTREAM_ECOSYSTEMS = ["Debian:12", "Debian:13", "Alpine:v3.20", "Ubuntu:24.04:LTS"].freeze

    # Per-release lookup for crates that don't encode the upstream version in
    # +metadata. Values extracted from the crates.io tarball (which bundles
    # submodule content) by grepping the vendored header's version macro.
    # Regenerate with `ruby upstream_version.rb <crate> <version>...` when new
    # versions appear in crate_deps.
    UPSTREAM_TABLE = {
        ["aws-lc-fips-sys", "0.13.10" ] => ["aws-lc",    "3.0.0"],
        ["aws-lc-sys",      "0.30.0"  ] => ["aws-lc",    "1.55.0"],
        ["aws-lc-sys",      "0.33.0"  ] => ["aws-lc",    "1.64.0"],
        ["aws-lc-sys",      "0.39.0"  ] => ["aws-lc",    "1.71.0"],
        ["aws-lc-sys",      "0.40.0"  ] => ["aws-lc",    "1.72.0"],
        ["aws-lc-sys",      "0.41.0"  ] => ["aws-lc",    "1.73.0"],
        ["aws-lc-sys",      "0.42.0"  ] => ["aws-lc",    "5.1.0"],
        ["aws-lc-sys",      "0.43.0"  ] => ["aws-lc",    "5.2.0"],
        ["aws-lc-sys",      "0.44.0"  ] => ["aws-lc",    "5.5.0"],
        ["libdeflate-sys",  "1.22.0"  ] => ["libdeflate","1.22"],
        ["libmimalloc-sys", "0.1.39"  ] => ["mimalloc",  "2.1.7"],
        ["libmimalloc-sys", "0.1.40"  ] => ["mimalloc",  "2.2.3"],
        ["libmimalloc-sys", "0.1.43"  ] => ["mimalloc",  "2.2.5"],
        ["libmimalloc-sys", "0.1.44"  ] => ["mimalloc",  "2.2.4"],
        ["libmimalloc-sys", "0.1.46"  ] => ["mimalloc",  "2.3.0"],
        ["libmimalloc-sys", "0.1.49"  ] => ["mimalloc",  "2.3.2"],
        ["librocksdb-sys",  "5.6.2"   ] => ["rocksdb",   "5.6.2"],
        ["libsqlite3-sys",  "0.30.1"  ] => ["sqlite3",   "3.46.0"],
        ["libsqlite3-sys",  "0.37.0"  ] => ["sqlite3",   "3.51.3"],
        ["libwebp-sys",     "0.3.0"   ] => ["libwebp",   "1.1.0"],
        ["libz-sys",        "1.1.18"  ] => ["zlib",      "1.3.1"],
        ["libz-sys",        "1.1.2"   ] => ["zlib",      "1.2.11"],
        ["libz-sys",        "1.1.8"   ] => ["zlib",      "1.2.11"],
        ["lzma-sys",        "0.1.20"  ] => ["xz",        "5.2.5"],
        ["onig_sys",        "69.9.1"  ] => ["oniguruma", "6.9.10"],
        ["onig_sys",        "69.9.3"  ] => ["oniguruma", "6.9.10"],
    }.freeze

    def self.upstream_for(crate, version)
        if (t = UPSTREAM_TABLE[[crate, version]])
            return t
        end
        name, re = UPSTREAM[crate]
        return nil unless name && (m = version.to_s.match(re))
        [name, m[1]]
    end
end
