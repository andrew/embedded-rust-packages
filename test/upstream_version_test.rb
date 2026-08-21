require "minitest/autorun"
require_relative "../upstream_version"

class UpstreamVersionTest < Minitest::Test
    def test_extracts_encoded_brotli_version
        body = "#define BROTLI_VERSION 0x01002000\n"

        assert_equal ["brotli", "1.2.0"], extract_body("brotli-sys", body)
    end

    def test_extracts_legacy_brotli_version
        body = "#define BROTLI_VERSION \"0.3.0\"\n"

        assert_equal ["brotli", "0.3.0"], extract_body("brotli-sys", body)
    end

    def test_extracts_grpc_version
        body = 'set(PACKAGE_VERSION       "1.35.0")'

        assert_equal ["grpc", "1.35.0"], extract_body("grpcio-sys", body)
    end

    def test_extracts_pytorch_version
        body = 'const TORCH_VERSION: &str = "2.11.0";'

        assert_equal ["pytorch", "2.11.0"], extract_body("torch-sys", body)
    end
end
