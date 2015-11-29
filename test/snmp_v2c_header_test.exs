defmodule V2cHeaderTest do
    use ExUnit.Case, async: true

    import Snimple.SNMP.Header

    test "should encode header correctly" do
      assert encode_v2c_header("united") == << 2, 1, 1, 4, 6, 117, 110, 105, 116, 101, 100 >>
    end

    test "should decode header correctly" do
      assert decode_v2c_header(<< 2, 1, 1, 4, 6, 117, 110, 105, 116, 101, 100 >>) ==
        %{version: "v2c", community: "united"}
    end

    test "should raise error when not version v2c" do
      assert_raise ArgumentError, "SNMP version not supported",  fn ->
        decode_v2c_header(<< 2, 1, 0, 4, 6, 117, 110, 105, 116, 101, 100 >>)
        end
    end

end
