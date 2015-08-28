defmodule BERTest do
	use ExUnit.Case

	import Snimple.BER

	defp test_string do
		"a test octet string"
	end
	
	test "should be able to encode an integer32 according to BER" do
		assert ber(:int32, 8) == << 2, 1, 8 >>
	end

	test "should be able to encode an integer32 according to BER" do
		assert ber(:int32, 256) == << 2, 2, 1, 0 >>
	end

	test "should be able to encode null value according to BER" do
		assert ber(:null) == << 5, 0 >>
	end

	test "should be able to encode an octetstring according to BER" do
		test_string_size = byte_size(test_string)
		assert ber(:octetstring, test_string) == << 4 >> <> <<test_string_size>> <> test_string
	end

	test "should be able to encode an OID according to BER" do
		oid = ".1.3.6.1.4.1.8708.2.1.2.2.1.1.3.237"
		assert ber(:oid, oid) == << 6, 16, 43, 6, 1, 4, 1, 196, 4, 2, 4, 2, 2, 1, 1, 72, 141, 3 >>
	end

	test "should encode oid node greater than or equal to 128" do
		assert encode_oid_node(8708) == << 0xC4, 0x04 >>
		assert encode_oid_node(19865) == << 0x81, 0x9B, 0x19 >>
	end
	
end
