defmodule SNMPGetTest do
	use ExUnit.Case

	import Snimple.SNMPGet

	def example_message do
		{:ok, pkt} = Base.decode16("303102010104067075626c6963a02402047f71fce70201000201003016301406102b06010401c40402030204010104817d0500", [case: :lower])
		pkt
	end

	def test_string do
		"a test octet string"
	end

	test "should be able to construct an snmp get message" do
		assert make_snmp_get() == example_message
	end

	#tests of encoding utilities
	test "should be able to strip leading 0's in a binary" do
		assert strip_zero_bytes(<<0, 0, 0, 10>>) == <<10>>
	end

	test "should encode oid node greater than or equal to 128" do
		assert encode_node(8708) == << 0x82, 0x37 >>
	end

	#tests of Basic Encoding Rules (BER)
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
		assert ber(:oid, oid) == <<6, 16, 43, 6, 1, 4, 1, 196, 4, 2, 4, 2, 2, 1, 1, 72, 141, 3>>
	end
	
end
