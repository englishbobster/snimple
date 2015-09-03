defmodule BERTest do
	use ExUnit.Case

	import Snimple.BER

	defp test_string do
		"a test octet string"
	end

	test "should be able to encode an integer32 according to BER_ENCODE" do
		assert ber_encode(8, :int32) == << 2, 1, 8 >>
		assert ber_encode(256, :int32) == << 2, 2, 1, 0 >>
		assert ber_encode(2138176743, :int32) == << 2, 4, 127, 113, 252, 231 >>
	end

	test "should be able to encode null value according to BER_ENCODE" do
		assert ber_encode(:null) == << 5, 0 >>
	end

	test "should be able to encode an octetstring according to BER_ENCODE" do
		test_string_size = byte_size(test_string)
		assert ber_encode(test_string, :octetstring) == << 4 >> <> <<test_string_size>> <> test_string
	end

	test "should be able to encode assorted OIDs according to BER_ENCODE" do
		oid_1 = ".1.3.6.1.4.1.8708.2.1.2.2.1.1.3.16"       #an oid
		oid_2 = ".1.3.6.1.4.1.8708.2.4.2.2.1.1.72.1667"    #greater than 127 at the end
		oid_3 = ".1.3.6.1.4.1.8708.2.4.2.0.1.1.72.1667"    #zero somewhere in the middle
		oid_4 = ".1.3.6.1.4.1.19865.1.2.1.6.0"             #zero at the end
		oid_5 = "1.3.6.1.4.1.19865.1.2.1.6.0"              #no . as start
		oid_6 = "1.3.0.1.4.1.2680.1.2.7.3.2.19865.0"       #unholy combo
		assert ber_encode(oid_1, :oid) == << 6, 15, 43, 6, 1, 4, 1, 196, 4, 2, 1, 2, 2, 1, 1, 3, 16 >>
		assert ber_encode(oid_2, :oid) == << 6, 16, 43, 6, 1, 4, 1, 196, 4, 2, 4, 2, 2, 1, 1, 72, 141, 3 >>
		assert ber_encode(oid_3, :oid) == << 6, 16, 43, 6, 1, 4, 1, 196, 4, 2, 4, 2, 0, 1, 1, 72, 141, 3 >>
		assert ber_encode(oid_4, :oid) == <<6, 13, 43, 6, 1, 4, 1, 129, 155, 25, 1, 2, 1, 6, 0>>
		assert ber_encode(oid_5, :oid) == <<6, 13, 43, 6, 1, 4, 1, 129, 155, 25, 1, 2, 1, 6, 0>>
		assert ber_encode(oid_6, :oid) == <<6, 16, 43, 0, 1, 4, 1, 148, 120, 1, 2, 7, 3, 2, 129, 155, 25, 0 >>
	end

	test "should encode an oid node less than 128" do
		assert encode_oid_node(127) == <<0x7F>>
		assert encode_oid_node(65) == <<0x41>>
	end

	test "should encode oid node greater than or equal to 128" do
		assert encode_oid_node(8708) == << 0xC4, 0x04 >>
		assert encode_oid_node(19865) == << 0x81, 0x9B, 0x19 >>
	end

	test "should encode a sequence correctly" do
		value = ber_encode(:null)
		oid = ber_encode(".1.3.6.1.4.1.8708.2.1.2.2.1.1.3.16", :oid)
		assert ber_encode(oid <> value, :sequence) ==  << 48, 19 >> <>  << 6, 15, 43, 6, 1, 4, 1, 196, 4, 2, 1, 2, 2, 1, 1, 3, 16 >> <> << 5, 0 >>
	end

	test "nr_of_bits should return correct value for some inputs" do
		assert nr_of_bits(19865) == 15
		assert nr_of_bits(841557) == 20
	end

end
