defmodule BERTest do
	use ExUnit.Case

	import Snimple.BER

	defp test_oids do
	%{
		oid_1: {".1.3.6.1.4.1.8708.2.1.2.2.1.1.3.16",    << 6, 15, 43, 6, 1, 4, 1, 196, 4, 2, 1, 2, 2, 1, 1, 3, 16 >> },       #an oid
		oid_2: {".1.3.6.1.4.1.8708.2.4.2.2.1.1.72.1667", << 6, 16, 43, 6, 1, 4, 1, 196, 4, 2, 4, 2, 2, 1, 1, 72, 141, 3 >> },  #greater than 127 at the end
		oid_3: {".1.3.6.1.4.1.8708.2.4.2.0.1.1.72.1667", << 6, 16, 43, 6, 1, 4, 1, 196, 4, 2, 4, 2, 0, 1, 1, 72, 141, 3 >> },  #zero somewhere in the middle
		oid_4: {".1.3.6.1.4.1.19865.1.2.1.6.0",          <<6, 13, 43, 6, 1, 4, 1, 129, 155, 25, 1, 2, 1, 6, 0>> },             #zero at the end
		oid_5: {"1.3.6.1.4.1.19865.1.2.1.6.0",           <<6, 13, 43, 6, 1, 4, 1, 129, 155, 25, 1, 2, 1, 6, 0>> },             #no . as start
		oid_6: {"1.3.0.1.4.1.2680.1.2.7.3.2.19865.0",	   <<6, 16, 43, 0, 1, 4, 1, 148, 120, 1, 2, 7, 3, 2, 129, 155, 25, 0 >> }#unholy combo
	}
	end

	defp test_oid_str(oid) do
		{str, _} = Dict.get(test_oids, oid)
		str
	end
	defp test_oid_bin(oid) do
		{_, bin} = Dict.get(test_oids, oid)
		bin
	end

	defp test_string do
		"a test octet string"
	end

	test "should be able to encode an integer32 according to integer binary" do
		assert ber_encode(8, :int32) == << 2, 1, 8 >>
		assert ber_encode(256, :int32) == << 2, 2, 1, 0 >>
		assert ber_encode(2138176743, :int32) == << 2, 4, 127, 113, 252, 231 >>
		assert ber_encode(935904613, :int32) == <<2, 4, 55, 200, 197, 101 >>
	end

	test "should be able to decode an integer type to integer" do
		assert ber_decode(<< 2, 4, 127, 113, 252, 231 >>) == 2138176743
	end

	test "should be able to encode null value" do
		assert ber_encode(:null) == << 5, 0 >>
	end

	test "should be able to decode null value" do
		assert ber_decode(<< 5, 0 >>) == :null
	end

	test "should be able to encode an octetstring" do
		test_string_size = byte_size(test_string)
		assert ber_encode(test_string, :octetstring) == << 4 >> <> << test_string_size >> <> test_string
	end

	test "should be able to decode a binary to an octet string" do
		assert ber_decode(<< 4, 23 >> <> "this should be a string") ==  "this should be a string"
	end

	test "should be able to encode assorted OIDs accordingly" do
		assert test_oid_str(:oid_1) |> ber_encode(:oid) == test_oid_bin(:oid_1)
		assert test_oid_str(:oid_2) |> ber_encode(:oid) == test_oid_bin(:oid_2)
		assert test_oid_str(:oid_3) |> ber_encode(:oid) == test_oid_bin(:oid_3)
		assert test_oid_str(:oid_4) |> ber_encode(:oid) == test_oid_bin(:oid_4)
		assert test_oid_str(:oid_5) |> ber_encode(:oid) == test_oid_bin(:oid_5)
		assert test_oid_str(:oid_6) |> ber_encode(:oid) == test_oid_bin(:oid_6)
	end

	test "should be able to decode assorted OIDs accordingly" do
		assert test_oid_bin(:oid_1) |> ber_decode() == test_oid_str(:oid_1)
		assert test_oid_bin(:oid_2) |> ber_decode() == test_oid_str(:oid_2)
		assert test_oid_bin(:oid_3) |> ber_decode() == test_oid_str(:oid_3)
		assert test_oid_bin(:oid_4) |> ber_decode() == test_oid_str(:oid_4)
		assert test_oid_bin(:oid_5) |> ber_decode() == "." <> test_oid_str(:oid_5)
		assert test_oid_bin(:oid_6) |> ber_decode() == "." <> test_oid_str(:oid_6)
	end

	test "should encode an oid node less than 128" do
		assert encode_oid_node(127) == <<0x7F>>
		assert encode_oid_node(65) == <<0x41>>
	end

	test "should encode oid node greater than or equal to 128" do
		assert encode_oid_node(8708) == << 0xC4, 0x04 >>
		assert encode_oid_node(19865) == << 0x81, 0x9B, 0x19 >>
	end

	test "should decode oids less than 128" do
		assert decode_oid_node(<< 0x7F >>) == [127]
		assert decode_oid_node(<< 0x41 >>) == [65]
	end

	test "should decode oids greater than or equal to 128" do
		assert decode_oid_node(<< 0xC4, 0x04 >>) == [8708]
		assert decode_oid_node(<< 0x81, 0x9B, 0x19 >>) == [19865]
	end

	test "should encode a sequence correctly" do
		value = ber_encode(:null)
		oid = ber_encode(".1.3.6.1.4.1.8708.2.1.2.2.1.1.3.16", :oid)
		assert ber_encode(oid <> value, :sequence) ==  << 48, 19 >> <>  << 6, 15, 43, 6, 1, 4, 1, 196, 4, 2, 1, 2, 2, 1, 1, 3, 16 >> <> << 5, 0 >>
	end

	test "should decode a sequence correctly" do
		assert ber_decode(<< 48, 19, 6, 15, 43, 6, 1, 4, 1, 196, 4, 2, 1, 2, 2, 1, 1, 3, 16, 5, 0 >>) == <<6, 15, 43, 6, 1, 4, 1, 196, 4, 2, 1, 2, 2, 1, 1, 3, 16, 5, 0 >>
	end

	test "should encode ipaddress correctly" do
		assert ber_encode("127.0.0.1", :ipaddr) == << 64, 4, 127, 0, 0, 1 >>
		assert ber_encode("172.21.1.54", :ipaddr) == << 64, 4, 172, 21, 1, 54 >>
	end

	test "should encode counter32 correctly" do
		assert ber_encode(0, :counter32) == << 65, 1, 0 >>
		assert ber_encode(4294967295, :counter32) == << 65, 4, 255, 255, 255, 255 >>
		assert ber_encode(4294967296, :counter32) == << 65, 1, 0 >>
		assert ber_encode(4294967298, :counter32) == << 65, 1, 2 >>
	end

	test "should encode gauge32 correctly" do
		assert ber_encode(0, :gauge32) == << 66, 1, 0 >>
		assert ber_encode(4294967295, :gauge32) == << 66, 4, 255, 255, 255, 255 >>
		assert ber_encode(4294967296, :gauge32) == << 66, 4, 255, 255, 255, 255 >>
	end

	test "should encode timeticks correctly" do
		assert ber_encode(872197439, :timeticks) == << 43, 4, 12, 34, 55, 33 >>
		assert ber_encode(4294967295, :timeticks) == << 43, 4, 12, 34, 55, 33 >>
		assert ber_encode(4294967296, :timeticks) == << 43, 1, 0 >>
	end

	test "should encode opaque correctly" do
		assert ber_encode("really a double wrapped octetstring", :opaque) == << 44, 4, 12, 34, 55, 33 >>
	end

	test "should encode counter64 correctly" do
		assert ber_encode(0, :counter64) == << 70, 1, 0 >>
		assert ber_encode(18446744073709551615, :counter64) == << 70, 8, 255, 255, 255, 255, 255, 255, 255, 255 >>
		assert ber_encode(18446744073709551616, :counter64) == << 70, 1, 0 >>
	end

	test "nr_of_bits should return correct value for some inputs" do
		assert nr_of_bits(19865) == 15
		assert nr_of_bits(841557) == 20
	end

end
