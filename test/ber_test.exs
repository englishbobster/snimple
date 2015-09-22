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
		assert ber_encode(0, :timeticks) == << 67, 1, 0 >>
		assert ber_encode(4294967295, :timeticks) == << 67, 4, 255, 255, 255, 255 >>
		assert ber_encode(4294967296, :timeticks) == << 67, 1, 0 >>
	end

	test "should encode counter64 correctly" do
		assert ber_encode(0, :counter64) == << 70, 1, 0 >>
		assert ber_encode(18446744073709551615, :counter64) == << 70, 8, 255, 255, 255, 255, 255, 255, 255, 255 >>
		assert ber_encode(18446744073709551616, :counter64) == << 70, 1, 0 >>
	end

end
