defmodule SNMPTypesTest do
	use ExUnit.Case

	import Snimple.SNMP.Types

	test "should be able to encode an int32" do
		assert encode(8, :integer32) == << 2, 1, 8 >>
		assert encode(256, :integer32) == << 2, 2, 1, 0 >>
		assert encode(2138176743, :integer32) == << 2, 4, 127, 113, 252, 231 >>
		assert encode(935904613, :integer32) == <<2, 4, 55, 200, 197, 101 >>
	end

	test "should be able to decode an int32 type" do
		assert decode(<< 2, 4, 127, 113, 252, 231 >>) == %{type: :integer32, length: 4, value: 2138176743}
	end

	test "should encode ipaddress correctly" do
		assert encode("127.0.0.1", :ipaddr) == << 64, 4, 127, 0, 0, 1 >>
		assert encode("172.21.1.54", :ipaddr) == << 64, 4, 172, 21, 1, 54 >>
	end

	test "should decode an ipaddress type correctly" do
		assert decode (<< 64, 4, 172, 21, 1, 54 >> ) == %{type: :ipaddr, length: 4, value: "172.21.1.54"}
	end

	test "should encode counter32 correctly" do
		assert encode(0, :counter32) == << 65, 1, 0 >>
		assert encode(4294967295, :counter32) == << 65, 4, 255, 255, 255, 255 >>
		assert encode(4294967296, :counter32) == << 65, 1, 0 >>
		assert encode(4294967298, :counter32) == << 65, 1, 2 >>
	end

	test "should decode counter32 type correctly" do
		assert decode(<< 65, 4, 255, 255, 255, 255 >>) == %{type: :counter32, length: 4, value: 4294967295}
	end

	test "should encode gauge32 correctly" do
		assert encode(0, :gauge32) == << 66, 1, 0 >>
		assert encode(4294967295, :gauge32) == << 66, 4, 255, 255, 255, 255 >>
		assert encode(4294967296, :gauge32) == << 66, 4, 255, 255, 255, 255 >>
	end

	test "should decode gauge32 type correctly" do
		assert decode(<< 66, 4, 255, 255, 255, 255 >>) == %{type: :gauge32, length: 4, value: 4294967295}
	end

	test "should encode timeticks correctly" do
		assert encode(0, :timeticks) == << 67, 1, 0 >>
		assert encode(4294967295, :timeticks) == << 67, 4, 255, 255, 255, 255 >>
		assert encode(4294967296, :timeticks) == << 67, 1, 0 >>
	end

	test "should decode timeticks type correctly" do
		assert decode(<< 67, 4, 255, 255, 255, 255 >>) == %{type: :timeticks, length: 4, value: "some time"}
	end

	test "should encode counter64 correctly" do
		assert encode(0, :counter64) == << 70, 1, 0 >>
		assert encode(18446744073709551615, :counter64) == << 70, 8, 255, 255, 255, 255, 255, 255, 255, 255 >>
		assert encode(18446744073709551616, :counter64) == << 70, 1, 0 >>
	end

	test "should decode counter64 type correctly" do
		assert decode(<< 70, 8, 255, 255, 255, 255, 255, 255, 255, 255 >>) == %{type: :counter64, length: 8, value: 18446744073709551615}
	end

end
