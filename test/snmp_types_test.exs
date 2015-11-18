defmodule SNMPTypesTest do
	use ExUnit.Case

	import Snimple.SNMP.Types

	#encode signed integer32
	test "should be able to encode 0 to integer32" do
		assert encode(0, :integer32) == << 2, 1, 0 >>
	end

	test "should be able to encode small positive value to integer32" do
		assert encode(8, :integer32) == << 2, 1, 8 >>
	end

	test "should be able to encode small negative value to integer32" do
		assert encode(-8, :integer32) == << 2, 1, 248 >>
	end

	test "should be able to encode 2 byte value to integer32" do
		assert encode(256, :integer32) == << 2, 2, 1, 0 >>
	end

	test "should be able to encode large positive value to integer32" do
		assert encode(2138176743, :integer32) == << 2, 4, 127, 113, 252, 231 >>
	end

	test "should be able to encode large negative value to integer32" do
		assert encode(-935904613, :integer32) == << 2, 4, 200, 55, 58, 155 >>
	end

	test "should be able to encode max positive value to integer32" do
		assert encode(2147483647, :integer32) == << 2, 4, 127, 255, 255, 255 >>
	end

	test "should be able to encode min negative value to integer32" do
		assert encode(-2147483648, :integer32) == << 2, 4, 128, 0, 0, 0 >>
	end

	#decode bin to signed integer32
	test "should be able to decode integer32 binary to 0" do
		assert decode(<< 2, 1, 0 >>) == %{type: :integer32, length: 1, value: 0}
	end

	test "should be able to decode integer32 binary to small value" do
		assert decode(<< 2, 1, 8 >>) == %{type: :integer32, length: 1, value: 8}
	end

	test "should be able to decode integer binary to small negative value" do
		assert decode(<< 2, 1, 248 >>) == %{type: :integer32, length: 1, value: -8}
	end

	test "should be able to decode 2 byte integer32 binary to value" do
		assert decode(<< 2, 2, 1, 0 >>) == %{type: :integer32, length: 2, value: 256}
	end

	test "should be able to decode 4 byte integer32 binary to large positive value" do
		assert decode(<< 2, 4, 127, 113, 252, 231 >>) == %{type: :integer32, length: 4, value: 2138176743}
	end

	test "should be able to decode 4 byte integer32 binary to large negative value" do
		assert decode(<< 2, 4, 200, 55, 58, 155 >>) == %{type: :integer32, length: 4, value: -935904613}
	end

	test "should be able to decode integer32 binary to max positive value" do
		assert decode(<< 2, 4, 127, 255, 255, 255 >>) == %{type: :integer32, length: 4, value: 2147483647}
	end

	test "should be able to decode integer32 binary to min negative value" do
		assert decode(<< 2, 4, 128, 0, 0, 0 >>) == %{type: :integer32, length: 4, value: -2147483648}
	end

	#encode ipaddress
	test "should encode loopback ipaddress correctly" do
		assert encode("127.0.0.1", :ipaddr) == << 64, 4, 127, 0, 0, 1 >>
	end

	test "should encode another nice ipaddress correctly" do
		assert encode("172.21.1.54", :ipaddr) == << 64, 4, 172, 21, 1, 54 >>
	end

	#decode ipaddress
	test "should decode an ipaddress type correctly" do
		assert decode( << 64, 4, 172, 21, 1, 54 >> ) == %{type: :ipaddr, length: 4, value: "172.21.1.54"}
	end

	#encode counter32
	test "should encode 0 to counter32 correctly" do
		assert encode(0, :counter32) == << 65, 1, 0 >>
	end

	test "should encode max value to counter32 correctly as unsigned integer32" do
		assert encode(4294967295, :counter32) == << 65, 4, 255, 255, 255, 255 >>
	end

	test "should encode higher by 1 than max values for counter32 by wrapping" do
		assert encode(4294967296, :counter32) == << 65, 1, 0 >>
	end

	test "should encode higher by 3 than max value for counter32 by wrapping" do
		assert encode(4294967298, :counter32) == << 65, 1, 2 >>
	end

	#decode counter32
	test "should decode counter32 type to small value correctly" do
		assert decode(<< 65, 1, 8 >>) == %{type: :counter32, length: 1, value: 8}
	end

	test "should decode counter32 type to max value correctly" do
		assert decode(<< 65, 4, 255, 255, 255, 255 >>) == %{type: :counter32, length: 4, value: 4294967295}
	end

	#encode gauge32
	test "should encode 0 to gauge32 correctly" do
		assert encode(0, :gauge32) == << 66, 1, 0 >>
	end

	test "should encode max value to gauge32 correctly as unsigned integer" do
		assert encode(4294967295, :gauge32) == << 66, 4, 255, 255, 255, 255 >>
	end

	test "should not wrap value when encoding a gauge32" do
		assert encode(4294967296, :gauge32) == << 66, 4, 255, 255, 255, 255 >>
	end

	#decode gauge32
	test "should decode gauge32 to small value" do
		assert decode(<< 66, 1, 8 >>) == %{type: :gauge32, length: 1, value: 8}
	end

	test "should decode max value to gauge32 type correctly" do
		assert decode(<< 66, 4, 255, 255, 255, 255 >>) == %{type: :gauge32, length: 4, value: 4294967295}
	end

	#encode timeticks
	test "should encode timeticks correctly" do
		assert encode(0, :timeticks) == << 67, 1, 0 >>
	end

	test "should encode max value to timeticks correctly as unsigned integer" do
		assert encode(4294967295, :timeticks) == << 67, 4, 255, 255, 255, 255 >>
	end

	test "should not wrap value when encoding timeticks" do
		assert encode(4294967296, :timeticks) == << 67, 4, 255, 255, 255, 255 >>
	end

	#decode timeticks
	test "should decode timeticks type to max value correctly" do
		assert decode(<< 67, 4, 255, 255, 255, 255 >>) == %{type: :timeticks, length: 4, value: 4294967295}
	end

	#encode opaque value
	test "should encode opaque correctly. This is just another encoding of octetstring." do
		assert encode(<< 1, 2, 3, 4 >> <> "test" , :opaque) == << 68, 8, 1, 2, 3, 4, 116, 101, 115, 116 >>
	end

	#decode opaque value
	test "should decode the opaque type correctly" do
		assert decode(<< 68, 8, 1, 2, 3, 4, 116, 101, 115, 116 >>) == %{type: :opaque, length: 8, value: << 1, 2, 3, 4, 116, 101, 115, 116 >>}
	end

	#encode counter64
	test "should encode 0 to counter64 correctly" do
		assert encode(0, :counter64) == << 70, 1, 0 >>
	end

	test "should encode max value to counter64 correctly" do
		assert encode(18446744073709551615, :counter64) == << 70, 8, 255, 255, 255, 255, 255, 255, 255, 255 >>
	end

	test "should encode higher by 1 value than max value for counter64 by wrapping" do
		assert encode(18446744073709551616, :counter64) == << 70, 1, 0 >>
	end

	#decode counter64
	test "should decode counter64 type to max value for integer64 correctly" do
		assert decode(<< 70, 8, 255, 255, 255, 255, 255, 255, 255, 255 >>) == %{type: :counter64, length: 8, value: 18446744073709551615}
	end

end
