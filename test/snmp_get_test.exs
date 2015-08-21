defmodule SNMPGetTest do
	use ExUnit.Case

	import Snimple.SNMPGet

	def example_message do
		{:ok, pkt} = Base.decode16("303102010104067075626c6963a02402047f71fce70201000201003016301406102b06010401c40402030204010104817d0500", [case: :lower])
		pkt
	end

	test "signify should strip leading 0's in a binary" do
		assert signify(<<0, 0, 0, 10>>) == <<10>>
	end
	
	test "should be able to construct an snmp get message" do
		assert make_snmp_get() == example_message
	end

	test "should be able to encode an integer32 according to BER (Basic Encoding Rules) and get 1 byte" do
		assert ber(:int32, 8) == << 2, 1, 8 >>
	end

	test "should be able to encode an integer32 according to BER (Basic Encoding Rules) and get 2 bytes" do
		assert ber(:int32, 256) == << 2, 2, 1, 0 >>
	end
	
end
