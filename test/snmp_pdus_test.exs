defmodule SNMPGetTest do
	use ExUnit.Case

	import Snimple.SnmpPdus
	import Snimple.BER

	defp example_message do
		{:ok, pkt} = Base.decode16("303102010104067075626c6963a02402047f71fce70201000201003016301406102b06010401c40402030204010104817d0500", [case: :lower])
		pkt
	end

	test "should be able to construct an snmp get message" do
		assert make_snmp_get() == example_message
	end

	test "should be able to make a variable binding" do
		assert ber_encode(:null) |> var_bind("1.3.1.1.1") == << 48, 8, 6, 4, 43, 1, 1, 1, 5, 0 >>
		assert ber_encode("octetstring", :octetstring) |> var_bind("1.3.6.1.4.1.2680.1.2.7.3.2.0") == << 48, 28 >> <> << 6, 13, 43, 6, 1, 4, 1, 148, 120, 1, 2, 7, 3, 2, 0 >> <>
			<<4, 11, 111, 99, 116, 101, 116, 115, 116, 114, 105, 110, 103>>
	end
		
end
