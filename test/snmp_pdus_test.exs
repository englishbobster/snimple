defmodule SNMPGetTest do
	use ExUnit.Case

	import Snimple.SnmpPdus
	import Snimple.BER

	defp example_message do
		#303102010104067075626c6963
		{:ok, pkt} = Base.decode16("a02402047f71fce70201000201003016301406102b06010401c40402030204010104817d0500", [case: :lower])
		pkt
	end

	defp test_varbind_list do
		[
			{ "1.3.6.1.4.1.2680.1.2.7.3.2.0", ber_encode(100, :int32) },
			{ "1.3.6.1.4.1.2680.1.2.7.3.2.1", ber_encode("octetstring", :octetstring) },
			{ "1.3.0.1.4.1.2680.1.2.7.3.2.19865.0", ber_encode(:null) },
			{".1.3.6.1.4.1.8708.2.4.2.2.1.1.72.1667", ber_encode(10557, :int32) }
		]
	end

	test "should be able to construct an snmpget pdu" do
		assert encode_pdu([{"1.3.6.1.4.1.8708.2.3.2.4.1.1.4.253",ber_encode(:null)}], 2138176743, :snmpget) == example_message
	end

	test "should be able to make a variable binding" do
		assert ber_encode(:null) |> var_bind("1.3.1.1.1") == << 48, 8, 6, 4, 43, 1, 1, 1, 5, 0 >>
		assert ber_encode("octetstring", :octetstring) |> var_bind("1.3.6.1.4.1.2680.1.2.7.3.2.0") == << 48, 28 >>
	      <> << 6, 13, 43, 6, 1, 4, 1, 148, 120, 1, 2, 7, 3, 2, 0 >>
	      <> <<4, 11, 111, 99, 116, 101, 116, 115, 116, 114, 105, 110, 103>>
	end

	test "should be able to make a list of variable bindings" do
		vblist = test_varbind_list |> var_bind_list()
		assert byte_size(vblist) == 96 + 2
	end

end
