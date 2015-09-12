defmodule SNMPGetTest do
	use ExUnit.Case

	import Snimple.SnmpPdus
	import Snimple.BER

	defp example_snmpget_pdu do
		{:ok, pkt} = Base.decode16("002402047f71fce70201000201003016301406102b06010401c40402030204010104817d0500", [case: :lower])
		pkt
	end

	defp example_snmpgetresponse_pdu do
		{:ok, pkt} = Base.decode16("022502047f71fce70201000201003017301506102b06010401c40402030204010104817d020108", [case: :lower])
		pkt
	end
	
	defp example_snmpgetnext_pdu do
		{:ok, pkt} = Base.decode16("012302045f79337f02010002010030153013060f2b06010401c40402010202010103150500", [case: :lower])
		pkt
	end

	defp example_snmpset_pdu do
		{:ok, pkt} = Base.decode16("032102042cabc38d0201000201003013301106082b060102010106000405736f757468", [case: :lower])
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
		encoded_pdu = encode_pdu([{"1.3.6.1.4.1.8708.2.3.2.4.1.1.4.253", ber_encode(:null)}], 2138176743, :snmpget)
		assert encoded_pdu == example_snmpget_pdu
		assert_correct_pdu_identifier(encoded_pdu, :snmpget)
	end

	test "should be able to construct an snmpresponse pdu" do
		encoded_pdu = encode_pdu([{"1.3.6.1.4.1.8708.2.3.2.4.1.1.4.253", ber_encode(8, :int32)}], 2138176743, 0, 0, :snmpresponse)
		assert encode_pdu = example_snmpgetresponse_pdu
		assert_correct_pdu_identifier(encoded_pdu, :snmpresponse)
	end

	test "should be able to construct an snmpgetnext pdu" do
		encoded_pdu = encode_pdu([{"1.3.6.1.4.1.8708.2.1.2.2.1.1.3.21", ber_encode(:null)}], 1601778559, :snmpgetnext)
		assert encoded_pdu == example_snmpgetnext_pdu
		assert_correct_pdu_identifier(encoded_pdu, :snmpgetnext)
	end

	test "should be able to construct an snmpset pdu" do
		encoded_pdu = encode_pdu([{".1.3.6.1.2.1.1.6.0", ber_encode("south", :octetstring)}], 749454221, :snmpset)
		assert encoded_pdu == example_snmpset_pdu
		assert_correct_pdu_identifier(encoded_pdu, :snmpset)
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

	defp assert_correct_pdu_identifier(pdu, identifier) do
		[h|_] = :erlang.binary_to_list(pdu)
		assert <<h>> == Dict.get(Snimple.SnmpPdus.pdu_identifier, identifier)
	end

end
