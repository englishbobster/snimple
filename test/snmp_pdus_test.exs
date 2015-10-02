defmodule SnmpPdusTest do
	use ExUnit.Case

	import Snimple.SnmpPdus

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

	defp example_snmptrap_pdu do
		{:ok, pkt} = Base.decode16("078201b9020437c8c565020100020100308201a9301006082b06010201010300430433" <>
			"fcad3f301b060a2b060106030101040100060d2b06010401c404020102030007301406" <>
			"0f2b06010401c40402010202010101324201323020060f2b06010401c4040201020201" <>
			"010232060d2b06010401c4040201020502003020060f2b06010401c404020102020101" <>
			"0332060d2b06010401c404020102050500301c060f2b06010401c40402010202010104" <>
			"320409616c61726d546573743014060f2b06010401c404020102020101053242010530" <>
			"14060f2b06010401c40402010202010106324201003014060f2b06010401c404020102" <>
			"02010107320201053014060f2b06010401c4040201020201010832020135303c060f2b" <>
			"06010401c4040201020201010932042954657374206f6620656e7669726f6e6d656e74" <>
			"616c207479706520637269746963616c20616c61726d3014060f2b06010401c4040201" <>
			"020201010a32020106301e060f2b06010401c4040201020201010b32040b07df090d0a" <>
			"0b04002b0200301e060f2b06010401c4040201020201010c32040b07df090d0a0b0400" <>
			"2b02003014060f2b06010401c4040201020201010d3241015d", [case: :lower])
		pkt
	end

	defp example_var_bind_list do
		{:ok, pkt} = Base.decode16("308201a9301006082b06010201010300430433" <>
			"fcad3f301b060a2b060106030101040100060d2b06010401c404020102030007301406" <>
			"0f2b06010401c40402010202010101324201323020060f2b06010401c4040201020201" <>
			"010232060d2b06010401c4040201020502003020060f2b06010401c404020102020101" <>
			"0332060d2b06010401c404020102050500301c060f2b06010401c40402010202010104" <>
			"320409616c61726d546573743014060f2b06010401c404020102020101053242010530" <>
			"14060f2b06010401c40402010202010106324201003014060f2b06010401c404020102" <>
			"02010107320201053014060f2b06010401c4040201020201010832020135303c060f2b" <>
			"06010401c4040201020201010932042954657374206f6620656e7669726f6e6d656e74" <>
			"616c207479706520637269746963616c20616c61726d3014060f2b06010401c4040201" <>
			"020201010a32020106301e060f2b06010401c4040201020201010b32040b07df090d0a" <>
			"0b04002b0200301e060f2b06010401c4040201020201010c32040b07df090d0a0b0400" <>
			"2b02003014060f2b06010401c4040201020201010d3241015d", [case: :lower])
		pkt
	end

	defp test_varbind_list do
		[
			{ "1.3.6.1.4.1.2680.1.2.7.3.2.0", {100, :integer32}},
			{ "1.3.6.1.4.1.2680.1.2.7.3.2.1", {"octetstring", :octetstring}},
			{ "1.3.0.1.4.1.2680.1.2.7.3.2.19865.0", {0, :null}},
			{".1.3.6.1.4.1.8708.2.4.2.2.1.1.72.1667", {10557, :integer32}}
		]
	end

	test "should be able to construct an snmpget pdu" do
		encoded_pdu = encode_pdu([ {"1.3.6.1.4.1.8708.2.3.2.4.1.1.4.253", {0, :null}} ], 2138176743, :snmpget)
		assert encoded_pdu == example_snmpget_pdu
		assert_correct_pdu_identifier(encoded_pdu, :snmpget)
	end

	test "should be able to construct an snmpresponse pdu" do
		encoded_pdu = encode_pdu([ {"1.3.6.1.4.1.8708.2.3.2.4.1.1.4.253", {8, :integer32} } ], 2138176743, 0, 0, :snmpresponse)
		assert encoded_pdu == example_snmpgetresponse_pdu
		assert_correct_pdu_identifier(encoded_pdu, :snmpresponse)
	end

	test "should be able to construct an snmpgetnext pdu" do
		encoded_pdu = encode_pdu([ {"1.3.6.1.4.1.8708.2.1.2.2.1.1.3.21", {0, :null}} ], 1601778559, :snmpgetnext)
		assert encoded_pdu == example_snmpgetnext_pdu
		assert_correct_pdu_identifier(encoded_pdu, :snmpgetnext)
	end

	test "should be able to construct an snmpset pdu" do
		encoded_pdu = encode_pdu([ {".1.3.6.1.2.1.1.6.0", {"south", :octetstring}} ], 749454221, :snmpset)
		assert encoded_pdu == example_snmpset_pdu
		assert_correct_pdu_identifier(encoded_pdu, :snmpset)
	end

	test "should be able to construct an snmptrap pdu" do
		vbl = [
			{"1.3.6.1.2.1.1.3.0", {872197439, :timeticks}},
			{"1.3.6.1.6.3.1.1.4.1.0", {"1.3.6.1.4.1.8708.2.1.2.3.0.7", :oid}},
			{"1.3.6.1.4.1.8708.2.1.2.2.1.1.1.50", {50, :gauge32}},
			{"1.3.6.1.4.1.8708.2.1.2.2.1.1.2.50", {"1.3.6.1.4.1.8708.2.1.2.5.2.0", :oid}},
			{"1.3.6.1.4.1.8708.2.1.2.2.1.1.3.50", {"1.3.6.1.4.1.8708.2.1.2.5.5.0", :oid}},
			{"1.3.6.1.4.1.8708.2.1.2.2.1.1.4.50", {"alarmTest", :octetstring}},
			{"1.3.6.1.4.1.8708.2.1.2.2.1.1.5.50", {5, :gauge32}},
			{"1.3.6.1.4.1.8708.2.1.2.2.1.1.6.50", {0, :gauge32}},
			{"1.3.6.1.4.1.8708.2.1.2.2.1.1.7.50", {5, :integer32}},
			{"1.3.6.1.4.1.8708.2.1.2.2.1.1.8.50", {53, :integer32}},
			{"1.3.6.1.4.1.8708.2.1.2.2.1.1.9.50", {"Test of environmental type critical alarm", :octetstring}},
			{"1.3.6.1.4.1.8708.2.1.2.2.1.1.10.50", {6, :integer32}},
			{"1.3.6.1.4.1.8708.2.1.2.2.1.1.11.50", {<<7, 223, 9, 13, 10, 11, 4, 0, 43, 2, 0>>, :octetstring}},
			{"1.3.6.1.4.1.8708.2.1.2.2.1.1.12.50", {<<7, 223, 9, 13, 10, 11, 4, 0, 43, 2, 0>>, :octetstring}},
			{"1.3.6.1.4.1.8708.2.1.2.2.1.1.13.50", {93, :counter32}}
		]
		encoded_vbl = vbl |> var_bind_list()
		assert encoded_vbl == example_var_bind_list 
		encoded_pdu = encode_pdu(vbl, 935904613, :snmptrap)
		assert encoded_pdu == example_snmptrap_pdu
		assert_correct_pdu_identifier(encoded_pdu, :snmptrap)
	end

	test "should be able to make a variable binding of any type" do
		assert var_bind({"1.3.1.1.1", {0, :null}}) == << 48, 8, 6, 4, 43, 1, 1, 1, 5, 0 >>
		assert var_bind({"1.3.1.1.1", {4294967295, :gauge32}}) == << 48, 12, 6, 4, 43, 1, 1, 1, 66, 4, 255, 255, 255, 255 >> 
		assert var_bind({"1.3.6.1.4.1.2680.1.2.7.3.2.0", {"octetstring", :octetstring}}) == << 48, 28 >>
	      <> << 6, 13, 43, 6, 1, 4, 1, 148, 120, 1, 2, 7, 3, 2, 0 >>
	      <> <<4, 11, 111, 99, 116, 101, 116, 115, 116, 114, 105, 110, 103>>
	end

	test "should be able to make a list of variable bindings" do
		vblist = test_varbind_list |> var_bind_list()
		assert byte_size(vblist) == 96 + 2
	end

	defp assert_correct_pdu_identifier(pdu, identifier) do
		[h|_] = :erlang.binary_to_list(pdu)
		assert h == Snimple.SnmpPdus.pdu_id(identifier)
	end

end
