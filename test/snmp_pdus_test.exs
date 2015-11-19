defmodule SnmpPdusTest do
	use ExUnit.Case

	import Snimple.SnmpPdus

	#these encoded snmp message examples and all encoded message fragments are all based on the tcpdumps in the examples folder
	defp example_snmpget_pdu do
		{:ok, pkt} = Base.decode16("a02402047f71fce70201000201003016301406102b06010401c40402030204010104817d0500", [case: :lower])
		pkt
	end

	defp example_snmpgetnext_pdu do
		{:ok, pkt} = Base.decode16("a12302045f79337f02010002010030153013060f2b06010401c40402010202010103150500", [case: :lower])
		pkt
	end

	defp example_snmpresponse_pdu do
		{:ok, pkt} = Base.decode16("a22502047f71fce70201000201003017301506102b06010401c40402030204010104817d020108", [case: :lower])
		pkt
	end

	defp example_snmpset_pdu do
		{:ok, pkt} = Base.decode16("a32102042cabc38d0201000201003013301106082b060102010106000405736f757468", [case: :lower])
		pkt
	end

	defp example_snmpbulkget_pdu do
		{:ok, pkt} = Base.decode16("a52102041788f9b502010002010a30133011060d2b06010401c4040201020101000500", [case: :lower])
		pkt
	end

	defp example_snmpinform_pdu do
		{:ok, pkt} = Base.decode16("a65702045e408fa202010002010030493017060a2b06010603010104010006092b06010" <>
			"60301010503300e06092b0601020102020101020102300e06092b0601020102020107020101300e06092b0601020102020108020101", [case: :lower])
		pkt
	end

	defp example_snmptrap_pdu do
		{:ok, pkt} = Base.decode16("a78201b9020437c8c565020100020100308201a9301006082b06010201010300430433" <>
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

	defp unencoded_varbind_list do
		[
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
	end

	test "should be able to construct an snmpget pdu" do
		encoded_pdu = encode_pdu([ {"1.3.6.1.4.1.8708.2.3.2.4.1.1.4.253", {0, :null}} ], 2138176743, :snmpget)
		assert encoded_pdu == example_snmpget_pdu
	end

	test "should be able to construct an snmpresponse pdu" do
		encoded_pdu = encode_pdu([ {"1.3.6.1.4.1.8708.2.3.2.4.1.1.4.253", {8, :integer32} } ], 2138176743, 0, 0, :snmpresponse)
		assert encoded_pdu == example_snmpresponse_pdu
	end

	test "should be able to construct an snmpgetnext pdu" do
		encoded_pdu = encode_pdu([ {"1.3.6.1.4.1.8708.2.1.2.2.1.1.3.21", {0, :null}} ], 1601778559, :snmpgetnext)
		assert encoded_pdu == example_snmpgetnext_pdu
	end

	test "should be able to construct an snmpset pdu" do
		encoded_pdu = encode_pdu([ {".1.3.6.1.2.1.1.6.0", {"south", :octetstring}} ], 749454221, :snmpset)
		assert encoded_pdu == example_snmpset_pdu
	end

	test "should be able to construct an snmptrap pdu" do
		encoded_pdu = encode_pdu(unencoded_varbind_list, 935904613, :snmptrap)
		assert encoded_pdu == example_snmptrap_pdu
	end

	test "should be able to construct an snmpgetbulk pdu" do
		encoded_pdu = encode_pdu([ {"1.3.6.1.4.1.8708.2.1.2.1.1.0", {0, :null} }], 394852789, 0, 10, :snmpgetbulk)
		assert encoded_pdu == example_snmpbulkget_pdu
	end

	test "should be able to construct an snmpinform pdu" do
		encoded_pdu = encode_pdu([{"1.3.6.1.6.3.1.1.4.1.0", {"1.3.6.1.6.3.1.1.5.3", :oid}},
														  {"1.3.6.1.2.1.2.2.1.1", {2, :integer32}},
															{"1.3.6.1.2.1.2.2.1.7", {1, :integer32}},
														  {"1.3.6.1.2.1.2.2.1.8", {1, :integer32}}],
														  1581289378, :snmpinform)
		assert encoded_pdu == example_snmpinform_pdu
		end

	test "should be able to make a variable binding with oid and null" do
		assert var_bind({"1.3.1.1.1", {0, :null}}) == << 48, 8, 6, 4, 43, 1, 1, 1, 5, 0 >>
	end

	test "should be able to make a variable binding with oid and integer type" do
		assert var_bind({"1.3.1.1.1", {4294967295, :gauge32}}) == << 48, 12, 6, 4, 43, 1, 1, 1, 66, 4, 255, 255, 255, 255 >>
	end

	test "should be able to make a variable binding with oid and octetstring" do
		assert var_bind({"1.3.6.1.4.1.2680.1.2.7.3.2.0", {"octetstring", :octetstring}}) == << 48, 28 >>
	      <> << 6, 13, 43, 6, 1, 4, 1, 148, 120, 1, 2, 7, 3, 2, 0 >>
	      <> <<4, 11, 111, 99, 116, 101, 116, 115, 116, 114, 105, 110, 103>>
	end

	test "should be able to make a list of variable bindings" do
		vblist = unencoded_varbind_list |> var_bind_list()
		assert vblist == example_var_bind_list
	end

	test "should be able to decode an snmpget pdu" do
		assert decode_pdu(example_snmpget_pdu) == %{type: :snmpget,
																								length: 36,
																							  request_id: %{type: :integer32, length: 4, value: 2138176743},
																							  error_status: :noError,
																							  error_index: %{type: :integer32, length: 1, value: 0},
																							  var_bind_list: %{length: 22, type: :sequence,
																																 value: [%{length: 20, type: :sequence,
																																					 value: [%{length: 16, type: :oid,
																																										 value: ".1.3.6.1.4.1.8708.2.3.2.4.1.1.4.253"},
																																									 %{length: 0, type: :null, value: nil}]}]}}
	end

	test "should be able to decode an snmpgetnext pdu" do
		assert decode_pdu(example_snmpgetnext_pdu) ==%{error_index: %{length: 1, type: :integer32, value: 0},
             error_status: :noError, length: 35,
             request_id: %{length: 4, type: :integer32, value: 1601778559},
             type: :snmpgetnext,
             var_bind_list: %{length: 21, type: :sequence,
               value: [%{length: 19, type: :sequence,
                  value: [%{length: 15, type: :oid,
                     value: ".1.3.6.1.4.1.8708.2.1.2.2.1.1.3.21"},
													%{length: 0, type: :null, value: nil}]}]}}
	end

	test "should be able to decode an snmpresponse pdu" do
		assert decode_pdu(example_snmpresponse_pdu) == %{error_index: %{length: 1, type: :integer32, value: 0},
             error_status: :noError, length: 37,
             request_id: %{length: 4, type: :integer32, value: 2138176743},
             type: :snmpresponse,
             var_bind_list: %{length: 23, type: :sequence,
               value: [%{length: 21, type: :sequence,
                  value: [%{length: 16, type: :oid,
                     value: ".1.3.6.1.4.1.8708.2.3.2.4.1.1.4.253"},
                   %{length: 1, type: :integer32, value: 8}]}]}}
	end

	test "should be able to decode an snmpset pdu" do
		assert decode_pdu(example_snmpset_pdu) == %{error_index: %{length: 1, type: :integer32, value: 0},
             error_status: :noError, length: 33,
             request_id: %{length: 4, type: :integer32, value: 749454221},
             type: :snmpset,
             var_bind_list: %{length: 19, type: :sequence,
               value: [%{length: 17, type: :sequence,
                  value: [%{length: 8, type: :oid, value: ".1.3.6.1.2.1.1.6.0"},
                   %{length: 5, type: :octetstring, value: "south"}]}]}}
	end

	test "should be able to decode an snmpbulk pdu" do
		assert decode_pdu(example_snmpbulkget_pdu) == %{length: 33,
             max_repetitions: %{length: 1, type: :integer32, value: 10},
             non_repeaters: %{length: 1, type: :integer32, value: 0},
             request_id: %{length: 4, type: :integer32, value: 394852789},
             type: :snmpgetbulk,
             var_bind_list: %{length: 19, type: :sequence,
               value: [%{length: 17, type: :sequence,
                  value: [%{length: 13, type: :oid,
                     value: ".1.3.6.1.4.1.8708.2.1.2.1.1.0"},
                   %{length: 0, type: :null, value: nil}]}]}}
	end

	test "should be able to decode an snmpinform pdu" do
		assert decode_pdu(example_snmpinform_pdu) == %{error_index: %{length: 1, type: :integer32, value: 0},
             error_status: :noError, length: 87,
             request_id: %{length: 4, type: :integer32, value: 1581289378},
             type: :snmpinform,
             var_bind_list: %{length: 73, type: :sequence,
               value: [%{length: 23, type: :sequence,
                  value: [%{length: 10, type: :oid,
                     value: ".1.3.6.1.6.3.1.1.4.1.0"},
                   %{length: 9, type: :oid, value: ".1.3.6.1.6.3.1.1.5.3"}]},
                %{length: 14, type: :sequence,
                  value: [%{length: 9, type: :oid,
                     value: ".1.3.6.1.2.1.2.2.1.1"},
                   %{length: 1, type: :integer32, value: 2}]},
                %{length: 14, type: :sequence,
                  value: [%{length: 9, type: :oid,
                     value: ".1.3.6.1.2.1.2.2.1.7"},
                   %{length: 1, type: :integer32, value: 1}]},
                %{length: 14, type: :sequence,
                  value: [%{length: 9, type: :oid,
                     value: ".1.3.6.1.2.1.2.2.1.8"},
                   %{length: 1, type: :integer32, value: 1}]}]}}
	end

	test "should be able to decode an snmptrap pdu" do
		assert decode_pdu(example_snmptrap_pdu) == %{error_index: %{length: 1, type: :integer32, value: 0},
             error_status: :noError,
             length: 441,
             request_id: %{length: 4, type: :integer32, value: 935904613},
             type: :snmptrap,
             var_bind_list: %{length: 425, type: :sequence,
               value: [%{length: 16, type: :sequence,
                  value: [%{length: 8, type: :oid, value: ".1.3.6.1.2.1.1.3.0"},
                   %{length: 4, type: :timeticks, value: 872197439}]},
                %{length: 27, type: :sequence,
                  value: [%{length: 10, type: :oid,
                     value: ".1.3.6.1.6.3.1.1.4.1.0"},
                   %{length: 13, type: :oid,
                     value: ".1.3.6.1.4.1.8708.2.1.2.3.0.7"}]},
                %{length: 20, type: :sequence,
                  value: [%{length: 15, type: :oid,
                     value: ".1.3.6.1.4.1.8708.2.1.2.2.1.1.1.50"},
                   %{length: 1, type: :gauge32, value: 50}]},
                %{length: 32, type: :sequence,
                  value: [%{length: 15, type: :oid,
                     value: ".1.3.6.1.4.1.8708.2.1.2.2.1.1.2.50"},
                   %{length: 13, type: :oid,
                     value: ".1.3.6.1.4.1.8708.2.1.2.5.2.0"}]},
                %{length: 32, type: :sequence,
                  value: [%{length: 15, type: :oid,
                     value: ".1.3.6.1.4.1.8708.2.1.2.2.1.1.3.50"},
                   %{length: 13, type: :oid,
                     value: ".1.3.6.1.4.1.8708.2.1.2.5.5.0"}]},
                %{length: 28, type: :sequence,
                  value: [%{length: 15, type: :oid,
                     value: ".1.3.6.1.4.1.8708.2.1.2.2.1.1.4.50"},
                   %{length: 9, type: :octetstring, value: "alarmTest"}]},
                %{length: 20, type: :sequence,
                  value: [%{length: 15, type: :oid,
                     value: ".1.3.6.1.4.1.8708.2.1.2.2.1.1.5.50"},
                   %{length: 1, type: :gauge32, value: 5}]},
                %{length: 20, type: :sequence,
                  value: [%{length: 15, type: :oid,
                     value: ".1.3.6.1.4.1.8708.2.1.2.2.1.1.6.50"},
                   %{length: 1, type: :gauge32, value: 0}]},
                %{length: 20, type: :sequence,
                  value: [%{length: 15, type: :oid,
                     value: ".1.3.6.1.4.1.8708.2.1.2.2.1.1.7.50"},
                   %{length: 1, type: :integer32, value: 5}]},
                %{length: 20, type: :sequence,
                  value: [%{length: 15, type: :oid,
                     value: ".1.3.6.1.4.1.8708.2.1.2.2.1.1.8.50"},
                   %{length: 1, type: :integer32, value: 53}]},
                %{length: 60, type: :sequence,
                  value: [%{length: 15, type: :oid,
                     value: ".1.3.6.1.4.1.8708.2.1.2.2.1.1.9.50"},
                   %{length: 41, type: :octetstring,
                     value: "Test of environmental type critical alarm"}]},
                %{length: 20, type: :sequence,
                  value: [%{length: 15, type: :oid,
                     value: ".1.3.6.1.4.1.8708.2.1.2.2.1.1.10.50"},
                   %{length: 1, type: :integer32, value: 6}]},
                %{length: 30, type: :sequence,
                  value: [%{length: 15, type: :oid,
                     value: ".1.3.6.1.4.1.8708.2.1.2.2.1.1.11.50"},
                   %{length: 11, type: :octetstring,
                     value: <<7, 223, 9, 13, 10, 11, 4, 0, 43, 2, 0>>}]},
                %{length: 30, type: :sequence,
                  value: [%{length: 15, type: :oid,
                     value: ".1.3.6.1.4.1.8708.2.1.2.2.1.1.12.50"},
                   %{length: 11, type: :octetstring,
                     value: <<7, 223, 9, 13, 10, 11, 4, 0, 43, 2, 0>>}]},
                %{length: 20, type: :sequence,
                  value: [%{length: 15, type: :oid,
                     value: ".1.3.6.1.4.1.8708.2.1.2.2.1.1.13.50"},
                   %{length: 1, type: :counter32, value: 93}]}]}}
	end
end
