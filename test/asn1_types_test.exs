defmodule ASN1TypesTest do
	use ExUnit.Case

	import Snimple.SNMP.Types
  doctest Snimple.SNMP.Types
	defp test_string,  do: "a test octet string"
	defp binary_size_small, do: 1..10 |> Enum.map(fn x -> x end) |> :binary.list_to_bin
	defp binary_size_large, do: 1..250 |> Enum.map(fn x -> x end) |> :binary.list_to_bin
	defp binary_size_mega, do: binary_size_large <> binary_size_large

	defp test_oids do
	%{
		oid_1: {".1.3.6.1.4.1.8708.2.1.2.2.1.1.3.16",    << 6, 15, 43, 6, 1, 4, 1, 196, 4, 2, 1, 2, 2, 1, 1, 3, 16 >>},        #an oid
		oid_2: {".1.3.6.1.4.1.8708.2.4.2.2.1.1.72.1667", << 6, 16, 43, 6, 1, 4, 1, 196, 4, 2, 4, 2, 2, 1, 1, 72, 141, 3 >>},   #greater than 127 at the end
		oid_3: {".1.3.6.1.4.1.8708.2.4.2.0.1.1.72.1667", << 6, 16, 43, 6, 1, 4, 1, 196, 4, 2, 4, 2, 0, 1, 1, 72, 141, 3 >>},   #zero somewhere in the middle
		oid_4: {".1.3.6.1.4.1.19865.1.2.1.6.0",          << 6, 13, 43, 6, 1, 4, 1, 129, 155, 25, 1, 2, 1, 6, 0>>},             #zero at the end
		oid_5: {"1.3.6.1.4.1.19865.1.2.1.6.0",           << 6, 13, 43, 6, 1, 4, 1, 129, 155, 25, 1, 2, 1, 6, 0>>},             #no . as start
		oid_6: {"1.3.0.1.4.1.2680.1.2.7.3.2.19865.0",	   << 6, 16, 43, 0, 1, 4, 1, 148, 120, 1, 2, 7, 3, 2, 129, 155, 25, 0 >>}#unholy combo
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

	defp test_nested_sequence do
		value_null = encode(0, :null)
		value_int = encode(1, :integer32)
		oid = encode(".1.3.6.1.4.1.8708.2.1.2.2.1.1.3.16", :oid)
	 << 48, 43 >> <> << 48, 19 >> <>  oid <> value_null <> << 48, 20 >> <>  oid <> value_int
	end

	test "should encode size according to primitive, definite length method" do
		assert encoded_data_size(binary_size_small) == << 10 >>
		assert encoded_data_size(binary_size_large) == << 0x81, 250 >>
		assert encoded_data_size(binary_size_mega) == << 0x82, 1, 244 >>
	end

	test "should decode given size according to primitive, definite length method" do
		assert decoded_data_size(<< 10 >> <> binary_size_small) == {10, binary_size_small}
		assert decoded_data_size(<< 0x81, 250 >> <> binary_size_large)== {250, binary_size_large}
		assert decoded_data_size(<< 0x82, 1 , 244 >> <> binary_size_mega) == {500, binary_size_mega}
	end

	test "should be able to encode an octetstring" do
		test_string_size = byte_size(test_string)
		assert encode(test_string, :octetstring) == << 4 >> <> << test_string_size >> <> test_string
	end

	test "should be able to decode an octetstring" do
		test_string_size = byte_size(test_string)
		octetstring_bin = << 4 >> <> << test_string_size >> <> test_string
		assert decode(octetstring_bin) == %{type: :octetstring, length: test_string_size, value: test_string}
		assert decode(octetstring_bin <> "too long") == %{type: :octetstring, length: test_string_size, value: test_string}
	end

	test "should be able to encode null value" do
		assert encode(0, :null) == << 5, 0 >>
	end

	test "should be able to decode null value" do
		assert decode(<< 5, 0 >>) == %{type: :null, length: 0, value: nil}
		assert decode(<< 5, 0 >> <> "too long") == %{type: :null, length: 0, value: nil}
	end

	test "should be able to encode assorted OIDs accordingly" do
		assert test_oid_str(:oid_1) |> encode(:oid) == test_oid_bin(:oid_1)
		assert test_oid_str(:oid_2) |> encode(:oid) == test_oid_bin(:oid_2)
		assert test_oid_str(:oid_3) |> encode(:oid) == test_oid_bin(:oid_3)
		assert test_oid_str(:oid_4) |> encode(:oid) == test_oid_bin(:oid_4)
		assert test_oid_str(:oid_5) |> encode(:oid) == test_oid_bin(:oid_5)
		assert test_oid_str(:oid_6) |> encode(:oid) == test_oid_bin(:oid_6)
	end

	test "should be able to decode assorted OIDs accordingly" do
		assert test_oid_bin(:oid_1) |> decode() == %{type: :oid, length: 15, value: test_oid_str(:oid_1)}
		assert test_oid_bin(:oid_2) |> decode() == %{type: :oid, length: 16, value: test_oid_str(:oid_2)}
		assert test_oid_bin(:oid_3) |> decode() == %{type: :oid, length: 16, value: test_oid_str(:oid_3)}
		assert test_oid_bin(:oid_4) |> decode() == %{type: :oid, length: 13, value: test_oid_str(:oid_4)}
		assert test_oid_bin(:oid_5) |> decode() == %{type: :oid, length: 13, value: "." <> test_oid_str(:oid_5)}
		assert test_oid_bin(:oid_6) |> decode() == %{type: :oid, length: 16, value: "." <> test_oid_str(:oid_6)}
		assert test_oid_bin(:oid_6) <> "too long" |> decode() == %{type: :oid, length: 16, value: "." <> test_oid_str(:oid_6)}
	end

	test "should encode an oid node less than 128" do
		assert encode_oid_node(127) == << 0x7F >>
		assert encode_oid_node(65) == << 0x41 >>
	end

	test "should encode oid node greater than or equal to 128" do
		assert encode_oid_node(8708) == << 0xC4, 0x04 >>
		assert encode_oid_node(19865) == << 0x81, 0x9B, 0x19 >>
	end

	test "should decode binary less than 128 to oid node" do
		assert decode_oid_node(<< 0x7F >>) == [127]
		assert decode_oid_node(<< 0x41 >>) == [65]
	end

	test "should decode binary greater than or equal to 128 to oid node" do
		assert decode_oid_node(<< 0xC4, 0x04 >>) == [8708]
		assert decode_oid_node(<< 0x81, 0x9B, 0x19 >>) == [19865]
	end

	test "should be able to encode a sequence correctly" do
		value = encode(0, :null)
		oid = encode(".1.3.6.1.4.1.8708.2.1.2.2.1.1.3.16", :oid)
		assert encode([{".1.3.6.1.4.1.8708.2.1.2.2.1.1.3.16", :oid}, {0, :null}], :sequence) ==  << 48, 19 >> <>  oid <> value
	end

	test "sequence should be able to contain at least one sequence" do
		value = encode(0, :null)
		oid = encode(".1.3.6.1.4.1.8708.2.1.2.2.1.1.3.16", :oid)
		assert encode([{[{".1.3.6.1.4.1.8708.2.1.2.2.1.1.3.16", :oid}, {0, :null}], :sequence}], :sequence) == << 48, 21 >> <> << 48, 19 >> <>  oid <> value
	end

	test "sequence should be able to contain more than one sequence" do
		assert encode([
			{[{".1.3.6.1.4.1.8708.2.1.2.2.1.1.3.16", :oid}, {0, :null}], :sequence},
			{[{".1.3.6.1.4.1.8708.2.1.2.2.1.1.3.16", :oid}, {1, :integer32}], :sequence}],
									:sequence) == test_nested_sequence
	end

	test "should be able to decode a sequence binary correctly" do
		expected_result = %{type: :sequence,
												length: 19,
												value: [
													%{type: :oid, length: 15, value: ".1.3.6.1.4.1.8708.2.1.2.2.1.1.3.16"},
													%{type: :null, length: 0, value: nil}
															 ]
												}
		assert decode(<< 48, 19, 6, 15, 43, 6, 1, 4, 1, 196, 4, 2, 1, 2, 2, 1, 1, 3, 16, 5, 0 >>) == expected_result
		assert decode(<< 48, 19, 6, 15, 43, 6, 1, 4, 1, 196, 4, 2, 1, 2, 2, 1, 1, 3, 16, 5, 0 >> <> "too long") == expected_result
	end

	test "should be able to decode a small sequence binary correctly" do
		{:ok, seq} = Base.decode16("30493017060a2b06010603010104010006092b06010" <>
			"60301010503300e06092b0601020102020101020102" <> "300e06092b0601020102020107020101" <>"300e06092b0601020102020108020101", [case: :lower])
		assert decode(seq) == %{length: 73, type: :sequence,
             value: [%{length: 23, type: :sequence,
                value: [%{length: 10, type: :oid,
                   value: ".1.3.6.1.6.3.1.1.4.1.0"},
                 %{length: 9, type: :oid, value: ".1.3.6.1.6.3.1.1.5.3"}]},
              %{length: 14, type: :sequence,
                value: [%{length: 9, type: :oid, value: ".1.3.6.1.2.1.2.2.1.1"},
                 %{length: 1, type: :integer32, value: 2}]},
              %{length: 14, type: :sequence,
                value: [%{length: 9, type: :oid, value: ".1.3.6.1.2.1.2.2.1.7"},
                 %{length: 1, type: :integer32, value: 1}]},
              %{length: 14, type: :sequence,
                value: [%{length: 9, type: :oid, value: ".1.3.6.1.2.1.2.2.1.8"},
                 %{length: 1, type: :integer32, value: 1}]}]}
	end

	test "should be able to decode a sequence containing a sequence" do
		expected_result = %{length: 43,
												type: :sequence,
												value: [%{length: 19,
																	type: :sequence,
																	value: [%{length: 15,
																						type: :oid,
																						value: ".1.3.6.1.4.1.8708.2.1.2.2.1.1.3.16"},
																					%{length: 0,
																						type: :null,
																						value: nil}
																				 ]
																 },
																%{length: 20,
																	type: :sequence,
																	value: [%{length: 15,
																						type: :oid,
																						value: ".1.3.6.1.4.1.8708.2.1.2.2.1.1.3.16"},
																					%{length: 1,
																						type: :integer32,
																						value: 1}
																				 ]
																 }
															 ]
											 }
				assert decode(test_nested_sequence) == expected_result
	end

end
