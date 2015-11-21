defmodule Snimple.SNMP.Types do
	use Bitwise, only_operators: true

	@moduledoc """
	This SNMP imlementation should be compatible with at least SNMPv2c.
	The module defines:

  * The types used in encoding and decoding SNMP messages.
    These are separated according to ASN.1 basic types and
    SNMP specific types.

  * The ASN.1 basic encoding rules (BER) used for SNMP encoding
    and decoding of the defined types.

  The types supported can be listed using one of the functions:

  * list_asn1_types

  * list_snmp_types

  * list_all_types


  See the relevant function help.
	"""

	defp asn1_type_identifier do
		%{
			integer:     0x02,
		  octetstring: 0x04,
		  null:        0x05,
		  oid:         0x06,
			sequence:    0x30,
		}
	end
	defp asn1_type(id) when is_atom(id) do
		asn1_type_identifier[id]
	end

	@doc ~S"""
	Helper function that lists the supported ASN.1 types used by SNMP.

 ## Example
      iex> Snimple.SNMP.Types.list_asn1_types
      [:integer, :null, :octetstring, :oid, :sequence]

	"""
	def list_asn1_types do
		Dict.keys(asn1_type_identifier)
	end

	defp snmp_type_identifier do
		%{
			integer32:   asn1_type(:integer),
			ipaddr:      0x40,
			counter32:   0x41,
			gauge32:     0x42,
			timeticks:   0x43,
			opaque:      0x44,
			counter64:   0x46
		 }
	end
	defp snmp_type(id) when is_atom(id) do
		snmp_type_identifier[id]
	end
	@doc ~S"""
	Helper function that lists the supported SNMP derived types used by SNMP.

 ## Example
      iex> Snimple.SNMP.Types.list_snmp_types
      [:counter32, :counter64, :gauge32, :integer32, :ipaddr, :opaque, :timeticks]

	"""
	def list_snmp_types do
		Dict.keys(snmp_type_identifier)
	end

	@doc ~S"""
	Helper function that lists all the supported SNMP types, both derived and ASN.1.

 ## Example
      iex> Snimple.SNMP.Types.list_all_types
      [:integer, :null, :octetstring, :oid, :sequence, :counter32, :counter64, :gauge32, :integer32, :ipaddr, :opaque, :timeticks]

	"""
	def list_all_types do
		List.flatten([list_asn1_types, list_snmp_types])
	end

	@doc ~S"""
	Encodes the given `value` and `type` and produces a binary representation according to the ASN.1 basic encoding rules.
	The result is a sequence of bytes:

  * The first byte is the id byte representing the type.
  * The second is the size byte of the coming encoded value.
  * The rest is the encoded value itself.

	Depending on `type`, the expected values will be as follows:

  * `:octetstring`, `:opaque` -> `value` shall be a binary string.
  * `:null` -> `value` will be ignored.
  * `:ipaddr` -> `value` shall be a string representation of an ip address e.g. "127.0.0.1"
  * `:integer32` -> `value` is a 32 bit signed integer.
  * `:counter32` -> `value` is an unsigned 32 bit integer that wraps.
  * `:gauge32`  ->  `value` is an unsigned 32 bit integer that can increase or descrease, cannot be smaller than zero and doesn't wrap.
  * `:timeticks` -> `value` is an unsigned integer that represents the time in hundredths of a second.
  * `:counter64` -> `value` is an unsigned 64 bit integer that wraps.
  * `:oid` -> `value` shall be a string representation of the oid e.g. ".1.3.4.6.567.4.4.1.1.2". The leading "." is not mandatory.
  * `:sequence` -> The sequence type is basically a wrapper type for all the other types. The `value` shall be a list of tuples defining
  values and types to be wrapped.

  e.g. [{"127.0.0.1", :ipaddr}, {".1.2.3.4.5.6", :oid}, {"Hello", :octetstring}]

 ## Examples
      iex> Snimple.SNMP.Types.encode("Hello", :octetstring)
      <<4, 5, 72, 101, 108, 108, 111>>

      iex> Snimple.SNMP.Types.encode(0, :null)
      <<5, 0>>

      iex> Snimple.SNMP.Types.encode("127.0.0.1", :ipaddr)
      <<64, 4, 127, 0, 0, 1>>

      iex> Snimple.SNMP.Types.encode(1337, :gauge32)
      <<66, 2, 5, 57>>

      iex> Snimple.SNMP.Types.encode(".1.3.34.3.5.6.7.8", :oid)
      <<6, 7, 43, 34, 3, 5, 6, 7, 8>>

      iex> Snimple.SNMP.Types.encode([{"127.0.0.1", :ipaddr}, {".1.2.3.4.5.6", :oid}, {"Hello", :octetstring}], :sequence)
      <<48, 20, 64, 4, 127, 0, 0, 1, 6, 5, 42, 3, 4, 5, 6, 4, 5, 72, 101, 108, 108, 111>>

	"""
	def encode(value, :octetstring) do
		<< asn1_type(:octetstring) >> <> encode_field_size(value) <> value
	end

	def encode(_ignored, :null), do: << asn1_type(:null) >> <> << byte_size(<<>>) >>

	def encode(value, :integer32) when abs(value) >= 0xFFFFFF do
		format_tlv(:integer32, << value::signed-32 >>)
	end
	def encode(value, :integer32) when abs(value) >= 0xFFFF do
		format_tlv(:integer32, << value::signed-24 >>)
	end
	def encode(value, :integer32) when abs(value) >= 0xFF do
		format_tlv(:integer32, << value::signed-16 >>)
	end
	def encode(value, :integer32) do
		format_tlv(:integer32, << value::signed >>)
	end

	def encode(value, :counter32) when abs(value) <= 0xFFFFFFFF and abs(value) > 0xFFFFFF do
		format_tlv(:counter32, << value::integer-32 >>)
	end
	def encode(value, :counter32) when abs(value) <= 0xFFFFFF and abs(value) > 0xFFFF do
		format_tlv(:counter32, << value::integer-24 >>)
	end
	def encode(value, :counter32) when abs(value) <= 0xFFFF and abs(value) > 0xFF do
		format_tlv(:counter32, << value::integer-16 >>)
	end
	def encode(value, :counter32) do
		format_tlv(:counter32, << value::integer >>)
	end

	def encode(value, type) when type == :gauge32 or type == :timeticks do
		encode_gauge32_or_timeticks(value, type)
	end

	def encode(value, :counter64) when abs(value) <= 0xFFFFFFFFFFFFFFFF and abs(value) > 0xFFFFFFFFFFFFFF do
		format_tlv(:counter64, << value::integer-64 >>)
	end
	def encode(value, :counter64) when abs(value) <= 0xFFFFFFFFFFFFFF and abs(value) > 0xFFFFFFFFFFFF do
		format_tlv(:counter64, << value::integer-56 >>)
	end
	def encode(value, :counter64) when abs(value) <= 0xFFFFFFFFFFFF and abs(value) > 0xFFFFFFFFFF do
		format_tlv(:counter64, << value::integer-48 >>)
	end
	def encode(value, :counter64) when abs(value) <= 0xFFFFFFFFFF and abs(value) > 0xFFFFFFFF do
		format_tlv(:counter64, << value::integer-40 >>)
	end
	def encode(value, :counter64) when abs(value) <= 0xFFFFFFFF and abs(value) > 0xFFFFFF do
		format_tlv(:counter64, << value::integer-32 >>)
	end
	def encode(value, :counter64) when abs(value) <= 0xFFFFFF and abs(value) > 0xFFFF do
		format_tlv(:counter64, << value::integer-24 >>)
	end
	def encode(value, :counter64) when abs(value) <= 0xFFFF and abs(value) > 0xFF do
		format_tlv(:counter64, << value::integer-16 >>)
	end
	def encode(value, :counter64) do
		format_tlv(:counter64, << value::integer >>)
	end

	def encode(seq, :sequence) do
		result = seq |> Enum.map(fn {value, type} -> encode(value, type) end)
		|> Enum.join
		<< asn1_type(:sequence) >> <> encode_field_size(result) <> result
	end

	def encode(ip, :ipaddr) do
		ipaddr = ip |> String.split(".")
		|> Enum.map(fn n -> String.to_integer(n) end)
		|> :binary.list_to_bin
		format_tlv(:ipaddr, ipaddr)
	end

	def encode(legacy, :opaque) do
		<< snmp_type(:opaque) >> <> encode_field_size(legacy) <> legacy
	end

	def encode(oid_string, :oid) do
		oid_nodes = oid_string |> String.strip(?.)
		|> String.split(".")
		|> Enum.map(fn nr -> String.to_integer(nr) end)
		{[a, b], oid_tail} = oid_nodes |> Enum.split(2)
		oid = oid_tail
		|> Enum.map(fn oid_node -> encode_oid_node(oid_node) end)
		|> Enum.join
		<< asn1_type(:oid) >> <> << (byte_size(oid) + 1) >> <> << a*40 + b >> <> oid
 	end
	def encode_oid_node(node) when node <= 127 do
		<< node >>
	end

	def encode_gauge32_or_timeticks(value, type) when abs(value) > 0xFFFFFFFF do
		format_tlv(type, << 255, 255, 255, 255 >>)
	end
	def encode_gauge32_or_timeticks(value, type) when abs(value) <= 0xFFFFFFFF and abs(value) > 0xFFFFFF do
		format_tlv(type, << value::integer-32 >>)
	end
	def encode_gauge32_or_timeticks(value, type) when abs(value) <= 0xFFFFFF and abs(value) > 0xFFFF do
		format_tlv(type, << value::integer-24 >>)
	end
	def encode_gauge32_or_timeticks(value, type) when abs(value) <= 0xFFFF and abs(value) > 0xFF do
		format_tlv(type, << value::integer-16 >>)
	end
	def encode_gauge32_or_timeticks(value, type) do
		format_tlv(type, << value::integer >>)
	end

	def encode_oid_node(node) do
		size = nr_of_bits(node)
		value = << (node &&& 0x7F) >>
		encode_node((node >>> 7), value, size - 7)
	end

	defp encode_node(_, current, value) when value <= 0 do
		current
	end
	defp encode_node(value, current, remaining_bits) do
		val = (value &&& 0x7F) ||| 0x80
		encode_node((val >>> 7), << val >> <> current, remaining_bits - 7)
	end

	def encode_field_size(field), do: byte_size(field) |> encode_field_size_as_binary()

	defp encode_field_size_as_binary(size) when size <= 127 do
		<< size >>
	end
	defp encode_field_size_as_binary(size) do
		size_encoded = :binary.encode_unsigned(size)
		<< byte_size(size_encoded) ||| (0x80) >> <> size_encoded
	end

	defp format_tlv(type, data) do
		<< snmp_type(type) >> <> encode_field_size(data) <> data
	end

	@doc ~S"""
	The `arg` is a binary, usually a type from the payload of a SNMP PDU. The given binary data is decoded
  and a map containing the decoded fields is returned.

	The returned map contains the 3 keys:

  * :type - the decoded ASN.1 or SNMP derived type.
  * :length - the length of the value field.
  * :value -  the decoded value.


  The value field will be a string for types such as `:ipaddr`, `:oid`,  and `:octetstring`, otherwise integers.
  The value of a decoded `:sequence` will result in a list of maps containing the decoded types in the sequence.

 ## Example

      iex> Snimple.SNMP.Types.decode(<<48, 20, 64, 4, 127, 0, 0, 1, 6, 5, 42, 3, 4, 5, 6, 4, 5, 72, 101, 108, 108, 111>>)
      %{length: 20, type: :sequence,
         value: [%{length: 4, type: :ipaddr, value: "127.0.0.1"},
         %{length: 5, type: :oid, value: ".1.2.3.4.5.6"},
         %{length: 5, type: :octetstring, value: "Hello"}]}

	"""
	def decode(<< 0x04, data::binary >>) do
		{len, data} = decoded_data_size(data)
		data = :binary.part(data, 0, len)
		to_map(:octetstring, len, data)
	end

	def decode(<< 0x05, data::binary >>) do
		{len, _} = decoded_data_size(data)
		to_map(:null, len, nil)
	end

	def decode(<< 0x06, data::binary >>) do
		{len, data} = decoded_data_size(data)
		data = :binary.part(data, 0, len)
		<< head, tail::binary >> = data
		first_byte = [ 1, head - 40 ]
		result = first_byte ++ decode_oid_node(tail) |> Enum.join(".")
		to_map(:oid, len, "." <> result)
	end

	def decode(<< 0x02, data::binary >>) do
		{len, data} = decoded_data_size(data)
		data = :binary.part(data, 0, len)
		decode_int32(data, len)
	end

	def decode(<< 0x40, data::binary >>) do
		decode_internal(data, :ipaddr, &to_ip/1)
	end

	def decode(<< 0x41, data::binary >>) do
		decode_internal(data, :counter32, &:binary.decode_unsigned/1)
	end

	def decode(<< 0x42, data::binary >>) do
		decode_internal(data, :gauge32, &:binary.decode_unsigned/1)
	end

	def decode(<< 0x43, data::binary >>) do
		decode_internal(data, :timeticks, &:binary.decode_unsigned/1)
	end

	def decode(<< 0x44, data::binary >>) do
		decode_internal(data, :opaque, &(&1))
	end

	def decode(<< 0x46, data::binary >>) do
		decode_internal(data, :counter64, &:binary.decode_unsigned/1)
	end

	def decode(<< 0x30, data::binary >>) do
		{len, data} = decoded_data_size(data)
		data = :binary.part(data, 0, len)
		sequence_list = decode_sequence_data([], data)
		to_map(:sequence, len, sequence_list)
	end

	defp decode_sequence_data(list, <<>>) do
		list
	end
	defp decode_sequence_data(list, data) do
		result = decode(data)
		pattern = decode_as_binary_only(data)
		case pattern do
			<<>> -> data = pattern
			_    -> data = :binary.split(data, pattern, [:global]) |> List.last
		end
		list = List.insert_at(list, -1, result)
		decode_sequence_data(list, data)
	end

	defp decode_internal(data, type, decode_func) do
		{len, data} = decoded_data_size(data)
		data = :binary.part(data, 0, len)
		to_map(type, len, decode_func.(data))
	end

	def decode_oid_node(bin) do
		list = :binary.bin_to_list(bin)
		decode_node(0, list, [])
	end

	defp decode_node(_register, [], target) do
		target
	end
	defp decode_node(register, [head|tail], target) when head <= 127 do
		register = register + head
		decode_node(0, tail, target ++ [register])
	end
	defp decode_node(register, [head|tail], target) do
		register = register + (head &&& 0x7F)
		decode_node((register <<< 7), tail, target)
	end

	defp decode_int32(<< value::signed >>, 1) do
		to_map(:integer32, 1, value)
	end
	defp decode_int32(<< value::signed-16 >>, 2)  do
		to_map(:integer32, 2, value)
	end
	defp decode_int32(<< value::signed-24 >>, 3) do
		to_map(:integer32, 3, value)
	end
	defp decode_int32(<< value::signed-32 >>, 4)  do
		to_map(:integer32, 4, value)
	end

	defp to_map(type, len, value) do
		%{type: type,
			length: len,
			value: value
		 }
	end

	def decode_as_binary_only(<<_::binary-size(1), data::binary >>) do
		{len, data} = decoded_data_size(data)
		:binary.part(data, 0, len)
	end

	def decoded_data_size(<< 0::size(1), shortform_size_data::size(7), data::binary >>) do
		{shortform_size_data, data}
	end
	def decoded_data_size(<< 1::size(1), longform_size::size(7), size_data::binary-size(longform_size), data::binary >>) do
		{:binary.decode_unsigned(size_data), data}
	end

	defp to_ip(binary) do
		binary |> :binary.bin_to_list |> Enum.join(".")
	end

	defp nr_of_bits(value) do
		:erlang.trunc(:math.log2(value)) + 1
	end
end
