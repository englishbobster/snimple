defmodule Snimple.SNMP.Types do
	use Bitwise

	@int32max  (4294967295)
	@int32mask (0xFFFFFFFF)
	@int64mask (0xFFFFFFFFFFFFFFFF)
	@int64max  (18446744073709551615)

	@moduledoc """
	This SNMP imlementation should be compatible with SNMPv1 and SNMPv2c.
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
	Lists the supported ASN.1 types used by SNMP.

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
	Lists the supported SNMP derived types used by SNMP.

 ## Example
      iex> Snimple.SNMP.Types.list_snmp_types
      [:counter32, :counter64, :gauge32, :integer32, :ipaddr, :opaque, :timeticks]

	"""
	def list_snmp_types do
		Dict.keys(snmp_type_identifier)
	end

	@doc ~S"""
	Lists all the supported SNMP types, both derived and ASN.1.

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
  * `:integer32`, `:counter32`, `:gauge32`, `:timeticks`, `:counter64` -> `value` shall be an integer.
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
		<< asn1_type(:octetstring) >> <> encoded_data_size(value) <> value
	end

	def encode(_, :null), do: << asn1_type(:null) >> <> << byte_size(<<>>) >>

	def encode(seq, :sequence) do
		result = seq |> Enum.map(fn {value, type} -> encode(value, type) end)
		|> Enum.join
		<< asn1_type(:sequence) >> <> encoded_data_size(result) <> result
	end

	def encode(ip, :ipaddr) do
		ipaddr = ip |> String.split(".")
		|> Enum.map(fn n -> String.to_integer(n) end)
		|> :binary.list_to_bin
		<< snmp_type(:ipaddr) >> <> << 4 >> <> ipaddr
	end

	def encode(value, :integer32) do
		_encode_integer_type(value, @int32mask, :integer32)
	end

	def encode(value, :counter32) do
		_encode_integer_type(value, @int32mask, :counter32)
	end

	def encode(value, :gauge32) when value <= @int32max do
		_encode_integer_type(value, @int32mask, :gauge32)
	end
	def encode(_value, :gauge32) do
		_encode_integer_type(@int32max, @int32mask, :gauge32)
	end

	def encode(centisecs, :timeticks) when centisecs <= @int32max do
		_encode_integer_type(centisecs, @int32mask, :timeticks)
	end
	def encode(_centisecs, :timeticks) do
		_encode_integer_type(@int32max, @int32mask, :timeticks)
	end

	def encode(value, :counter64) do
		_encode_integer_type(value, @int64mask, :counter64)
	end

	def encode(legacy, :opaque) do
		<< snmp_type(:opaque) >> <> encoded_data_size(legacy) <> legacy
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
	def encode_oid_node(node) do
		size = nr_of_bits(node)
		value = << Bitwise.&&&(node, 0x7F) >>
		_encode_node(Bitwise.>>>(node, 7), value, size - 7)
	end
	defp _encode_node(_, current, value) when value <= 0 do
		current
	end
	defp _encode_node(value, current, remaining_bits) do
		val = Bitwise.&&&(value, 0x7F) |> Bitwise.|||(0x80)
		_encode_node(Bitwise.>>>(val, 7), << val >> <> current, remaining_bits - 7)
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
		%{type: :octetstring,
			length: len,
			value: data
			}
	end

	def decode(<< 0x05, data::binary >>) do
		{len, _} = decoded_data_size(data)
		%{type: :null,
			length: len,
			value: nil
		 }
	end

	def decode(<< 0x06, data::binary >>) do
		{len, data} = decoded_data_size(data)
		data = :binary.part(data, 0, len)
		<< head, tail::binary >> = data
		first_byte = [ 1, head - 40 ]
		result = first_byte ++ decode_oid_node(tail) |> Enum.join(".")
		%{type: :oid,
			length: len,
			value: "." <> result
			}
	end
	def decode_oid_node(bin) do
		list = :binary.bin_to_list(bin)
		_decode_node(0, list, [])
	end
	defp _decode_node(_register, [], target) do
		target
	end
	defp _decode_node(register, [head|tail], target) when head <= 127 do
		register = register + head
		_decode_node(0, tail, target ++ [register])
	end
	defp _decode_node(register, [head|tail], target) do
		register = register + Bitwise.&&&(head, 0x7F)
		_decode_node(Bitwise.<<<(register, 7), tail, target)
	end

	def decode(<< 0x02, data::binary >>) do
		_decode_internal(data, :integer32, &:binary.decode_unsigned/1)
	end

	def decode(<< 0x40, data::binary >>) do
		_decode_internal(data, :ipaddr, &_data_to_ip/1)
	end
	defp _data_to_ip(data) do
		data |> :binary.bin_to_list |> Enum.join(".")
	end

	def decode(<< 0x41, data::binary >>) do
		_decode_internal(data, :counter32, &:binary.decode_unsigned/1)
	end

	def decode(<< 0x42, data::binary >>) do
		_decode_internal(data, :gauge32, &:binary.decode_unsigned/1)
	end

	def decode(<< 0x43, data::binary >>) do
		_decode_internal(data, :timeticks, &:binary.decode_unsigned/1)
	end

	def decode(<< 0x44, data::binary >>) do
		_decode_internal(data, :opaque, &(&1))
	end

	def decode(<< 0x46, data::binary >>) do
		_decode_internal(data, :counter64, &:binary.decode_unsigned/1)
	end

	def decode(<< 0x30, data::binary >>) do
		{len, data} = decoded_data_size(data)
		data = :binary.part(data, 0, len)
		sequence_list = _decode_sequence_data([], data)
		%{type: :sequence, length: len, value: sequence_list}
	end
	defp _decode_sequence_data(list, <<>>) do
		list
	end
	defp _decode_sequence_data(list, data) do
		result = decode(data)
		pattern = decode_as_binary_only(data)
		case pattern do
			<<>> -> data = pattern
			_    -> data = :binary.split(data, pattern, [:global]) |> List.last
		end
		list = List.insert_at(list, -1, result)
		_decode_sequence_data(list, data)
	end

	defp _decode_internal(data, type, decode_func) do
		{len, data} = decoded_data_size(data)
		data = :binary.part(data, 0, len)
		%{type: type,
			length: len,
			value: decode_func.(data)
			}
	end

	defp _encode_integer_type(value, mask, t) when is_atom(t) do
		value_as_bin = Bitwise.&&&(value, mask) |> :binary.encode_unsigned
		<< snmp_type(t) >> <> encoded_data_size(value_as_bin) <> value_as_bin
	end

	def decode_as_binary_only(<<_::binary-size(1), data::binary >>) do
		{len, data} = decoded_data_size(data)
		:binary.part(data, 0, len)
	end

	def encoded_data_size(data), do: byte_size(data) |> _encoded_data_size()
	defp _encoded_data_size(size) when size <= 127 do
		<< size >>
	end
	defp _encoded_data_size(size) do
		size_encoded = :binary.encode_unsigned(size)
		<< byte_size(size_encoded) |> Bitwise.|||(0x80) >> <> size_encoded
	end

	def decoded_data_size(<< 0::size(1), shortform_size_data::size(7), data::binary >>) do
		{shortform_size_data, data}
	end
	def decoded_data_size(<< 1::size(1), longform_size::size(7), size_data::binary-size(longform_size), data::binary >>) do
		{:binary.decode_unsigned(size_data), data}
	end

	defp nr_of_bits(value) do
		:erlang.trunc(:math.log2(value)) + 1
	end

end
