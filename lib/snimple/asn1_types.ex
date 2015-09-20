defmodule Snimple.ASN1.Types do
	use Bitwise
	
	defp type_identifier do
		%{
			integer:     0x02,
		  octetstring: 0x04,
		  null:        0x05,
		  oid:         0x06,
			sequence:    0x30,
		}
	end
	defp type(id) when is_atom(id) do
		Dict.get(type_identifier, id)
	end

	def encode(value, :integer) do
		encode_integer_type(value, value, :integer)
	end

	def encode(value, :octetstring) do
		<< type(:octetstring) >> <> encoded_data_size(value) <> value
	end
	
	def encode(_, :null), do: << type(:null) >> <> << 0 >>

	def encode(seq, :sequence) do
		result = seq |> Enum.map(fn {value, type} -> encode(value, type) end)
		|> Enum.join
		<< type(:sequence) >> <> encoded_data_size(result) <> result
	end
	
	def encode(oid_string, :oid) do
		oid_nodes = oid_string |> String.strip(?.)
		|> String.split(".")
		|> Enum.map(fn nr -> String.to_integer(nr) end)
		{[a, b], oid_tail} = oid_nodes
		|> Enum.split(2)
		oid = oid_tail
		|> Enum.map(fn oid_node -> encode_oid_node(oid_node) end)
		|> Enum.join
		<< type(:oid) >> <> << (byte_size(oid) + 1) >> <> << a*40 + b >> <> oid
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

	def decode(<< 0x02, data::binary >>) do
		{len, data} = decoded_data_size(data)
		data = :binary.part(data, 0, len)
		%{ type: :integer,
			 length: len,
			 value: :binary.decode_unsigned(data)
		 }
	end

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
			_    -> data = :binary.split(data, pattern) |> List.last
		end
		list = List.insert_at(list, -1, result)
		_decode_sequence_data(list, data)
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

	def decode_as_binary_only(<<_::binary-size(1), data::binary >>) do
		{len, data} = decoded_data_size(data)
		:binary.part(data, 0, len)
	end
		
	def encode_integer_type(value, mask, t) when is_atom(t) do
		value_as_bin = Bitwise.&&&(value, mask) |> :binary.encode_unsigned
		<< type(t) >> <> encoded_data_size(value_as_bin) <> value_as_bin
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
