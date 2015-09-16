defmodule Snimple.BER do
	use Bitwise

	defp type_identifier do
		%{
			int32:       0x02,
		  octetstring: 0x04,
		  null:        0x05,
		  oid:         0x06,
			sequence:    0x30,
			ipaddr:      0x40,
			counter32:   0x41,
			gauge32:     0x42,
			timeticks:   0x43,
			opaque:      0x44,
			counter64:   0x46
		 }
	end
	defp type(id) when is_atom(id) do
		Dict.get(type_identifier, id)
	end

	def ber_decode(<< 0x30, len::integer, data::binary-size(len) >>) do
		data
	end
	def ber_decode(<< 0x02, len::integer, data::binary-size(len) >>) do
		:binary.decode_unsigned(data)
	end
	def ber_decode(<< 0x04, len::integer, data::binary-size(len) >>) do
		data
	end
	def ber_decode(<< 0x05, len::integer, data::binary-size(len) >>) do
		:null
	end
	def ber_decode(<< 0x06, len::integer, data::binary-size(len) >>) do
		<< head, tail::binary >> = data
		first_byte = [1, head - 40 ]
		result = first_byte ++ decode_oid_node(tail) |> Enum.join(".")
		"." <> result
	end
	def decode_oid_node(bin) do
		list = :binary.bin_to_list(bin)
		_decode(0, list, [])
	end
	defp _decode(register, [], target) do
		target
	end
	defp _decode(register, [head|tail], target) when head <= 127 do
		register = register + head
		_decode(0, tail, target ++ [register])
	end
	defp _decode(register, [head|tail], target) do
		register = register + Bitwise.&&&(head, 0x7F)
		_decode(Bitwise.<<<(register, 7), tail, target)
	end

	def ber_encode(seq, :sequence) when is_binary(seq) do
		<< type(:sequence) >> <> << byte_size(seq) >> <> seq
	end
	def ber_encode(value, :int32) when is_integer(value) do
		value_as_bin = :binary.encode_unsigned(value)
		<< type(:int32) >> <>
	  << byte_size(value_as_bin) >> <>
		value_as_bin
	end
	def ber_encode(value, :octetstring) when is_binary(value) do
		<< type(:octetstring) >> <> << byte_size(value) >> <> value
	end
	def ber_encode(oid_string, :oid) do
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
	def ber_encode(:null) do
		<< type(:null) >> <> << byte_size(<<>>) >>
	end
	def encode_oid_node(node) when node <= 127 do
		<< node >>
	end
	def encode_oid_node(node) do
		size = nr_of_bits(node)
		value = << Bitwise.&&&(node, 0x7F) >>
		_encode(Bitwise.>>>(node, 7), value, size - 7)
	end
	defp _encode(_, current, value) when value <= 0 do
		current
	end
	defp _encode(value, current, remaining_bits) do
		val = Bitwise.&&&(value, 0x7F) |> Bitwise.|||(0x80)
		_encode(Bitwise.>>>(val, 7), << val >> <> current, remaining_bits - 7)
	end

	def ber_encode(ip, :ipaddr) do
		ipaddr = ip |> String.split(".")
		|> Enum.map(fn n -> String.to_integer(n) end)
		|> :binary.list_to_bin
		<< type(:ipaddr) >> <> << 4 >> <> ipaddr
	end

	def ber_encode(counter, :counter32) do
		
	end

	def nr_of_bits(value) do
		:erlang.trunc(:math.log2(value)) + 1
	end

end
