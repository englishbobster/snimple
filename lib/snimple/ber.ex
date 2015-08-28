defmodule Snimple.BER do

	import Bitwise, only: [&&&: 2, |||: 2, >>>: 2]

	def type_identifier do
		%{
			int32:       << 0x02 >>,
		  octetstring: << 0x04 >>,
		  null:        << 0x05 >>,
		  oid:         << 0x06 >>
		 }
	end
		
	def ber(:int32, value) when is_integer(value) do
		value_as_bin = :binary.encode_unsigned(value)
		Dict.get(type_identifier, :int32) <>
	  << byte_size(value_as_bin) >> <>
		value_as_bin
	end

	def ber(:octetstring, value) when is_binary(value) do
		Dict.get(type_identifier, :octetstring) <>
	  << byte_size(value) >> <>
		value
	end

	def ber(:null) do
		Dict.get(type_identifier, :null) <> << 0 >>
	end

	def ber(:oid, oid_string) do
		oid_nodes = oid_string |> String.strip(?.)
		|> String.split(".") |> Enum.map(fn nr -> String.to_integer(nr) end)
		{[a, b], oid_tail} = oid_nodes |> Enum.split(2)
		oid = oid_tail |> Enum.map(fn oid_node -> encode_oid_node(oid_node) end) |> Enum.join
		Dict.get(type_identifier, :oid) <> << (byte_size(oid) + 1) >> <> << a*40 + b >> <> oid
 	end

	def encode_oid_node(node) when node <= 127 do
		<<node>>
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

	def nr_of_bits(value) do
		:erlang.trunc(:math.log2(value)) + 1
	end

end


