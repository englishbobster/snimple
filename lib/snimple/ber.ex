defmodule Snimple.BER do

	require Bitwise
	
	def ber(:int32, value) when is_integer(value) do
		value_as_bin = :binary.encode_unsigned(value)
		<< 2 >> <> << byte_size(value_as_bin) >> <> value_as_bin
	end

	def ber(:octetstring, value) when is_binary(value) do
		<< 4 >> <> << byte_size(value) >> <> value
	end

	def ber(:oid, oid_string) do
		oid_nodes = oid_string |> String.strip(?.) |> String.split(".") |> Enum.map(fn nr -> String.to_integer(nr) end)
		{[a, b], oid_tail} = oid_nodes |> Enum.split(2)
		<< 6 >> <> << byte_size <<1>>  >> <> << a*40 + b >>
	end

	def ber(:null) do
		<< 5, 0 >>
	end
	
	def encode_oid_node(node) do
		size = :binary.encode_unsigned(node) |> bit_size()
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
end
