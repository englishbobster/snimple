defmodule Snimple.BER do
	
	def ber(:int32, value) when is_integer(value) do
		value_as_bin = :erlang.encode_unsigned(value)
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
		node_as_bin = :erlang.encode_unsigned(node)
		current_size = byte_size(node_as_bin)
		current = Bitmask.&&&(node_as_bin, 0x7F)
		_encode(Bitmask.>>>(node_as_bin, 7), current, current_size - 1)
	end
	defp _encode(bin, current, remaining_bytes) do

	end
	defp _encode(_, current,  0) do
		current
	end
end
