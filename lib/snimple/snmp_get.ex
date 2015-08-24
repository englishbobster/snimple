defmodule Snimple.SNMPGet do

	def make_snmp_get() do
		<<11>>
	end

	def ber(:int32, value) when is_integer(value) do
		as_bin = << value::size(32) >>
		sig = strip_zero_bytes(as_bin)
		<< 2 >> <> << byte_size(sig) >> <> sig
	end

	def ber(:octetstring, value) when is_binary(value) do
		<< 4 >> <> << byte_size(value) >> <> value
	end

	@doc """
	BER for an OId is as follows:
	1) The first two nodes of the OID are encoded onto a single byte.
	   The first node is multiplied by the decimal 40 and the result
		 is added to the value of the second node.
	2) Node values less than or equal to 127 are encoded on one byte.
	3) Node values greater than or equal to 128 are encoded on
	   multiple bytes. Bit 7 of the leftmost byte is set to one,
		 when there are more byes to come, zero otherwise.
		 Bits 0 through 6 of each byte contains the encoded value.
		 http://forcedfx.blogspot.se/2010/07/ber-encoding-snmp-oid.html
		 """
	def ber(:oid, oid_string) do
		oid_nodes = oid_string |> String.strip(?.) |> String.split(".") |> Enum.map(fn nr -> String.to_integer(nr) end)
		{[a, b], oid_tail} = oid_nodes |> Enum.split(2)
		<< 6 >> <> << byte_size <<1>>  >> <> << a*40 + b >>
	end
	def ber(:null) do
		<< 5, 0 >>
	end

	def encode_tail(oid_node) do
		cond do
			oid_node >= 128 ->
			  encode_node(oid_node)
			true ->
				<< oid_node >>
		end
	end

	def encode_node(oid_node) do
		bytes = << oid_node::size(32) >> | strip_zero_bytes
		
	end

	def strip_zero_bytes(value) when is_binary(value) do
		_strip_zero_bytes(value)
	end
	defp _strip_zero_bytes(<< 0, 0, 0, x::binary >>) do
		x
	end
	defp _strip_zero_bytes(<< 0, 0, x::binary >>) do
		x
	end
	defp _strip_zero_bytes(<< 0, x::binary >>) do
		x
	end
	defp _strip_zero_bytes(<< x::binary >>) do
		x
	end
end
