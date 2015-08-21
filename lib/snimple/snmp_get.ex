defmodule Snimple.SNMPGet do
	def make_snmp_get() do
		<<11>>
	end

	def ber(:int32, value) when is_integer(value) do
		as_bin = << value::size(32) >>
		sig = signify(as_bin)
		<< 2 >> <> << byte_size(sig) >> <> sig
	end

	def signify(value) when is_binary(value) do
		_signify(value)
	end
	defp _signify(<< 0, 0, 0, x::binary >>) do
		x
	end
	defp _signify(<< 0, 0, x::binary >>) do
		x
	end
	defp _signify(<< 0, x::binary >>) do
		x
	end
	defp _signify(<< x::binary >>) do
		x
	end
	
end
