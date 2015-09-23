defmodule Snimple.SNMP.Types do
	alias Snimple.ASN1.Types, as: ASN1

	use Bitwise

	@int32max  (4294967295)
	@int32mask (0xFFFFFFFF)
	@int64mask (0xFFFFFFFFFFFFFFFF)
	@int64max  (18446744073709551615)

	defp snmp_type_identifier do
		%{
			integer32:   0x02, #same as ASN1 integer type
			ipaddr:      0x40,
			counter32:   0x41,
			unsigned32:  0x42,
			gauge32:     0x42, #indistinguishable from unsigned32
			timeticks:   0x43,
			opaque:      0x44,
			counter64:   0x46
		 }
	end
	defp snmp_type(id) when is_atom(id) do
		Dict.get(snmp_type_identifier, id)
	end

	def encode(value, :integer32) do
		encode_integer_type(value, @int32mask, :integer32)
	end

	def encode(ip, :ipaddr) do
		ipaddr = ip |> String.split(".")
		|> Enum.map(fn n -> String.to_integer(n) end)
		|> :binary.list_to_bin
		<< snmp_type(:ipaddr) >> <> << 4 >> <> ipaddr
	end

	def encode(value, :counter32) do
		encode_integer_type(value, @int32mask, :counter32)
	end

	def encode(value, :unsigned32) when value <= @int32max do
		encode_integer_type(value, @int32mask, :unsigned32)
	end
	def encode(_value, :unsigned32) do
		encode_integer_type(@int32max, @int32mask, :unsigned32)
	end

	def encode(value, :gauge32) do
		encode(value, :unsigned32)
	end
	
	def encode(ticks, :timeticks) do
	end

	def encode(value, :counter64) do
		encode_integer_type(value, @int64mask, :counter64)
	end

	def decode(<< data::binary >>) do
	end

	def encode_integer_type(value, mask, t) when is_atom(t) do
		value_as_bin = Bitwise.&&&(value, mask) |> :binary.encode_unsigned
		<< snmp_type(t) >> <> ASN1.encoded_data_size(value_as_bin) <> value_as_bin
	end

end
