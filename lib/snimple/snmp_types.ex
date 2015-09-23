defmodule Snimple.SNMP.Types do
	alias Snimple.ASN1.Types, as: ASN1

	use Bitwise

	@int32max  (4294967295)
	@int32mask (0xFFFFFFFF)
	@int64mask (0xFFFFFFFFFFFFFFFF)
	@int64max  (18446744073709551615)
	
	defp asn1_type_integer, do: ASN1.type(:integer)
	defp snmp_type_identifier do
		%{
			integer32:   asn1_type_integer,
			ipaddr:      0x40,
			counter32:   0x41,
			unsigned32:  0x42,
			gauge32:     snmp_type(:unsigned32),
			timeticks:   0x43,
			opaque:      0x44,
			counter64:   0x46
		 }
	end
	defp snmp_type(id) when is_atom(id) do
		Dict.get(snmp_type_identifier, id)
	end
	
	def encode(value, :integer32) do
	end

	def encode(ipaddress, :ipaddr) do
	end

	def encode(value, :counter32) do
	end

	def encode(value, :gauge32) do
	end

	def encode(ticks, :timeticks) do
	end
	
	def encode(value, :counter64) do
	end

	def decode(<< data::binary >>) do
	end

	def encode_integer_type(value, mask, t) when is_atom(t) do
		value_as_bin = Bitwise.&&&(value, mask) |> :binary.encode_unsigned
		<< snmp_type(t) >> <> ASN1.encoded_data_size(value_as_bin) <> value_as_bin
	end

end
