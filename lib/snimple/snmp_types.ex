defmodule Snimple.SNMP.Types do
	alias Snimple.ASN1.Types, as: ASN1

	use Bitwise

	@int32max  (4294967295)
	@int32mask (0xFFFFFFFF)
	@int64mask (0xFFFFFFFFFFFFFFFF)
	@int64max  (18446744073709551615)

	defp snmp_type_identifier do
		%{
			integer32:   0x02, #indistinguishable from ASN1 integer,
			ipaddr:      0x40,
			counter32:   0x41,
			gauge32:     0x42,
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

	def encode(value, :gauge32) when value <= @int32max do
		encode_integer_type(value, @int32mask, :gauge32)
	end
	def encode(_value, :gauge32) do
		encode_integer_type(@int32max, @int32mask, :gauge32)
	end

	def encode(centisecs, :timeticks) when centisecs <= @int32max do
		encode_integer_type(centisecs, @int32mask, :timeticks)
	end
	def encode(_centisecs, :timeticks) do
		encode_integer_type(@int32max, @int32mask, :timeticks)
	end

	def encode(value, :counter64) do
		encode_integer_type(value, @int64mask, :counter64)
	end

	def encode(legacy, :opaque) do
		<< snmp_type(:opaque) >> <> ASN1.encoded_data_size(legacy) <> legacy
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

	defp _decode_internal(data, type, decode_func) do
		{len, data} = ASN1.decoded_data_size(data)
		data = :binary.part(data, 0, len)
		%{type: type,
			length: len,
			value: decode_func.(data)
			}
	end

	def encode_integer_type(value, mask, t) when is_atom(t) do
		value_as_bin = Bitwise.&&&(value, mask) |> :binary.encode_unsigned
		<< snmp_type(t) >> <> ASN1.encoded_data_size(value_as_bin) <> value_as_bin
	end

end
