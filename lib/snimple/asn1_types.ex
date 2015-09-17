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

	def ber_encode(value, :integer) do
		ber_encode_integer_type(value, value, :integer)
	end
		
	def ber_decode(<< 0x02, len::integer, data::binary-size(len) >>) do
		%{ type: :integer,
			 length: len,
			 value: :binary.decode_unsigned(data)
		 }
	end

	def ber_encode_integer_type(value, mask, t) when is_atom(t) do
		value_as_bin = Bitwise.&&&(value, mask) |> :binary.encode_unsigned
		<< type(t) >> <>
	  << byte_size(value_as_bin) >> <>
		value_as_bin
	end

	def data_size(data) do
		size = byte_size(data)
		cond do
			size <= 127
				-> << size >>
			true
				->  encoded_size = :binary.encode_unsigned(size)
			      << byte_size(encoded_size) |> Bitwise.|||(0x80)>> <> encoded_size
		end
	end
		
end
