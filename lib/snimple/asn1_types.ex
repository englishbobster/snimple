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

	def encode(value, :integer) do
		encode_integer_type(value, value, :integer)
	end

	def encode(value, :octetstring) do
		<< type(:octetstring) >> <> encoded_data_size(value) <> value
	end
	
	def encode(:null), do: << type(:null) >> <> << 0 >>

	def decode(<< 0x02, data::binary >>) do
		{len, data} = decoded_data_size(data)
		%{ type: :integer,
			 length: len,
			 value: :binary.decode_unsigned(data)
		 }
	end

	def decode(<< 0x04, data::binary >>) do
		{len, data} = decoded_data_size(data)
		%{type: :octetstring,
			length: len,
			value: data
			}
	end

	def decode(<< 0x05, data::binary >>) do
		{len, data} = decoded_data_size(data)
		%{type: :null,
			length: len,
			value: nil
		 }
	end
	
	def encode_integer_type(value, mask, t) when is_atom(t) do
		value_as_bin = Bitwise.&&&(value, mask) |> :binary.encode_unsigned
		<< type(t) >> <> encoded_data_size(value_as_bin) <> value_as_bin
	end

	def encoded_data_size(data), do: byte_size(data) |> _encoded_data_size()
	defp _encoded_data_size(size) when size <= 127 do
		<< size >>
	end
	defp _encoded_data_size(size) do
		size_encoded = :binary.encode_unsigned(size)
		<< byte_size(size_encoded) |> Bitwise.|||(0x80) >> <> size_encoded
	end

	def decoded_data_size(<< 0::size(1), shortform_size_data::size(7), data::binary >>) do
		{shortform_size_data, data}
	end
	def decoded_data_size(<< 1::size(1), longform_size::size(7), size_data::binary-size(longform_size), data::binary >>) do
		{:binary.decode_unsigned(size_data), data}
	end
	
end
