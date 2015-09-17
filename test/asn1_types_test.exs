defmodule ASN1TypesTest do
	use ExUnit.Case

	import Snimple.ASN1.Types

	defp test_string,  do: "a test octet string"

	test "should encode size according to primitive, definite length method" do
		binary_size_small = 1..10 |> Enum.map(fn x -> x end) |> :binary.list_to_bin
		binary_size_large = 1..250 |> Enum.map(fn x -> x end) |> :binary.list_to_bin
		assert data_size(binary_size_small) == << 10 >>
		assert data_size(binary_size_large <> binary_size_large) == << 0x82, 1, 244 >>  
	end
		
	test "should be able to encode any size integer" do
		assert ber_encode(0, :integer) == << 2, 1, 0 >>
		assert ber_encode(256, :integer) == << 2, 2, 1, 0 >>
		assert ber_encode(2138176743, :integer) == << 2, 4, 127, 113, 252, 231 >>
		assert ber_encode(9595959595959595999, :integer) == <<2, 8, 133, 43, 178, 105, 52, 44, 51, 223>>
	end
	
	test "should be able to decode any size integer type" do
		assert ber_decode(<< 2, 1, 0 >>) == %{type: :integer, length: 1, value: 0}
		assert ber_decode(<< 2, 2, 1, 0 >>) == %{type: :integer, length: 2, value: 256}
		assert ber_decode(<< 2, 4, 127, 113, 252, 231 >>) == %{type: :integer, length: 4, value: 2138176743}
		assert ber_decode(<<2, 8, 133, 43, 178, 105, 52, 44, 51, 223>>) == %{type: :integer, length: 8, value: 9595959595959595999}
	end

	test "should be able to encode an octetstring" do
		test_string_size = byte_size(test_string)
		assert ber_encode(test_string, :octetstring) == << 4 >> <> << test_string_size >> <> test_string
	end

	
end
