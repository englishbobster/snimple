defmodule Snimple.SnmpPdus do
	import Snimple.BER

	def pdu_identifier do
		%{
			snmpget:     << 0xA0 >>
		 }
	end

	def encode_pdu(vblist, reqid, :snmpget) do
		<< 11 >>
	end

	def var_bind(value, oid) do
		ber_encode(oid, :oid) <> value |> ber_encode(:sequence)
	end

	def var_bind_list(tuple_list) do
		tuple_list
		|> Enum.map(fn {oid, value} -> var_bind(value, oid) end)
		|> Enum.join
		|> ber_encode(:sequence)
	end

end
