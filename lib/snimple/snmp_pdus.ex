defmodule Snimple.SnmpPdus do
	import Snimple.BER

	def pdu_identifier do
		%{
			snmpget:      << 0x00 >>,
			snmpgetnext:  << 0x01 >>,
			snmpset:      << 0x03 >>
		 }
	end

	def encode_pdu(vblist, requid, :snmpget),  do: _encode_pdu_get(vblist, requid, :snmpget)
	def encode_pdu(vblist, requid, :snmpgetnext),  do: _encode_pdu_get(vblist, requid, :snmpgetnext)
	def encode_pdu(vblist, requid, :snmpset),  do: _encode_pdu_get(vblist, requid, :snmpset)
	defp _encode_pdu_get(vblist, requid, type) do
		body = request_id(requid) <> error_status(0) <> error_index(0) <> var_bind_list(vblist)
		Dict.get(pdu_identifier, type) <> << byte_size(body) >>  <> body
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

	def request_id(id), do: ber_encode(id, :int32)
	def error_status(status), do: ber_encode(status, :int32)
	def error_index(index), do: ber_encode(index, :int32)

end
