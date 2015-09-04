defmodule Snimple.SnmpPdus do
	import Snimple.BER

	def pdu_identifier do
		%{
			snmpget:      << 0x00 >>,
			snmpgetnext:  << 0x01>>
		 }
	end

	def encode_pdu(vblist, reqid, :snmpget) do
		body = request_id(reqid) <> error_status(0) <> error_index(0) <> var_bind_list(vblist)
		Dict.get(pdu_identifier, :snmpget) <> << byte_size(body) >>  <> body
	end
	def encode_pdu(vblist, reqid, :snmpgetnext) do
		body = request_id(reqid) <> error_status(0) <> error_index(0) <> var_bind_list(vblist)
		Dict.get(pdu_identifier, :snmpgetnext) <> << byte_size(body) >>  <> body
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
