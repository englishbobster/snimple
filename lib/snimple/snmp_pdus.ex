defmodule Snimple.SnmpPdus do
	import Snimple.BER

	def pdu_identifier do
		%{
			snmpget:         << 0x00 >>,
			snmpgetnext:     << 0x01 >>,
			snmpresponse:    << 0x02 >>,
			snmpset:         << 0x03 >>,
			snmptrap:        << 0x04 >>
		 }
	end
	def pdu_id(id) do
		Dict.get(pdu_identifier, id)
	end
	
	def error_status do
		%{
			noError:              <<0x00>>,
			tooBig:               <<0x01>>,
			noSuchName:           <<0x02>>,
			badValue:             <<0x03>>,
			readOnly:             <<0x04>>,
			genErr:               <<0x05>>,
			noAccess:             <<0x06>>,
			wrongType:            <<0x07>>,
			wrongLength:          <<0x08>>,
			wrongEncoding:        <<0x09>>,
			wrongValue:           <<0x0A>>,
			noCreation:           <<0x0B>>,
			inconsistentValue:    <<0x0C>>,
			resourceUnavailable:  <<0x0D>>,
			commitFailed:         <<0x0E>>,
			undoFailed:           <<0x0F>>,
			authorizationError:   <<0x10>>,
			notWritable:          <<0x11>>,
			inconsistentName:     <<0x12>>
		}
	end
	def error(status) do
		Dict.get(error_status, status)
	end
		
	def encode_pdu(vblist, requid, :snmpget) do
	_encode_pdu(vblist, requid, 0, 0, :snmpget)
	end
	def encode_pdu(vblist, requid, error_status, error_index, :snmpresponse) do
		_encode_pdu(vblist, requid, error_status, error_index, :snmpresponse)
	end
	def encode_pdu(vblist, requid, :snmpgetnext)do
		_encode_pdu(vblist, requid, 0, 0, :snmpgetnext)
	end
	def encode_pdu(vblist, requid, :snmpset)do
		_encode_pdu(vblist, requid, 0, 0, :snmpset)
	end
	defp _encode_pdu(vblist, requid, errst, errin, type) do
		body = request_id(requid)
		<> error_status(errst)
		<> error_index(errin)
		<> var_bind_list(vblist)
		pdu_id(type) <> << byte_size(body) >>  <> body
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
