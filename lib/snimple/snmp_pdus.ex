defmodule Snimple.SnmpPdus do
	alias Snimple.SNMP.Types, as: SNMP

	def pdu_identifier do
		%{
			snmpget:         0xa0,
			snmpgetnext:     0xa1,
			snmpresponse:    0xa2,
			snmpset:         0xa3,
			notused:         0xa4,
			snmpgetbulk:     0xa5,
			snmpinform:      0xa6,
			snmptrap:        0xa7
		 }
	end
	def pdu_id(id) do
		Dict.get(pdu_identifier, id)
	end

	def list_supported_pdus do
		Dict.keys(pdu_identifier)
	end

	def error_status do
		%{
			noError:              0x00,
			tooBig:               0x01,
			noSuchName:           0x02,
			badValue:             0x03,
			readOnly:             0x04,
			genErr:               0x05,
			noAccess:             0x06,
			wrongType:            0x07,
			wrongLength:          0x08,
			wrongEncoding:        0x09,
			wrongValue:           0x0A,
			noCreation:           0x0B,
			inconsistentValue:    0x0C,
			resourceUnavailable:  0x0D,
			commitFailed:         0x0E,
			undoFailed:           0x0F,
			authorizationError:   0x10,
			notWritable:          0x11,
			inconsistentName:     0x12
		}
	end
	def error(status) do
		Dict.get(error_status, status)
	end

	def list_possible_errors do
		Dict.keys(error_status)
	end

	def encode_pdu(vblist, requid, :snmpget) do
		_encode_pdu(vblist, requid, error(:noError), 0, :snmpget)
	end

	def encode_pdu(vblist, requid, errst, errin, :snmpresponse) do
		_encode_pdu(vblist, requid, errst, errin, :snmpresponse)
	end

	def encode_pdu(vblist, requid, :snmpgetnext) do
		_encode_pdu(vblist, requid, error(:noError), 0, :snmpgetnext)
	end

	def encode_pdu(vblist, requid, :snmpset) do
		_encode_pdu(vblist, requid, error(:noError), 0, :snmpset)
	end

	def encode_pdu(vblist, requid, :snmptrap) do
		_encode_pdu(vblist, requid, error(:noError), 0, :snmptrap)
	end

	def encode_pdu(vblist, requid, :snmpinform) do
		_encode_pdu(vblist, requid, error(:noError), 0, :snmpinform)
	end

	def encode_pdu(vblist, requid, nonrepeat, maxreps, :snmpgetbulk) do
		body = request_id(requid)
		<> non_repeaters(nonrepeat)
		<> max_repetitions(maxreps)
		<> var_bind_list(vblist)
		<< pdu_id(:snmpgetbulk) >> <> SNMP.encoded_data_size(body) <> body
	end

  defp _encode_pdu(vblist, requid, errst, errin, type) do
		body = request_id(requid)
		<> error_status(errst)
		<> error_index(errin)
		<> var_bind_list(vblist)
		<< pdu_id(type) >> <> SNMP.encoded_data_size(body) <> body
	end

  def decode_pdu(<< 0xa0, data::binary >>) do
		{len, data} = SNMP.decoded_data_size(data)
		data = :binary.part(data, 0 , len)
		%{type: :snmpget,
			length: len,
			request_id: 0,
			error_status: 0,
			error_index: 0,
			var_bind_list: 0
			}
	end

	def decode_pdu(<< 0xa1, data::binary >>) do
	end

  def decode_pdu(<< 0xa2, data::binary >>) do
	end

	def decode_pdu(<< 0xa3, data::binary >>) do
	end

	def decode_pdu(<< 0xa5, data::binary >>) do
	end

  def decode_pdu(<< 0xa6, data::binary >>) do
	end

	def decode_pdu(<< 0xa7, data::binary >>) do
	end


	def var_bind({oid, {value, type}} = vb) do
		SNMP.encode([{oid, :oid},{value, type}], :sequence) 
	end

	def var_bind_list(vb_list) do
		vb_list
		|> Enum.map(fn {oid, {value, type}} -> {[{oid, :oid}, {value, type}],:sequence} end)
		|> SNMP.encode(:sequence)
	end

	def request_id(id), do: SNMP.encode(id, :integer32)
	def non_repeaters(nrp), do: SNMP.encode(nrp, :integer32)
	def max_repetitions(max_reps), do: SNMP.encode(max_reps, :integer32)
	def error_status(status), do: SNMP.encode(status, :integer32)
	def error_index(index), do: SNMP.encode(index, :integer32)

end
