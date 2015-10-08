defmodule Snimple.SnmpPdus do
	alias Snimple.SNMP.Types, as: SNMP

	def pdu_identifier do
		%{
			snmpget:         0xA0,
			snmpgetnext:     0xA1,
			snmpresponse:    0xA2,
			snmpset:         0xA3,
			notused:         0xA4,
			snmpgetbulk:     0xA5,
			snmpinform:      0xA6,
			snmptrap:        0xA7
		 }
	end
	def pdu_id(id) when is_atom(id) do
		pdu_identifier[id]
	end

	def list_supported_pdus do
		Dict.keys(pdu_identifier)
	end

	def error_status do
		[
			{:noError,              0x00},
			{:tooBig,               0x01},
			{:noSuchName,           0x02},
			{:badValue,             0x03},
			{:readOnly,             0x04},
			{:genErr,               0x05},
			{:noAccess,             0x06},
			{:wrongType,            0x07},
			{:wrongLength,          0x08},
			{:wrongEncoding,        0x09},
			{:wrongValue,           0x0A},
			{:noCreation,           0x0B},
			{:inconsistentValue,    0x0C},
			{:resourceUnavailable,  0x0D},
			{:commitFailed,         0x0E},
			{:undoFailed,           0x0F},
			{:authorizationError,   0x10},
			{:notWritable,          0x11},
			{:inconsistentName,     0x12}
		]
	end
	def error(status) when is_atom(status) do
		error_status[status]
	end
	def error(status) when is_integer(status) do
		{error, _} = error_status |> Enum.find(fn {_, status_code} -> status_code == status end)
		error
	end

	def list_possible_errors do
		Dict.keys(error_status)
	end

	def encode_pdu(vblist, requid, :snmpget) do
		_encode_pdu(vblist, requid, error(:noError), 0, :snmpget)
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

	def encode_pdu(vblist, requid, errst, errin, :snmpresponse) do
		_encode_pdu(vblist, requid, errst, errin, :snmpresponse)
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

  def decode_pdu(<< 0xA0, data::binary >>) do
		_decode_std_pdu(data, :snmpget)
	end

	def decode_pdu(<< 0xA1, data::binary >>) do
		_decode_std_pdu(data, :snmpgetnext)
	end

  def decode_pdu(<< 0xA2, data::binary >>) do
		_decode_std_pdu(data, :snmpresponse)
	end

	def decode_pdu(<< 0xA3, data::binary >>) do
		_decode_std_pdu(data, :snmpset)
	end

	def decode_pdu(<< 0xA5, data::binary >>) do
		_decode_non_std_pdu(data, :snmpgetbulk)
	end

  def decode_pdu(<< 0xA6, data::binary >>) do
		_decode_std_pdu(data, :snmpinform)
	end

	def decode_pdu(<< 0xA7, data::binary >>) do
		_decode_std_pdu(data, :snmptrap)
	end

	def var_bind({oid, {value, type}}) do
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

	defp _decode_std_pdu(data, type) when is_atom(type) do
		{len, data} = SNMP.decoded_data_size(data)
		{requid, data} = _chomp_field(data)
		{error_stat, data} = _chomp_error_status(data)
		{error_in, data} = _chomp_field(data)
		sequence = SNMP.decode(data)

		%{type: type,
			length: len,
			request_id: requid,
			error_status: error_stat,
			error_index: error_in,
			var_bind_list: sequence
			}
	end

	defp _chomp_field(data) do
		field_value = SNMP.decode(data)
		pattern = SNMP.decode_as_binary_only(data)
		data = :binary.split(data, pattern) |> List.last
		{field_value, data}
	end

  defp _chomp_error_status(data) do
		{field_value, data} = _chomp_field(data)
		 val = Dict.get(field_value, :value)
		{error(val), data}
	end

	defp _decode_non_std_pdu(data, type) when is_atom(type) do
		{len, data} = SNMP.decoded_data_size(data)
		{requid, data} = _chomp_field(data)
		{non_reps, data} = _chomp_field(data)
		{max_reps, data} = _chomp_field(data)
		sequence = SNMP.decode(data)
		%{type: type,
			length: len,
			request_id: requid,
			non_repeaters: non_reps,
			max_repetitions: max_reps,
			var_bind_list: sequence
			}
	end
end
