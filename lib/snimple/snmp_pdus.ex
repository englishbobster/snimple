defmodule Snimple.SnmpPdus do
	import Snimple.BER
	
	def make_snmp_get() do
		<< 11 >>
	end

	def var_bind(value, oid) do
		ber_encode(oid, :oid) <> value |> ber_encode(:sequence)
	end

	def var_bind_list(map_oids_to_values) do
		map_oids_to_values
	end
		
end
