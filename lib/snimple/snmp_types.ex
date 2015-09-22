defmodule Snimple.SNMP.Types do

	def encode(value, :int32) do
	end

	def encode(ipaddress, :ipaddr) do
	end

	def encode(value, :counter32) do
	end

	def encode(value, :gauge32) do
	end

	def encode(ticks, :timeticks) do
	end
	
	def encode(value, :counter64) do
	end

	def decode(<< data::binary >>) do
	end
		
end
