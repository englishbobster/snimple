defmodule SNMPGetTest do
	use ExUnit.Case

	import Snimple.SNMPGet

	def example_message do
		{:ok, pkt} = Base.decode16("303102010104067075626c6963a02402047f71fce70201000201003016301406102b06010401c40402030204010104817d0500", [case: :lower])
		pkt
	end
	
	test "should be able to construct an snmp get message" do
		assert make_snmp_get() == example_message
	end
	
end
