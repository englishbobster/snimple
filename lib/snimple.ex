defmodule Snimple do
	def get_message do
		{:ok, pkt} = Base.decode16("303102010104067075626c6963" <> "002402047f71fce70201000201003016301406102b06010401c40402030204010104817d0500", [case: :lower])
		pkt
	end

	def main() do
		{:ok, port} = Socket.UDP.open(1600)
		Socket.Datagram.send(port, get_message, {"172.21.1.5", 161})
		message = Socket.Datagram.recv(port)
		IO.inspect(message)
	end
	
end
