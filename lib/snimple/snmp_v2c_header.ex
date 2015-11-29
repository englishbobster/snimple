defmodule Snimple.SNMP.Header do
  alias Snimple.SNMP.Types, as: SNMP

  defp version_v2c do
    SNMP.encode(1, :integer32)
  end

  defp community_string(community) do
    SNMP.encode(community, :octetstring)
  end

  def encode_v2c_header(community) do
    version_v2c <> community_string(community)
  end

  def decode_v2c_header(<<2, 1, 1, community::binary>>) do
    %{version: "v2c",
      community: SNMP.decode(community).value
     }
  end
  def decode_v2c_header(_version) do
   raise ArgumentError, "SNMP version not supported"
  end

end
