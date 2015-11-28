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

  def decode_v2c_header(<<02, 01, 01, community::binary>>) do
    {:ok, %{version: "v2c",
            community: SNMP.decode(community)}}
  end
  def decode_v2c_header(_version) do
   {:error, "Unrecognised snmp version"}
  end

end
