using PacketHorn.Core.Models;

namespace PacketHorn.Processing.Parsers;

/// <summary>
/// Parses Ethernet (Layer 2) frames from raw packets.
/// </summary>
public class EthernetParser
{
    private const int ETHERNET_HEADER_LENGTH = 14;
    private const int ETHERNET_TYPE_IPV4 = 0x0800;
    private const int ETHERNET_TYPE_IPV6 = 0x86DD;

    /// <summary>
    /// Try to parse an Ethernet frame from a raw packet.
    /// </summary>
    public bool TryParse(RawPacket rawPacket, out (string SrcMAC, string DstMAC)? result)
    {
        result = null;

        if (rawPacket.Data.Length < ETHERNET_HEADER_LENGTH)
            return false;

        try
        {
            // Extract destination MAC (6 bytes)
            string dstMac = FormatMAC(rawPacket.Data.AsSpan(0, 6));
            
            // Extract source MAC (6 bytes)
            string srcMac = FormatMAC(rawPacket.Data.AsSpan(6, 6));
            
            result = (srcMac, dstMac);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string FormatMAC(ReadOnlySpan<byte> data)
    {
        return string.Join(":", data.ToArray().Select(b => b.ToString("X2")));
    }
}
