using PacketHorn.Core.Models;

namespace PacketHorn.Processing.Parsers;

/// <summary>
/// Parses UDP (Layer 4) headers from raw packets.
/// </summary>
public class UDPParser
{
    /// <summary>
    /// Try to parse a UDP header from a raw packet.
    /// Requires that IP header has already been parsed.
    /// </summary>
    public bool TryParse(RawPacket rawPacket, out (int SrcPort, int DstPort, int Length)? result)
    {
        result = null;

        if (rawPacket.Data.Length < 28) // Minimum: 14 (ETH) + 20 (IP) + 8 (UDP)
            return false;

        try
        {
            // Get IP header length from the data
            byte versionAndIHL = rawPacket.Data[0];
            int ipHeaderLength = (versionAndIHL & 0x0F) * 4;
            int udpStart = 14 + ipHeaderLength; // 14 bytes for Ethernet header

            if (rawPacket.Data.Length < udpStart + 8)
                return false;

            var data = rawPacket.Data;
            
            // Extract source port (bytes 0-1 of UDP header)
            int srcPort = (data[udpStart] << 8) | data[udpStart + 1];
            
            // Extract destination port (bytes 2-3 of UDP header)
            int dstPort = (data[udpStart + 2] << 8) | data[udpStart + 3];
            
            // Extract length (bytes 4-5 of UDP header)
            int length = (data[udpStart + 4] << 8) | data[udpStart + 5];

            result = (srcPort, dstPort, length);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
