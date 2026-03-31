using PacketHorn.Core.Models;

namespace PacketHorn.Processing.Parsers;

/// <summary>
/// Parses TCP (Layer 4) headers from raw packets.
/// </summary>
public class TCPParser
{
    /// <summary>
    /// Try to parse a TCP header from a raw packet.
    /// Requires that IP header has already been parsed.
    /// </summary>
    public bool TryParse(RawPacket rawPacket, out (int SrcPort, int DstPort, byte Flags)? result)
    {
        result = null;

        if (rawPacket.Data.Length < 34) // Minimum: 14 (ETH) + 20 (IP) + 20 (TCP)
            return false;

        try
        {
            // Get IP header length from the data (first byte of IPv4 header after Ethernet)
            byte versionAndIHL = rawPacket.Data[14];
            int ipHeaderLength = (versionAndIHL & 0x0F) * 4;
            int tcpStart = 14 + ipHeaderLength; // 14 bytes for Ethernet header

            if (rawPacket.Data.Length < tcpStart + 20)
                return false;

            var data = rawPacket.Data;
            
            // Extract source port (bytes 0-1 of TCP header)
            int srcPort = (data[tcpStart] << 8) | data[tcpStart + 1];
            
            // Extract destination port (bytes 2-3 of TCP header)
            int dstPort = (data[tcpStart + 2] << 8) | data[tcpStart + 3];
            
            // Extract flags (byte 13 of TCP header - lower 6 bits)
            byte flags = (byte)(data[tcpStart + 13] & 0x3F);

            result = (srcPort, dstPort, flags);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
