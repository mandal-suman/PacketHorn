using PacketHorn.Core.Models;
using PacketHorn.Core.Enums;

namespace PacketHorn.Processing.Parsers;

public class IPParser
{
    private const int EthernetHeaderLength = 14;

    public bool TryParse(RawPacket rawPacket, out StructuredPacket? result)
    {
        result = null;

        if (rawPacket.Data.Length < EthernetHeaderLength + 20)
            return false;

        try
        {
            var data = rawPacket.Data;
            var ipOffset = EthernetHeaderLength;

            byte versionAndIHL = data[ipOffset];
            int version = (versionAndIHL >> 4) & 0x0F;

            if (version != 4)
                return false;

            int headerLength = (versionAndIHL & 0x0F) * 4;

            if (data.Length < ipOffset + headerLength)
                return false;

            byte protocolByte = data[ipOffset + 9];
            Protocol protocol = protocolByte switch
            {
                6 => Protocol.TCP,
                17 => Protocol.UDP,
                1 => Protocol.ICMP,
                _ => Protocol.Other
            };

            int totalLength = (data[ipOffset + 2] << 8) | data[ipOffset + 3];

            string srcIP = $"{data[ipOffset + 12]}.{data[ipOffset + 13]}.{data[ipOffset + 14]}.{data[ipOffset + 15]}";
            string dstIP = $"{data[ipOffset + 16]}.{data[ipOffset + 17]}.{data[ipOffset + 18]}.{data[ipOffset + 19]}";

            var packet = new StructuredPacket
            {
                Timestamp = rawPacket.Timestamp,
                SrcIP = srcIP,
                DstIP = dstIP,
                Protocol = protocol,
                SrcPort = 0,
                DstPort = 0,
                Flags = "",
                PacketSize = rawPacket.Length
            };

            result = packet;
            return true;
        }
        catch
        {
            return false;
        }
    }
}
