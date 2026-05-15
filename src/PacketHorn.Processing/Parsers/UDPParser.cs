using PacketHorn.Core.Models;

namespace PacketHorn.Processing.Parsers;

public class UDPParser
{
    public bool TryParse(RawPacket rawPacket, out (int SrcPort, int DstPort, int Length)? result)
    {
        result = null;

        if (rawPacket.Data.Length < 28)
            return false;

        try
        {
            byte versionAndIHL = rawPacket.Data[14];
            int ipHeaderLength = (versionAndIHL & 0x0F) * 4;
            int udpStart = 14 + ipHeaderLength;

            if (rawPacket.Data.Length < udpStart + 8)
                return false;

            var data = rawPacket.Data;

            int srcPort = (data[udpStart] << 8) | data[udpStart + 1];
            int dstPort = (data[udpStart + 2] << 8) | data[udpStart + 3];
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
