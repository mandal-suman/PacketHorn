using PacketHorn.Core.Models;

namespace PacketHorn.Processing.Parsers;

public class TCPParser
{
    public bool TryParse(RawPacket rawPacket, out (int SrcPort, int DstPort, byte Flags)? result)
    {
        result = null;

        if (rawPacket.Data.Length < 34)
            return false;

        try
        {
            byte versionAndIHL = rawPacket.Data[14];
            int ipHeaderLength = (versionAndIHL & 0x0F) * 4;
            int tcpStart = 14 + ipHeaderLength;

            if (rawPacket.Data.Length < tcpStart + 20)
                return false;

            var data = rawPacket.Data;

            int srcPort = (data[tcpStart] << 8) | data[tcpStart + 1];
            int dstPort = (data[tcpStart + 2] << 8) | data[tcpStart + 3];
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
