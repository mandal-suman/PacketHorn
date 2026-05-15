using PacketHorn.Core.Models;

namespace PacketHorn.Processing.Parsers;

public class EthernetParser
{
    private const int ETHERNET_HEADER_LENGTH = 14;

    public bool TryParse(RawPacket rawPacket, out (string SrcMAC, string DstMAC)? result)
    {
        result = null;

        if (rawPacket.Data.Length < ETHERNET_HEADER_LENGTH)
            return false;

        try
        {
            string dstMac = FormatMAC(rawPacket.Data.AsSpan(0, 6));
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
