using System;
using PacketHorn.Core.Models;
using PacketHorn.Core.Enums;
using PacketHorn.Processing.Parsers;
using PacketHorn.Processing.Extractors;

using PacketHorn.Core.Interfaces;

namespace PacketHorn.Processing.Builders;

public class StructuredPacketBuilder : IStructuredPacketBuilder
{
    private readonly EthernetParser _ethParser = new();
    private readonly IPParser _ipParser = new();
    private readonly TCPParser _tcpParser = new();
    private readonly UDPParser _udpParser = new();
    private readonly FeatureExtractor _extractor = new();

    public StructuredPacket? Build(RawPacket rawPacket)
    {
        if (!_ethParser.TryParse(rawPacket, out _))
            return null;

        if (!_ipParser.TryParse(rawPacket, out var packet))
            return null;

        if (packet != null)
        {
            if (packet.Protocol == PacketHorn.Core.Enums.Protocol.TCP)
            {
                if (_tcpParser.TryParse(rawPacket, out var tcpDetails))
                {
                    packet.SrcPort = tcpDetails?.SrcPort ?? 0;
                    packet.DstPort = tcpDetails?.DstPort ?? 0;
                    packet.Flags = FormatTcpFlags(tcpDetails?.Flags ?? 0);
                }
            }
            else if (packet.Protocol == PacketHorn.Core.Enums.Protocol.UDP)
            {
                if (_udpParser.TryParse(rawPacket, out var udpDetails))
                {
                    packet.SrcPort = udpDetails?.SrcPort ?? 0;
                    packet.DstPort = udpDetails?.DstPort ?? 0;
                }
            }

            packet.Timestamp = rawPacket.Timestamp;
            _extractor.ExtractFeatures(packet);
        }

        return packet;
    }

    private static string FormatTcpFlags(byte flags)
    {
        var names = new List<string>();
        if ((flags & 0x01) != 0) names.Add("FIN");
        if ((flags & 0x02) != 0) names.Add("SYN");
        if ((flags & 0x04) != 0) names.Add("RST");
        if ((flags & 0x08) != 0) names.Add("PSH");
        if ((flags & 0x10) != 0) names.Add("ACK");
        if ((flags & 0x20) != 0) names.Add("URG");
        return names.Count == 0 ? "NONE" : string.Join("|", names);
    }
}
