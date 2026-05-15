using System;
using System.Net;
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

    private static readonly string[] Rfc1918Ranges = { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" };

    public StructuredPacket? Build(RawPacket rawPacket)
    {
        if (!_ethParser.TryParse(rawPacket, out _))
            return null;

        if (!_ipParser.TryParse(rawPacket, out var packet))
            return null;

        if (packet != null)
        {
            int payloadOffset = 14;

            if (packet.Protocol == Protocol.TCP)
            {
                if (_tcpParser.TryParse(rawPacket, out var tcpDetails))
                {
                    packet.SrcPort = tcpDetails?.SrcPort ?? 0;
                    packet.DstPort = tcpDetails?.DstPort ?? 0;
                    packet.Flags = FormatTcpFlags(tcpDetails?.Flags ?? 0);
                }

                byte versionAndIHL = rawPacket.Data[14];
                int ipHeaderLength = (versionAndIHL & 0x0F) * 4;
                int tcpStart = 14 + ipHeaderLength;
                if (rawPacket.Data.Length > tcpStart + 12)
                {
                    int tcpDataOffset = ((rawPacket.Data[tcpStart + 12] >> 4) & 0x0F) * 4;
                    payloadOffset = tcpStart + tcpDataOffset;
                }
            }
            else if (packet.Protocol == Protocol.UDP)
            {
                if (_udpParser.TryParse(rawPacket, out var udpDetails))
                {
                    packet.SrcPort = udpDetails?.SrcPort ?? 0;
                    packet.DstPort = udpDetails?.DstPort ?? 0;
                }

                byte versionAndIHL = rawPacket.Data[14];
                int ipHeaderLength = (versionAndIHL & 0x0F) * 4;
                payloadOffset = 14 + ipHeaderLength + 8;
            }
            else
            {
                byte versionAndIHL = rawPacket.Data[14];
                int ipHeaderLength = (versionAndIHL & 0x0F) * 4;
                payloadOffset = 14 + ipHeaderLength;
            }

            if (payloadOffset < rawPacket.Data.Length)
            {
                int payloadLength = rawPacket.Data.Length - payloadOffset;
                packet.Payload = new byte[payloadLength];
                Array.Copy(rawPacket.Data, payloadOffset, packet.Payload, 0, payloadLength);
            }

            packet.Direction = InferDirection(packet.SrcIP, packet.DstIP);
            packet.Timestamp = rawPacket.Timestamp;
            _extractor.ExtractFeatures(packet);
        }

        return packet;
    }

    private static Direction InferDirection(string srcIP, string dstIP)
    {
        bool srcInternal = IsRfc1918(srcIP);
        bool dstInternal = IsRfc1918(dstIP);

        if (srcInternal && dstInternal)
            return Direction.Lateral;

        if (srcInternal && !dstInternal)
            return Direction.Outbound;

        if (!srcInternal && dstInternal)
            return Direction.Inbound;

        return Direction.Unknown;
    }

    private static bool IsRfc1918(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr))
            return false;

        var bytes = addr.GetAddressBytes();
        if (bytes.Length != 4)
            return false;

        if (bytes[0] == 10)
            return true;

        if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            return true;

        if (bytes[0] == 192 && bytes[1] == 168)
            return true;

        return false;
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
