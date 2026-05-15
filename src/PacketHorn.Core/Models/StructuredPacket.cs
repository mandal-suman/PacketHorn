using System;
using PacketHorn.Core.Enums;

namespace PacketHorn.Core.Models;

public class StructuredPacket
{
    public string SrcIP { get; set; } = string.Empty;
    public string DstIP { get; set; } = string.Empty;
    public int SrcPort { get; set; }
    public int DstPort { get; set; }
    public Protocol Protocol { get; set; }
    public Direction Direction { get; set; } = Direction.Unknown;
    public string Flags { get; set; } = string.Empty;
    public int PacketSize { get; set; }
    public DateTime Timestamp { get; set; }
    public byte[] Payload { get; set; } = Array.Empty<byte>();
}
