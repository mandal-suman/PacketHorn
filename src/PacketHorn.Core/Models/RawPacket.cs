using System;

namespace PacketHorn.Core.Models;

public class RawPacket
{
    public byte[] Data { get; set; } = Array.Empty<byte>();
    public DateTime Timestamp { get; set; }
    public int Length { get; set; }
}
