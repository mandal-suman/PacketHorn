using PacketHorn.Core.Models;

namespace PacketHorn.Core.Interfaces;

public interface IStructuredPacketBuilder
{
    StructuredPacket? Build(RawPacket rawPacket);
}
