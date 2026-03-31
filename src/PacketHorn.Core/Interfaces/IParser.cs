using PacketHorn.Core.Models;

namespace PacketHorn.Core.Interfaces;

public interface IParser
{
    bool TryParse(RawPacket rawPacket, out StructuredPacket structuredPacket);
}
