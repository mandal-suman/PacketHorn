using PacketHorn.Core.Models;

namespace PacketHorn.Core.Interfaces;

public interface IRuleEngine
{
    List<DetectionMatch> EvaluatePacket(StructuredPacket packet);
}
