using PacketHorn.Core.Models;

namespace PacketHorn.Core.Interfaces;

public interface IResponseEngine
{
    void ProcessDecision(Decision decision, DetectionResult detectionResult);
}
