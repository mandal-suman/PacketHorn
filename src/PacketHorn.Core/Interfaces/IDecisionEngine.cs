using PacketHorn.Core.Enums;
using PacketHorn.Core.Models;

namespace PacketHorn.Core.Interfaces;

public interface IDecisionEngine
{
    Decision Evaluate(DetectionResult detectionResult, DecisionMode mode);
}
