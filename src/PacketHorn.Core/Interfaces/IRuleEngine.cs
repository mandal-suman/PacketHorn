using PacketHorn.Core.Models;

namespace PacketHorn.Core.Interfaces;

/// <summary>
/// Interface for rule-based detection engines.
/// </summary>
public interface IRuleEngine
{
    /// <summary>
    /// Evaluates a packet against loaded rules.
    /// Returns a list of detection matches (can be empty if no detections).
    /// </summary>
    List<DetectionMatch> EvaluatePacket(StructuredPacket packet);
}
