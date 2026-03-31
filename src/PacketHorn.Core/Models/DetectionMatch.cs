using PacketHorn.Core.Models;

namespace PacketHorn.Core.Models;

/// <summary>
/// Detection match result combining rule evaluation with detection outcome.
/// </summary>
public class DetectionMatch
{
    public string RuleName { get; set; } = string.Empty;
    public DetectionResult? Result { get; set; }
    public string Reason { get; set; } = string.Empty;
}
