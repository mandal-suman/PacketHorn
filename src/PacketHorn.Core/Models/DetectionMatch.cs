using PacketHorn.Core.Enums;

namespace PacketHorn.Core.Models;

public class DetectionMatch
{
    public string RuleName { get; set; } = string.Empty;
    public DetectionResult? Result { get; set; }
    public string Reason { get; set; } = string.Empty;
    public RuleAction Action { get; set; } = RuleAction.Alert;
}
