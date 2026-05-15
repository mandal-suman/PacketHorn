using System;
using PacketHorn.Core.Enums;

namespace PacketHorn.Core.Models;

public class DetectionResult
{
    public string SourceIP { get; set; } = string.Empty;
    public string DestinationIP { get; set; } = string.Empty;
    public string ThreatType { get; set; } = string.Empty;
    public string RuleName { get; set; } = string.Empty;
    public string MitreTactic { get; set; } = string.Empty;
    public string MitreTechnique { get; set; } = string.Empty;
    public string Tags { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public SeverityLevel SeverityLevel { get; set; }
    public double ConfidenceScore { get; set; }
    public RuleAction RequestedAction { get; set; } = RuleAction.Alert;
    public DateTime Timestamp { get; set; }
}
