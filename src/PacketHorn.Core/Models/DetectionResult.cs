using System;
using PacketHorn.Core.Enums;

namespace PacketHorn.Core.Models;

public class DetectionResult
{
    public string SourceIP { get; set; } = string.Empty;
    public string DestinationIP { get; set; } = string.Empty;
    public string ThreatType { get; set; } = string.Empty;
    public SeverityLevel SeverityLevel { get; set; }
    public double ConfidenceScore { get; set; }
    public DateTime Timestamp { get; set; }
}
