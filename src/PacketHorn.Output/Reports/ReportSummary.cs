using System;
using System.Collections.Generic;
using PacketHorn.Core.Enums;

namespace PacketHorn.Output.Reports;

public sealed class ReportSummary
{
    public DateTime SessionStartUtc { get; init; }
    public DateTime SessionEndUtc { get; init; }
    public ulong TotalPackets { get; init; }
    public ulong TotalBytes { get; init; }
    public ulong TotalDetections { get; init; }
    public DecisionMode DecisionMode { get; init; }
    public string HostName { get; init; } = string.Empty;
    public string UserName { get; init; } = string.Empty;
    public string OSDescription { get; init; } = string.Empty;
    public List<string> LocalAddresses { get; init; } = new();
    public string InterfaceName { get; init; } = string.Empty;
    public string InterfaceDescription { get; init; } = string.Empty;
    public string CaptureFilter { get; init; } = string.Empty;
    public bool Promiscuous { get; init; }
    public int ReadTimeoutMs { get; init; }
    public Dictionary<SeverityLevel, ulong> SeverityCounts { get; init; } = new();
    public Dictionary<string, ulong> ThreatCounts { get; init; } = new(StringComparer.OrdinalIgnoreCase);
}
