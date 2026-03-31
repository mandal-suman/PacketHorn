using PacketHorn.Core.Enums;

namespace PacketHorn.Detection.Models;

/// <summary>
/// Signature-based detection rule (static pattern matching).
/// </summary>
public class SignatureRule
{
    public string Name { get; set; } = string.Empty;
    public Protocol Protocol { get; set; }
    public Direction Direction { get; set;}
    public string SourceIP { get; set; } = "ANY";
    public string DestinationIP { get; set; } = "ANY";
    public ushort Port { get; set; } = 0;
    public byte FlagMatch { get; set; } = 0x00;
    public byte FlagMask { get; set; } = 0x00;
    public int Count { get; set; } = 1;
    public int WindowSeconds { get; set; } = 1;
    public SeverityLevel Severity { get; set; }
    public string Description { get; set; } = string.Empty;
}

/// <summary>
/// Behavior-based detection rule (stateful anomaly detection).
/// </summary>
public class BehaviorRule
{
    public string Name { get; set; } = string.Empty;
    public Protocol Protocol { get; set; }
    public Direction Direction { get; set; }
    public int WindowSeconds { get; set; }
    public int Threshold { get; set; }
    public MetricType Metric { get; set; }
    public string GroupBy { get; set; } = "SRC_IP";
    public SeverityLevel Severity { get; set; }
    public string Description { get; set; } = string.Empty;
}

/// <summary>
/// State tracking for behavior-based rules.
/// </summary>
public class BehaviorState
{
    public string Key { get; set; } = string.Empty;
    public List<DateTime> PacketTimestamps { get; set; } = new();
    public HashSet<ushort> UniqueDestinationPorts { get; set; } = new();
    public ulong ByteCount { get; set; } = 0;
    public DateTime LastUpdate { get; set; } = DateTime.UtcNow;

    public int GetPacketCountInWindow(int windowSeconds)
    {
        var cutoff = DateTime.UtcNow.AddSeconds(-windowSeconds);
        return PacketTimestamps.Count(ts => ts >= cutoff);
    }

    public void PruneOldTimestamps(int windowSeconds)
    {
        var cutoff = DateTime.UtcNow.AddSeconds(-windowSeconds);
        PacketTimestamps.RemoveAll(ts => ts < cutoff);
    }
}
