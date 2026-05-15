using PacketHorn.Core.Enums;

namespace PacketHorn.Detection.Models;

public class SignatureRule
{
    public string Name { get; set; } = string.Empty;
    public int Version { get; set; } = 1;
    public Protocol Protocol { get; set; }
    public Direction Direction { get; set; }
    public string SourceIP { get; set; } = "*";
    public string SourcePort { get; set; } = "*";
    public string DestinationIP { get; set; } = "*";
    public string DestinationPort { get; set; } = "*";
    public byte FlagMatch { get; set; } = 0x00;
    public byte FlagMask { get; set; } = 0x00;
    public string PayloadPattern { get; set; } = string.Empty;
    public string PayloadPatternType { get; set; } = string.Empty;
    public int Count { get; set; } = 1;
    public int WindowSeconds { get; set; } = 0;
    public ThresholdMode ThresholdMode { get; set; } = ThresholdMode.PerSrc;
    public string MitreTactic { get; set; } = string.Empty;
    public string MitreTechnique { get; set; } = string.Empty;
    public string Tags { get; set; } = string.Empty;
    public SeverityLevel Severity { get; set; }
    public ConfidenceLevel Confidence { get; set; } = ConfidenceLevel.Medium;
    public RuleAction Action { get; set; } = RuleAction.Alert;
    public string Description { get; set; } = string.Empty;
}

public class BehaviorRule
{
    public string Name { get; set; } = string.Empty;
    public int Version { get; set; } = 1;
    public Protocol Protocol { get; set; }
    public Direction Direction { get; set; }
    public string SourceIP { get; set; } = "*";
    public string DestinationIP { get; set; } = "*";
    public string DestinationPort { get; set; } = "*";
    public int WindowSeconds { get; set; }
    public int Threshold { get; set; }
    public MetricType Metric { get; set; }
    public string GroupBy { get; set; } = "SRC_IP";
    public DecayMode Decay { get; set; } = DecayMode.None;
    public BaselineMode BaselineMode { get; set; } = BaselineMode.Static;
    public string MitreTactic { get; set; } = string.Empty;
    public string MitreTechnique { get; set; } = string.Empty;
    public string Tags { get; set; } = string.Empty;
    public SeverityLevel Severity { get; set; }
    public ConfidenceLevel Confidence { get; set; } = ConfidenceLevel.Medium;
    public RuleAction Action { get; set; } = RuleAction.Alert;
    public string Description { get; set; } = string.Empty;
}

public class BehaviorState
{
    public string Key { get; set; } = string.Empty;
    public List<DateTime> PacketTimestamps { get; set; } = new();
    public List<(DateTime Timestamp, int Bytes)> ByteSamples { get; set; } = new();
    public Dictionary<ushort, DateTime> DestinationPortsSeen { get; set; } = new();
    public Dictionary<string, DateTime> SourceIPsSeen { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, DateTime> DestinationIPsSeen { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, DateTime> FqdnsSeen { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, DateTime> SessionKeysSeen { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public List<DateTime> FailedConnectionTimestamps { get; set; } = new();
    public List<DateTime> ErrorEventTimestamps { get; set; } = new();
    public double AdaptiveBaseline { get; set; }
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
        ByteSamples.RemoveAll(sample => sample.Timestamp < cutoff);
        FailedConnectionTimestamps.RemoveAll(ts => ts < cutoff);
        ErrorEventTimestamps.RemoveAll(ts => ts < cutoff);
        PruneSeenDictionary(DestinationPortsSeen, cutoff);
        PruneSeenDictionary(SourceIPsSeen, cutoff);
        PruneSeenDictionary(DestinationIPsSeen, cutoff);
        PruneSeenDictionary(FqdnsSeen, cutoff);
        PruneSeenDictionary(SessionKeysSeen, cutoff);
    }

    private static void PruneSeenDictionary<TKey>(Dictionary<TKey, DateTime> dictionary, DateTime cutoff) where TKey : notnull
    {
        var keysToRemove = dictionary
            .Where(kvp => kvp.Value < cutoff)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in keysToRemove)
            dictionary.Remove(key);
    }
}
