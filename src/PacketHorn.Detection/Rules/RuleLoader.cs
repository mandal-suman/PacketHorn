using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using PacketHorn.Core.Enums;
using PacketHorn.Detection.Models;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace PacketHorn.Detection.Rules;

public class RuleLoader
{
    private readonly string _rulesDirectory;

    public RuleLoader(string rulesDirectory)
    {
        _rulesDirectory = rulesDirectory;
    }

    public List<SignatureRule> LoadSignatureRules()
    {
        var filePath = Path.Combine(_rulesDirectory, "signatures.yaml");
        var rules = new List<SignatureRule>();

        if (!File.Exists(filePath))
        {
            Console.WriteLine($"[WARNING] Signature rules file not found: {filePath}");
            return rules;
        }

        try
        {
            var yaml = File.ReadAllText(filePath);
            var deserializer = new DeserializerBuilder()
                .WithNamingConvention(UnderscoredNamingConvention.Instance)
                .IgnoreUnmatchedProperties()
                .Build();

            var doc = deserializer.Deserialize<SignatureYamlDocument>(yaml);
            if (doc?.Signatures == null)
                return rules;

            foreach (var entry in doc.Signatures)
            {
                var rule = MapSignatureEntry(entry);
                if (rule != null)
                    rules.Add(rule);
            }

            Console.WriteLine($"[INFO] Loaded {rules.Count} signature rules");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] Failed to load signature rules: {ex.Message}");
        }

        return rules;
    }

    public List<BehaviorRule> LoadBehaviorRules()
    {
        var filePath = Path.Combine(_rulesDirectory, "behaviors.yaml");
        var rules = new List<BehaviorRule>();

        if (!File.Exists(filePath))
        {
            Console.WriteLine($"[WARNING] Behavior rules file not found: {filePath}");
            return rules;
        }

        try
        {
            var yaml = File.ReadAllText(filePath);
            var deserializer = new DeserializerBuilder()
                .WithNamingConvention(UnderscoredNamingConvention.Instance)
                .IgnoreUnmatchedProperties()
                .Build();

            var doc = deserializer.Deserialize<BehaviorYamlDocument>(yaml);
            if (doc?.Behaviors == null)
                return rules;

            foreach (var entry in doc.Behaviors)
            {
                var rule = MapBehaviorEntry(entry);
                if (rule != null)
                    rules.Add(rule);
            }

            Console.WriteLine($"[INFO] Loaded {rules.Count} behavior rules");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] Failed to load behavior rules: {ex.Message}");
        }

        return rules;
    }

    private SignatureRule? MapSignatureEntry(SignatureYamlEntry entry)
    {
        try
        {
            return new SignatureRule
            {
                Name = entry.Name ?? string.Empty,
                Version = entry.Version,
                Protocol = ParseProtocol(entry.Protocol),
                Direction = ParseDirection(entry.Direction),
                SourceIP = entry.SrcIp ?? "*",
                SourcePort = entry.SrcPort ?? "*",
                DestinationIP = entry.DstIp ?? "*",
                DestinationPort = entry.DstPort ?? "*",
                FlagMatch = ParseHexByte(entry.FlagMatch),
                FlagMask = ParseHexByte(entry.FlagMask),
                PayloadPattern = entry.PayloadPattern ?? string.Empty,
                PayloadPatternType = entry.PayloadPatternType ?? string.Empty,
                Count = entry.Count > 0 ? entry.Count : 1,
                WindowSeconds = entry.WindowSec,
                ThresholdMode = ParseThresholdMode(entry.ThresholdMode),
                MitreTactic = entry.MitreTactic ?? string.Empty,
                MitreTechnique = entry.MitreTechnique ?? string.Empty,
                Tags = entry.Tags ?? string.Empty,
                Severity = ParseSeverity(entry.Severity),
                Confidence = ParseConfidence(entry.Confidence),
                Action = ParseRuleAction(entry.Action),
                Description = entry.Description?.Trim() ?? string.Empty
            };
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] Failed to map signature rule '{entry.Name}': {ex.Message}");
            return null;
        }
    }

    private BehaviorRule? MapBehaviorEntry(BehaviorYamlEntry entry)
    {
        try
        {
            return new BehaviorRule
            {
                Name = entry.Name ?? string.Empty,
                Version = entry.Version,
                Protocol = ParseProtocol(entry.Protocol),
                Direction = ParseDirection(entry.Direction),
                SourceIP = entry.SrcIp ?? "*",
                DestinationIP = entry.DstIp ?? "*",
                DestinationPort = entry.DstPort ?? "*",
                WindowSeconds = entry.WindowSec,
                Threshold = entry.Threshold,
                Metric = ParseMetric(entry.Metric),
                GroupBy = entry.GroupBy ?? "SRC_IP",
                Decay = ParseDecay(entry.Decay),
                BaselineMode = ParseBaselineMode(entry.BaselineMode),
                MitreTactic = entry.MitreTactic ?? string.Empty,
                MitreTechnique = entry.MitreTechnique ?? string.Empty,
                Tags = entry.Tags ?? string.Empty,
                Severity = ParseSeverity(entry.Severity),
                Confidence = ParseConfidence(entry.Confidence),
                Action = ParseRuleAction(entry.Action),
                Description = entry.Description?.Trim() ?? string.Empty
            };
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] Failed to map behavior rule '{entry.Name}': {ex.Message}");
            return null;
        }
    }

    private static Protocol ParseProtocol(string? protocol)
    {
        return (protocol?.ToUpperInvariant()) switch
        {
            "TCP" => Protocol.TCP,
            "UDP" => Protocol.UDP,
            "ICMP" => Protocol.ICMP,
            "ANY" => Protocol.Other,
            _ => Protocol.Other
        };
    }

    private static Direction ParseDirection(string? direction)
    {
        return (direction?.ToUpperInvariant()) switch
        {
            "INBOUND" => Direction.Inbound,
            "OUTBOUND" => Direction.Outbound,
            "LATERAL" => Direction.Lateral,
            "ANY" => Direction.Any,
            "BOTH" => Direction.Any,
            _ => Direction.Any
        };
    }

    private static SeverityLevel ParseSeverity(string? severity)
    {
        return (severity?.ToUpperInvariant()) switch
        {
            "CRITICAL" => SeverityLevel.Critical,
            "HIGH" => SeverityLevel.High,
            "MEDIUM" => SeverityLevel.Medium,
            "LOW" => SeverityLevel.Low,
            "INFO" => SeverityLevel.Info,
            _ => SeverityLevel.Low
        };
    }

    private static ConfidenceLevel ParseConfidence(string? confidence)
    {
        return (confidence?.ToUpperInvariant()) switch
        {
            "HIGH" => ConfidenceLevel.High,
            "MEDIUM" => ConfidenceLevel.Medium,
            "LOW" => ConfidenceLevel.Low,
            _ => ConfidenceLevel.Medium
        };
    }

    private static RuleAction ParseRuleAction(string? action)
    {
        return (action?.ToUpperInvariant()) switch
        {
            "ALERT" => RuleAction.Alert,
            "BLOCK" => RuleAction.Block,
            "ALERT_AND_BLOCK" => RuleAction.AlertAndBlock,
            "NONE" => RuleAction.None,
            _ => RuleAction.Alert
        };
    }

    private static ThresholdMode ParseThresholdMode(string? mode)
    {
        return (mode?.ToUpperInvariant()) switch
        {
            "PER_SRC" => ThresholdMode.PerSrc,
            "PER_DST" => ThresholdMode.PerDst,
            "PER_PAIR" => ThresholdMode.PerPair,
            "GLOBAL" => ThresholdMode.Global,
            _ => ThresholdMode.PerSrc
        };
    }

    private static MetricType ParseMetric(string? metric)
    {
        return (metric?.ToUpperInvariant()) switch
        {
            "PACKET_COUNT" or "PACKETS" => MetricType.PacketCount,
            "BYTE_COUNT" or "BYTES" => MetricType.ByteCount,
            "UNIQUE_DST_PORTS" or "UNIQUE_PORTS" => MetricType.UniquePorts,
            "UNIQUE_SRC_IPS" or "UNIQUE_SRC_ADDRESSES" => MetricType.UniqueSourceIPs,
            "UNIQUE_DST_IPS" or "UNIQUE_DSTS" => MetricType.UniqueDestinationIPs,
            "UNIQUE_SESSIONS" => MetricType.UniqueSessions,
            "FAILED_CONNECTIONS" => MetricType.FailedConnections,
            "PACKET_RATE" => MetricType.PacketRate,
            "CONNECTION_COUNT" => MetricType.ConnectionCount,
            "CONNECTION_RATE" => MetricType.ConnectionRate,
            "UNIQUE_FQDNS" => MetricType.UniqueFQDNs,
            "COUNT" => MetricType.Count,
            _ => MetricType.PacketCount
        };
    }

    private static DecayMode ParseDecay(string? decay)
    {
        return (decay?.ToUpperInvariant()) switch
        {
            "LINEAR" => DecayMode.Linear,
            "EXPONENTIAL" => DecayMode.Exponential,
            "NONE" => DecayMode.None,
            _ => DecayMode.None
        };
    }

    private static BaselineMode ParseBaselineMode(string? mode)
    {
        return (mode?.ToUpperInvariant()) switch
        {
            "STATIC" => BaselineMode.Static,
            "ADAPTIVE" => BaselineMode.Adaptive,
            _ => BaselineMode.Static
        };
    }

    private static byte ParseHexByte(string? hex)
    {
        if (string.IsNullOrWhiteSpace(hex) || hex == "ANY")
            return 0x00;

        var cleaned = hex;
        if (cleaned.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            cleaned = cleaned.Substring(2);

        return byte.TryParse(cleaned, System.Globalization.NumberStyles.HexNumber, null, out var result) ? result : (byte)0x00;
    }
}

public class SignatureYamlDocument
{
    public List<SignatureYamlEntry> Signatures { get; set; } = new();
}

public class SignatureYamlEntry
{
    public string? Name { get; set; }
    public int Version { get; set; } = 1;
    public string? Protocol { get; set; }
    public string? Direction { get; set; }
    public string? SrcIp { get; set; }
    public string? SrcPort { get; set; }
    public string? DstIp { get; set; }
    public string? DstPort { get; set; }
    public string? FlagMatch { get; set; }
    public string? FlagMask { get; set; }
    public string? PayloadPattern { get; set; }
    public string? PayloadPatternType { get; set; }
    public int Count { get; set; } = 1;
    public int WindowSec { get; set; }
    public string? ThresholdMode { get; set; }
    public string? MitreTactic { get; set; }
    public string? MitreTechnique { get; set; }
    public string? Tags { get; set; }
    public string? Severity { get; set; }
    public string? Confidence { get; set; }
    public string? Action { get; set; }
    public string? Description { get; set; }
}

public class BehaviorYamlDocument
{
    public List<BehaviorYamlEntry> Behaviors { get; set; } = new();
}

public class BehaviorYamlEntry
{
    public string? Name { get; set; }
    public int Version { get; set; } = 1;
    public string? Protocol { get; set; }
    public string? Direction { get; set; }
    public string? SrcIp { get; set; }
    public string? DstIp { get; set; }
    public string? DstPort { get; set; }
    public int WindowSec { get; set; }
    public int Threshold { get; set; }
    public string? Metric { get; set; }
    public string? GroupBy { get; set; }
    public string? Decay { get; set; }
    public string? BaselineMode { get; set; }
    public string? MitreTactic { get; set; }
    public string? MitreTechnique { get; set; }
    public string? Tags { get; set; }
    public string? Severity { get; set; }
    public string? Confidence { get; set; }
    public string? Action { get; set; }
    public string? Description { get; set; }
}
