using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using PacketHorn.Core.Enums;
using PacketHorn.Detection.Models;

namespace PacketHorn.Detection.Rules;

/// <summary>
/// Loads and parses signature and behavior rules from .rules files.
/// </summary>
public class RuleLoader
{
    private readonly string _rulesDirectory;

    public RuleLoader(string rulesDirectory)
    {
        _rulesDirectory = rulesDirectory;
    }

    /// <summary>
    /// Loads all signature rules from signatures.rules file.
    /// </summary>
    public List<SignatureRule> LoadSignatureRules()
    {
        var filePath = Path.Combine(_rulesDirectory, "signatures.rules");
        var rules = new List<SignatureRule>();

        if (!File.Exists(filePath))
        {
            Console.WriteLine($"[WARNING] Signature rules file not found: {filePath}");
            return rules;
        }

        try
        {
            var lines = File.ReadAllLines(filePath);
            foreach (var line in lines)
            {
                // Skip header and empty lines
                if (line.StartsWith("NAME |") || string.IsNullOrWhiteSpace(line))
                    continue;

                var rule = ParseSignatureRule(line);
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

    /// <summary>
    /// Loads all behavior rules from behaviors.rules file.
    /// </summary>
    public List<BehaviorRule> LoadBehaviorRules()
    {
        var filePath = Path.Combine(_rulesDirectory, "behaviors.rules");
        var rules = new List<BehaviorRule>();

        if (!File.Exists(filePath))
        {
            Console.WriteLine($"[WARNING] Behavior rules file not found: {filePath}");
            return rules;
        }

        try
        {
            var lines = File.ReadAllLines(filePath);
            foreach (var line in lines)
            {
                // Skip header and empty lines
                if (line.StartsWith("NAME |") || string.IsNullOrWhiteSpace(line))
                    continue;

                var rule = ParseBehaviorRule(line);
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

    private SignatureRule? ParseSignatureRule(string line)
    {
        try
        {
            var parts = line.Split('|').Select(p => p.Trim()).ToArray();
            if (parts.Length < 12)
                return null;

            return new SignatureRule
            {
                Name = parts[0],
                Protocol = ParseProtocol(parts[1]),
                Direction = ParseDirection(parts[2]),
                SourceIP = parts[3],
                DestinationIP = parts[4],
                Port = ushort.TryParse(parts[5], out var port) ? port : (ushort)0,
                FlagMatch = ParseHexByte(parts[6]),
                FlagMask = ParseHexByte(parts[7]),
                Count = int.TryParse(parts[8], out var count) ? count : 1,
                WindowSeconds = int.TryParse(parts[9], out var window) ? window : 1,
                Severity = ParseSeverity(parts[10]),
                Description = parts[11]
            };
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] Failed to parse signature rule: {ex.Message}");
            return null;
        }
    }

    private BehaviorRule? ParseBehaviorRule(string line)
    {
        try
        {
            var parts = line.Split('|').Select(p => p.Trim()).ToArray();
            if (parts.Length < 8)
                return null;

            return new BehaviorRule
            {
                Name = parts[0],
                Protocol = ParseProtocol(parts[1]),
                Direction = ParseDirection(parts[2]),
                WindowSeconds = int.TryParse(parts[3], out var window) ? window : 5,
                Threshold = int.TryParse(parts[4], out var threshold) ? threshold : 10,
                Metric = ParseMetric(parts[5]),
                GroupBy = parts[6],
                Severity = ParseSeverity(parts[7]),
                Description = parts.Length > 8 ? parts[8] : string.Empty
            };
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] Failed to parse behavior rule: {ex.Message}");
            return null;
        }
    }

    private Protocol ParseProtocol(string protocol)
    {
        return protocol.ToUpper() switch
        {
            "TCP" => Protocol.TCP,
            "UDP" => Protocol.UDP,
            "ICMP" => Protocol.ICMP,
            "ANY" => Protocol.Other,
            _ => Protocol.Other
        };
    }

    private Direction ParseDirection(string direction)
    {
        return direction.ToUpper() switch
        {
            "INBOUND" => Direction.Inbound,
            "OUTBOUND" => Direction.Outbound,
            "BOTH" => Direction.Unknown,
            _ => Direction.Unknown
        };
    }

    private SeverityLevel ParseSeverity(string severity)
    {
        return severity.ToUpper() switch
        {
            "CRITICAL" => SeverityLevel.Critical,
            "HIGH" => SeverityLevel.High,
            "MEDIUM" => SeverityLevel.Medium,
            "LOW" => SeverityLevel.Low,
            "INFO" => SeverityLevel.Info,
            _ => SeverityLevel.Low
        };
    }

    private MetricType ParseMetric(string metric)
    {
        return metric.ToUpper() switch
        {
            "PACKET_COUNT" => MetricType.PacketCount,
            "BYTE_COUNT" => MetricType.ByteCount,
            "UNIQUE_DST_PORTS" => MetricType.UniqueDestinationPorts,
            "CONNECTION_COUNT" => MetricType.ConnectionCount,
            _ => MetricType.PacketCount
        };
    }

    private byte ParseHexByte(string hex)
    {
        if (string.IsNullOrWhiteSpace(hex) || hex == "ANY")
            return 0x00;

        if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            hex = hex.Substring(2);

        return byte.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out var result) ? result : (byte)0x00;
    }
}
