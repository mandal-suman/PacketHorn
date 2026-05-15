using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using PacketHorn.Core.Enums;
using PacketHorn.Core.Models;
using PacketHorn.Detection.Models;

namespace PacketHorn.Detection.Evaluators;

public class SignatureEvaluator
{
    private readonly List<SignatureRule> _rules;
    private readonly ConcurrentDictionary<string, List<DateTime>> _countState = new();

    private static readonly string[] Rfc1918Ranges = { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" };

    public SignatureEvaluator(List<SignatureRule> rules)
    {
        _rules = rules ?? new List<SignatureRule>();
    }

    public List<DetectionMatch> Evaluate(StructuredPacket packet)
    {
        var matches = new List<DetectionMatch>();

        foreach (var rule in _rules)
        {
            if (!MatchesRule(packet, rule))
                continue;

            if (rule.Count > 1 && rule.WindowSeconds > 0)
            {
                var stateKey = BuildCountKey(rule, packet);
                var timestamps = _countState.GetOrAdd(stateKey, _ => new List<DateTime>());
                lock (timestamps)
                {
                    var cutoff = DateTime.UtcNow.AddSeconds(-rule.WindowSeconds);
                    timestamps.RemoveAll(ts => ts < cutoff);
                    timestamps.Add(DateTime.UtcNow);

                    if (timestamps.Count < rule.Count)
                        continue;

                    timestamps.Clear();
                }
            }

            var confidenceScore = rule.Confidence switch
            {
                ConfidenceLevel.High => 0.95,
                ConfidenceLevel.Medium => 0.75,
                ConfidenceLevel.Low => 0.50,
                _ => 0.75
            };

            var match = new DetectionMatch
            {
                RuleName = rule.Name,
                Reason = $"Signature: {rule.Description}",
                Action = rule.Action,
                Result = new DetectionResult
                {
                    SourceIP = packet.SrcIP,
                    DestinationIP = packet.DstIP,
                    ThreatType = rule.Name,
                    RuleName = rule.Name,
                    MitreTactic = rule.MitreTactic,
                    MitreTechnique = rule.MitreTechnique,
                    Tags = rule.Tags,
                    Description = rule.Description,
                    SeverityLevel = rule.Severity,
                    ConfidenceScore = confidenceScore,
                    RequestedAction = rule.Action,
                    Timestamp = DateTime.UtcNow
                }
            };
            matches.Add(match);
        }

        return matches;
    }

    private bool MatchesRule(StructuredPacket packet, SignatureRule rule)
    {
        if (rule.Protocol != Protocol.Other && packet.Protocol != rule.Protocol)
            return false;

        if (!MatchesDirection(packet.Direction, rule.Direction))
            return false;

        if (!MatchesIP(packet.SrcIP, rule.SourceIP))
            return false;

        if (!MatchesIP(packet.DstIP, rule.DestinationIP))
            return false;

        if (!MatchesPort(packet.SrcPort, rule.SourcePort))
            return false;

        if (!MatchesPort(packet.DstPort, rule.DestinationPort))
            return false;

        if (packet.Protocol == Protocol.TCP && rule.FlagMask != 0x00)
        {
            var flagBytes = ParseFlagsFromString(packet.Flags);
            if ((flagBytes & rule.FlagMask) != rule.FlagMatch)
                return false;
        }

        if (!string.IsNullOrEmpty(rule.PayloadPattern) && packet.Payload.Length > 0)
        {
            if (!MatchesPayload(packet.Payload, rule.PayloadPattern, rule.PayloadPatternType))
                return false;
        }

        return true;
    }

    private static bool MatchesDirection(Direction packetDir, Direction ruleDir)
    {
        if (ruleDir == Direction.Any)
            return true;

        return packetDir == ruleDir;
    }

    private static bool MatchesIP(string packetIP, string rulePattern)
    {
        if (string.IsNullOrWhiteSpace(rulePattern) || rulePattern == "*" || rulePattern == "ANY")
            return true;

        if (rulePattern.StartsWith("@"))
        {
            var group = rulePattern.ToLowerInvariant();
            return group switch
            {
                "@internal" or "@workstations" => IsRfc1918(packetIP),
                "@external" => !IsRfc1918(packetIP) && !IPAddress.IsLoopback(IPAddress.TryParse(packetIP, out var a) ? a : IPAddress.None),
                _ => true
            };
        }

        if (rulePattern.Contains('/'))
            return IsIPInCidr(packetIP, rulePattern);

        return string.Equals(packetIP, rulePattern, StringComparison.OrdinalIgnoreCase);
    }

    private static bool MatchesPort(int packetPort, string rulePattern)
    {
        if (string.IsNullOrWhiteSpace(rulePattern) || rulePattern == "*" || rulePattern == "ANY")
            return true;

        if (rulePattern.Contains(','))
        {
            var parts = rulePattern.Split(',');
            foreach (var part in parts)
            {
                if (MatchesSinglePortOrRange(packetPort, part.Trim()))
                    return true;
            }
            return false;
        }

        return MatchesSinglePortOrRange(packetPort, rulePattern);
    }

    private static bool MatchesSinglePortOrRange(int packetPort, string pattern)
    {
        if (pattern.Contains(':'))
        {
            var rangeParts = pattern.Split(':');
            if (rangeParts.Length == 2
                && int.TryParse(rangeParts[0], out var low)
                && int.TryParse(rangeParts[1], out var high))
            {
                return packetPort >= low && packetPort <= high;
            }
            return false;
        }

        if (int.TryParse(pattern, out var port))
            return packetPort == port;

        return false;
    }

    private static bool MatchesPayload(byte[] payload, string pattern, string patternType)
    {
        if (string.Equals(patternType, "HEX", StringComparison.OrdinalIgnoreCase))
        {
            var cleaned = pattern.Replace("|", "").Replace(" ", "");
            if (cleaned.Length % 2 != 0)
                return false;

            var patternBytes = new byte[cleaned.Length / 2];
            for (int i = 0; i < patternBytes.Length; i++)
            {
                if (!byte.TryParse(cleaned.AsSpan(i * 2, 2), NumberStyles.HexNumber, null, out patternBytes[i]))
                    return false;
            }

            return ContainsSequence(payload, patternBytes);
        }

        try
        {
            var text = System.Text.Encoding.ASCII.GetString(payload);
            return Regex.IsMatch(text, pattern, RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100));
        }
        catch
        {
            return false;
        }
    }

    private static bool ContainsSequence(byte[] haystack, byte[] needle)
    {
        if (needle.Length == 0 || haystack.Length < needle.Length)
            return false;

        for (int i = 0; i <= haystack.Length - needle.Length; i++)
        {
            bool found = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j])
                {
                    found = false;
                    break;
                }
            }
            if (found)
                return true;
        }
        return false;
    }

    private static byte ParseFlagsFromString(string flags)
    {
        byte result = 0x00;
        if (flags.Contains("SYN")) result |= 0x02;
        if (flags.Contains("ACK")) result |= 0x10;
        if (flags.Contains("FIN")) result |= 0x01;
        if (flags.Contains("RST")) result |= 0x04;
        if (flags.Contains("PSH")) result |= 0x08;
        if (flags.Contains("URG")) result |= 0x20;
        return result;
    }

    private string BuildCountKey(SignatureRule rule, StructuredPacket packet)
    {
        return rule.ThresholdMode switch
        {
            ThresholdMode.PerSrc => $"{rule.Name}:{packet.SrcIP}",
            ThresholdMode.PerDst => $"{rule.Name}:{packet.DstIP}",
            ThresholdMode.PerPair => $"{rule.Name}:{packet.SrcIP}->{packet.DstIP}",
            ThresholdMode.Global => $"{rule.Name}:GLOBAL",
            _ => $"{rule.Name}:{packet.SrcIP}"
        };
    }

    private static bool IsRfc1918(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr))
            return false;

        foreach (var cidr in Rfc1918Ranges)
        {
            if (IsIPInCidr(ip, cidr))
                return true;
        }
        return false;
    }

    private static bool IsIPInCidr(string ip, string cidr)
    {
        try
        {
            var parts = cidr.Split('/');
            if (parts.Length != 2)
                return false;

            var networkIP = IPAddress.Parse(parts[0]);
            var prefixLength = int.Parse(parts[1]);
            var packetIPAddr = IPAddress.Parse(ip);

            var ipBytes = packetIPAddr.GetAddressBytes();
            var networkBytes = networkIP.GetAddressBytes();

            if (ipBytes.Length != networkBytes.Length)
                return false;

            int maskBytes = prefixLength / 8;
            int maskBits = prefixLength % 8;

            for (int i = 0; i < maskBytes; i++)
            {
                if (ipBytes[i] != networkBytes[i])
                    return false;
            }

            if (maskBits > 0)
            {
                byte mask = (byte)(0xFF << (8 - maskBits));
                if ((ipBytes[maskBytes] & mask) != (networkBytes[maskBytes] & mask))
                    return false;
            }

            return true;
        }
        catch
        {
            return false;
        }
    }
}
