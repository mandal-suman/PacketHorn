using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using PacketHorn.Core.Enums;
using PacketHorn.Core.Models;
using PacketHorn.Detection.Models;

namespace PacketHorn.Detection.Evaluators;

public class BehaviorEvaluator
{
    private readonly List<BehaviorRule> _rules;
    private readonly Dictionary<string, BehaviorState> _stateStore = new();
    private const double AdaptiveBaselineMultiplier = 1.5;

    private static readonly string[] Rfc1918Ranges = { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" };

    public BehaviorEvaluator(List<BehaviorRule> rules)
    {
        _rules = rules ?? new List<BehaviorRule>();
    }

    public List<DetectionMatch> Evaluate(StructuredPacket packet)
    {
        var matches = new List<DetectionMatch>();

        foreach (var rule in _rules)
        {
            if (rule.Protocol != Protocol.Other && packet.Protocol != rule.Protocol)
                continue;

            if (!MatchesDirection(packet.Direction, rule.Direction))
                continue;

            if (!MatchesIP(packet.SrcIP, rule.SourceIP))
                continue;

            if (!MatchesIP(packet.DstIP, rule.DestinationIP))
                continue;

            if (!MatchesPort(packet.DstPort, rule.DestinationPort))
                continue;

            var stateKey = GetStateKey(rule, packet);
            if (!_stateStore.ContainsKey(stateKey))
                _stateStore[stateKey] = new BehaviorState { Key = stateKey };

            var state = _stateStore[stateKey];
            UpdateState(state, packet);

            var metricValue = GetMetricValue(state, rule, rule.WindowSeconds);
            var effectiveThreshold = GetEffectiveThreshold(rule, state);
            if (metricValue >= effectiveThreshold)
            {
                var confidenceScore = rule.Confidence switch
                {
                    ConfidenceLevel.High => Math.Min(0.99, 0.85 + (metricValue / (double)(Math.Max(1, effectiveThreshold) * 4))),
                    ConfidenceLevel.Medium => Math.Min(0.95, 0.60 + (metricValue / (double)(Math.Max(1, effectiveThreshold) * 3))),
                    ConfidenceLevel.Low => Math.Min(0.80, 0.40 + (metricValue / (double)(Math.Max(1, effectiveThreshold) * 3))),
                    _ => Math.Min(0.95, 0.50 + (metricValue / (double)(Math.Max(1, effectiveThreshold) * 2)))
                };

                var match = new DetectionMatch
                {
                    RuleName = rule.Name,
                    Reason = $"Behavior: {rule.Description} ({metricValue:0.##}/{effectiveThreshold:0.##})",
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

                _stateStore[stateKey] = new BehaviorState { Key = stateKey };
            }
            else
            {
                UpdateAdaptiveBaseline(rule, state, metricValue);
            }
        }

        return matches;
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

    private string GetStateKey(BehaviorRule rule, StructuredPacket packet)
    {
        return rule.GroupBy.ToUpperInvariant() switch
        {
            "SRC_IP" => $"{rule.Name}:{packet.SrcIP}",
            "DST_IP" => $"{rule.Name}:{packet.DstIP}",
            "SRC_DST_PAIR" => $"{rule.Name}:{packet.SrcIP}->{packet.DstIP}",
            "SRC_SUBNET" => $"{rule.Name}:{GetSubnet(packet.SrcIP)}",
            "SRC_PORT" => $"{rule.Name}:{packet.SrcPort}",
            "DST_PORT" => $"{rule.Name}:{packet.DstPort}",
            "PROTOCOL" => $"{rule.Name}:{packet.Protocol}",
            "GLOBAL" => $"{rule.Name}:GLOBAL",
            _ => $"{rule.Name}:{packet.SrcIP}"
        };
    }

    private static string GetSubnet(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr))
            return ip;

        var bytes = addr.GetAddressBytes();
        if (bytes.Length >= 3)
            return $"{bytes[0]}.{bytes[1]}.{bytes[2]}.0/24";

        return ip;
    }

    private void UpdateState(BehaviorState state, StructuredPacket packet)
    {
        var now = DateTime.UtcNow;
        state.PacketTimestamps.Add(now);
        state.ByteSamples.Add((now, packet.PacketSize));
        state.LastUpdate = now;

        if (packet.DstPort > 0)
            state.DestinationPortsSeen[(ushort)packet.DstPort] = now;

        if (!string.IsNullOrWhiteSpace(packet.SrcIP))
            state.SourceIPsSeen[packet.SrcIP] = now;

        if (!string.IsNullOrWhiteSpace(packet.DstIP))
            state.DestinationIPsSeen[packet.DstIP] = now;

        var sessionKey = $"{packet.Protocol}:{packet.SrcIP}:{packet.SrcPort}->{packet.DstIP}:{packet.DstPort}";
        state.SessionKeysSeen[sessionKey] = now;

        if (packet.Protocol == Protocol.UDP && (packet.SrcPort == 53 || packet.DstPort == 53))
        {
            var fqdn = TryExtractDnsQueryName(packet.Payload);
            if (!string.IsNullOrWhiteSpace(fqdn))
                state.FqdnsSeen[fqdn] = now;
        }

        if (packet.Protocol == Protocol.TCP && packet.Flags.Contains("SYN", StringComparison.OrdinalIgnoreCase) && !packet.Flags.Contains("ACK", StringComparison.OrdinalIgnoreCase))
            state.FailedConnectionTimestamps.Add(now);

        if ((packet.Protocol == Protocol.TCP && packet.Flags.Contains("RST", StringComparison.OrdinalIgnoreCase)) || packet.Protocol == Protocol.ICMP)
            state.ErrorEventTimestamps.Add(now);
    }

    private double GetMetricValue(BehaviorState state, BehaviorRule rule, int windowSeconds)
    {
        state.PruneOldTimestamps(Math.Max(1, windowSeconds));

        return rule.Metric switch
        {
            MetricType.PacketCount => ApplyDecay(state.PacketTimestamps, windowSeconds, rule.Decay),
            MetricType.ByteCount => ApplyByteDecay(state.ByteSamples, windowSeconds, rule.Decay),
            MetricType.UniqueDestinationPorts => state.DestinationPortsSeen.Count,
            MetricType.UniquePorts => state.DestinationPortsSeen.Count,
            MetricType.UniqueSourceIPs => state.SourceIPsSeen.Count,
            MetricType.UniqueDestinationIPs => state.DestinationIPsSeen.Count,
            MetricType.ConnectionCount => state.SessionKeysSeen.Count,
            MetricType.ConnectionRate => state.SessionKeysSeen.Count,
            MetricType.PacketRate => windowSeconds > 0 ? ApplyDecay(state.PacketTimestamps, windowSeconds, rule.Decay) / Math.Max(1, windowSeconds) : state.PacketTimestamps.Count,
            MetricType.Count => ApplyDecay(state.PacketTimestamps, windowSeconds, rule.Decay),
            MetricType.UniqueFQDNs => state.FqdnsSeen.Count,
            MetricType.UniqueSessions => state.SessionKeysSeen.Count,
            MetricType.FailedConnections => state.FailedConnectionTimestamps.Count,
            MetricType.ErrorRate => windowSeconds > 0 ? state.ErrorEventTimestamps.Count / (double)Math.Max(1, windowSeconds) : state.ErrorEventTimestamps.Count,
            _ => state.PacketTimestamps.Count
        };
    }

    private static double GetEffectiveThreshold(BehaviorRule rule, BehaviorState state)
    {
        var baseThreshold = Math.Max(1, rule.Threshold);
        if (rule.BaselineMode != BaselineMode.Adaptive || state.AdaptiveBaseline <= 0)
            return baseThreshold;

        return Math.Max(baseThreshold, Math.Ceiling(state.AdaptiveBaseline * AdaptiveBaselineMultiplier));
    }

    private static void UpdateAdaptiveBaseline(BehaviorRule rule, BehaviorState state, double metricValue)
    {
        if (rule.BaselineMode != BaselineMode.Adaptive)
            return;

        state.AdaptiveBaseline = state.AdaptiveBaseline <= 0
            ? metricValue
            : (state.AdaptiveBaseline * 0.8) + (metricValue * 0.2);
    }

    private static double ApplyDecay(List<DateTime> timestamps, int windowSeconds, DecayMode decayMode)
    {
        if (decayMode == DecayMode.None)
            return timestamps.Count;

        var now = DateTime.UtcNow;
        var window = Math.Max(1, windowSeconds);
        return timestamps.Sum(ts =>
        {
            var ageSeconds = Math.Max(0, (now - ts).TotalSeconds);
            var decayFactor = decayMode == DecayMode.Linear
                ? Math.Max(0, 1 - (ageSeconds / window))
                : Math.Exp(-ageSeconds / window);
            return decayFactor;
        });
    }

    private static double ApplyByteDecay(List<(DateTime Timestamp, int Bytes)> byteSamples, int windowSeconds, DecayMode decayMode)
    {
        if (decayMode == DecayMode.None)
            return byteSamples.Sum(sample => (double)sample.Bytes);

        var now = DateTime.UtcNow;
        var window = Math.Max(1, windowSeconds);
        return byteSamples.Sum(sample =>
        {
            var ageSeconds = Math.Max(0, (now - sample.Timestamp).TotalSeconds);
            var decayFactor = decayMode == DecayMode.Linear
                ? Math.Max(0, 1 - (ageSeconds / window))
                : Math.Exp(-ageSeconds / window);
            return sample.Bytes * decayFactor;
        });
    }

    private static string? TryExtractDnsQueryName(byte[] payload)
    {
        if (payload.Length < 13)
            return null;

        int offset = 12;
        var labels = new List<string>();

        while (offset < payload.Length)
        {
            var length = payload[offset++];
            if (length == 0)
                break;

            if (length > 63 || offset + length > payload.Length)
                return null;

            var label = System.Text.Encoding.ASCII.GetString(payload, offset, length).Trim();
            if (string.IsNullOrWhiteSpace(label))
                return null;

            labels.Add(label);
            offset += length;
        }

        if (labels.Count == 0)
            return null;

        return string.Join(".", labels);
    }

    public void CleanupOldStates(int maxAgeSeconds = 300)
    {
        var cutoff = DateTime.UtcNow.AddSeconds(-maxAgeSeconds);
        var keysToRemove = _stateStore
            .Where(kvp => kvp.Value.LastUpdate < cutoff)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in keysToRemove)
            _stateStore.Remove(key);
    }

    private static bool IsRfc1918(string ip)
    {
        if (!IPAddress.TryParse(ip, out _))
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
