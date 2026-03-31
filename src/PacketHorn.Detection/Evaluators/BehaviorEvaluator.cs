using System;
using System.Collections.Generic;
using System.Linq;
using PacketHorn.Core.Enums;
using PacketHorn.Core.Models;
using PacketHorn.Detection.Models;

namespace PacketHorn.Detection.Evaluators;

/// <summary>
/// Evaluates packets against behavior-based detection rules (stateful anomaly detection).
/// </summary>
public class BehaviorEvaluator
{
    private readonly List<BehaviorRule> _rules;
    private readonly Dictionary<string, BehaviorState> _stateStore = new();

    public BehaviorEvaluator(List<BehaviorRule> rules)
    {
        _rules = rules ?? new List<BehaviorRule>();
    }

    /// <summary>
    /// Evaluates a packet against all behavior rules with state tracking.
    /// </summary>
    public List<DetectionMatch> Evaluate(StructuredPacket packet)
    {
        var matches = new List<DetectionMatch>();

        foreach (var rule in _rules)
        {
            // Skip if rule doesn't match protocol
            if (rule.Protocol != Protocol.Other && packet.Protocol != rule.Protocol)
                continue;

            // Get or create state key for this rule + grouped attribute
            var stateKey = GetStateKey(rule, packet);
            if (!_stateStore.ContainsKey(stateKey))
                _stateStore[stateKey] = new BehaviorState { Key = stateKey };

            var state = _stateStore[stateKey];
            UpdateState(state, packet);

            // Check if threshold exceeded
            var metricValue = GetMetricValue(state, rule.Metric, rule.WindowSeconds);
            if (metricValue >= rule.Threshold)
            {
                var match = new DetectionMatch
                {
                    RuleName = rule.Name,
                    Reason = $"Behavior: {rule.Description} ({metricValue}/{rule.Threshold})",
                    Result = new DetectionResult
                    {
                        SourceIP = packet.SrcIP,
                        DestinationIP = packet.DstIP,
                        ThreatType = rule.Name,
                        SeverityLevel = rule.Severity,
                        ConfidenceScore = Math.Min(0.99f, 0.5f + (metricValue / (float)(rule.Threshold * 2))),
                        Timestamp = DateTime.UtcNow
                    }
                };
                matches.Add(match);

                // Reset state after detection to avoid duplicate alerts
                _stateStore[stateKey] = new BehaviorState { Key = stateKey };
            }
        }

        return matches;
    }

    private string GetStateKey(BehaviorRule rule, StructuredPacket packet)
    {
        return rule.GroupBy.ToUpper() switch
        {
            "SRC_IP" => $"{rule.Name}:{packet.SrcIP}",
            "DST_IP" => $"{rule.Name}:{packet.DstIP}",
            "SRC_PORT" => $"{rule.Name}:{packet.SrcPort}",
            "DST_PORT" => $"{rule.Name}:{packet.DstPort}",
            "PROTOCOL" => $"{rule.Name}:{packet.Protocol}",
            _ => $"{rule.Name}:{packet.SrcIP}"
        };
    }

    private void UpdateState(BehaviorState state, StructuredPacket packet)
    {
        // Add timestamp for sliding window
        state.PacketTimestamps.Add(DateTime.UtcNow);
        state.LastUpdate = DateTime.UtcNow;

        // Track unique destination ports
        if (packet.DstPort > 0)
            state.UniqueDestinationPorts.Add((ushort)packet.DstPort);

        // Track byte count
        state.ByteCount += (ulong)packet.PacketSize;
    }

    private int GetMetricValue(BehaviorState state, MetricType metric, int windowSeconds)
    {
        state.PruneOldTimestamps(Math.Max(1, windowSeconds));

        return metric switch
        {
            MetricType.PacketCount => state.PacketTimestamps.Count,
            MetricType.ByteCount => (int)Math.Min(int.MaxValue, state.ByteCount),
            MetricType.UniqueDestinationPorts => state.UniqueDestinationPorts.Count,
            MetricType.ConnectionCount => state.PacketTimestamps.Count,
            MetricType.ConnectionRate => state.PacketTimestamps.Count,
            MetricType.ErrorRate => state.PacketTimestamps.Count,
            _ => state.PacketTimestamps.Count
        };
    }

    /// <summary>
    /// Clears old state entries to prevent memory growth.
    /// </summary>
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
}
