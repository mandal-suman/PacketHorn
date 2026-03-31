using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using PacketHorn.Core.Enums;
using PacketHorn.Core.Models;
using PacketHorn.Detection.Models;

namespace PacketHorn.Detection.Evaluators;

/// <summary>
/// Evaluates packets against signature-based detection rules.
/// </summary>
public class SignatureEvaluator
{
    private readonly List<SignatureRule> _rules;

    public SignatureEvaluator(List<SignatureRule> rules)
    {
        _rules = rules ?? new List<SignatureRule>();
    }

    /// <summary>
    /// Evaluates a packet against all signature rules.
    /// </summary>
    public List<DetectionMatch> Evaluate(StructuredPacket packet)
    {
        var matches = new List<DetectionMatch>();

        foreach (var rule in _rules)
        {
            if (MatchesRule(packet, rule))
            {
                var match = new DetectionMatch
                {
                    RuleName = rule.Name,
                    Reason = $"Signature: {rule.Description}",
                    Result = new DetectionResult
                    {
                        SourceIP = packet.SrcIP,
                        DestinationIP = packet.DstIP,
                        ThreatType = rule.Name,
                        SeverityLevel = rule.Severity,
                        ConfidenceScore = 0.95f,
                        Timestamp = DateTime.UtcNow
                    }
                };
                matches.Add(match);
            }
        }

        return matches;
    }

    private bool MatchesRule(StructuredPacket packet, SignatureRule rule)
    {
        // Check protocol match
        if (rule.Protocol != Protocol.Other && packet.Protocol != rule.Protocol)
            return false;

        // Check source IP match
        if (rule.SourceIP != "ANY" && packet.SrcIP != rule.SourceIP)
        {
            if (!CheckIPRange(packet.SrcIP, rule.SourceIP))
                return false;
        }

        // Check destination IP match
        if (rule.DestinationIP != "ANY" && packet.DstIP != rule.DestinationIP)
        {
            if (!CheckIPRange(packet.DstIP, rule.DestinationIP))
                return false;
        }

        // Check port match
        if (rule.Port != 0)
        {
            if (packet.SrcPort != rule.Port && packet.DstPort != rule.Port)
                return false;
        }

        // Check TCP flags match (if applicable)
        if (packet.Protocol == Protocol.TCP && rule.FlagMask != 0x00)
        {
            var flagBytes = ParseFlagsFromString(packet.Flags);
            if ((flagBytes & rule.FlagMask) != rule.FlagMatch)
                return false;
        }

        return true;
    }

    private byte ParseFlagsFromString(string flags)
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

    private bool CheckIPRange(string packetIP, string rangePattern)
    {
        try
        {
            // Simple CIDR support (e.g., 192.168.1.0/24)
            if (rangePattern.Contains('/'))
            {
                var parts = rangePattern.Split('/');
                if (parts.Length == 2)
                {
                    var networkIP = IPAddress.Parse(parts[0]);
                    var prefixLength = int.Parse(parts[1]);
                    var packetIPAddr = IPAddress.Parse(packetIP);

                    return IsIPInRange(packetIPAddr, networkIP, prefixLength);
                }
            }

            // Exact match
            return packetIP == rangePattern;
        }
        catch
        {
            return false;
        }
    }

    private bool IsIPInRange(IPAddress ipAddress, IPAddress networkAddress, int prefixLength)
    {
        var ipBytes = ipAddress.GetAddressBytes();
        var networkBytes = networkAddress.GetAddressBytes();

        int bytesLength = ipBytes.Length;
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
}
