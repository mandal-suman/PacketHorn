using PacketHorn.Core.Enums;
using PacketHorn.Core.Interfaces;
using PacketHorn.Core.Models;

namespace PacketHorn.Response.Decision;

public class DecisionEngine : IDecisionEngine
{
    public PacketHorn.Core.Models.Decision Evaluate(DetectionMatch detectionMatch, DecisionMode mode)
    {
        var detectionResult = detectionMatch.Result;
        if (detectionResult == null)
        {
            return new PacketHorn.Core.Models.Decision
            {
                Mode = mode,
                Action = ResponseAction.Ignore,
                Reason = "Detection payload missing",
                RequiresOperatorApproval = false
            };
        }

        var sourceIp = detectionResult.SourceIP;
        var blockRequested = detectionMatch.Action is RuleAction.Block or RuleAction.AlertAndBlock;
        var alertRequested = detectionMatch.Action is RuleAction.Alert or RuleAction.AlertAndBlock;
        var canBlock = !string.IsNullOrWhiteSpace(sourceIp);

        if (detectionMatch.Action == RuleAction.None)
        {
            return new PacketHorn.Core.Models.Decision
            {
                Mode = mode,
                Action = ResponseAction.Ignore,
                TargetIP = sourceIp,
                Reason = "Rule action set to NONE",
                RequiresOperatorApproval = false
            };
        }

        return mode switch
        {
            DecisionMode.AlertOnly => new PacketHorn.Core.Models.Decision
            {
                Mode = mode,
                Action = ResponseAction.AlertOnly,
                TargetIP = sourceIp,
                Reason = alertRequested || blockRequested
                    ? "AlertOnly mode suppresses blocking"
                    : "AlertOnly mode enabled",
                RequiresOperatorApproval = false
            },
            DecisionMode.InteractiveBlock when blockRequested && canBlock => new PacketHorn.Core.Models.Decision
            {
                Mode = mode,
                Action = ResponseAction.BlockSourceIP,
                TargetIP = sourceIp,
                Reason = "Rule requested blocking and operator approval is required",
                RequiresOperatorApproval = true
            },
            DecisionMode.AutoBlock when blockRequested && canBlock => new PacketHorn.Core.Models.Decision
            {
                Mode = mode,
                Action = ResponseAction.BlockSourceIP,
                TargetIP = sourceIp,
                Reason = "Rule requested blocking and AutoBlock mode is enabled",
                RequiresOperatorApproval = false
            },
            _ => new PacketHorn.Core.Models.Decision
            {
                Mode = mode,
                Action = alertRequested || blockRequested ? ResponseAction.AlertOnly : ResponseAction.Ignore,
                TargetIP = sourceIp,
                Reason = alertRequested || blockRequested ? "Rule requested alerting only" : "Rule action suppressed the response",
                RequiresOperatorApproval = false
            }
        };
    }
}
