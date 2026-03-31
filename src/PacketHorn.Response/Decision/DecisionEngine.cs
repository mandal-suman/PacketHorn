using PacketHorn.Core.Enums;
using PacketHorn.Core.Interfaces;
using PacketHorn.Core.Models;

namespace PacketHorn.Response.Decision;

public class DecisionEngine : IDecisionEngine
{
    public PacketHorn.Core.Models.Decision Evaluate(DetectionResult detectionResult, DecisionMode mode)
    {
        var sourceIp = detectionResult.SourceIP;
        var shouldBlock = detectionResult.SeverityLevel >= SeverityLevel.High && !string.IsNullOrWhiteSpace(sourceIp);

        return mode switch
        {
            DecisionMode.AlertOnly => new PacketHorn.Core.Models.Decision
            {
                Mode = mode,
                Action = ResponseAction.AlertOnly,
                TargetIP = sourceIp,
                Reason = "AlertOnly mode enabled",
                RequiresOperatorApproval = false
            },
            DecisionMode.InteractiveBlock when shouldBlock => new PacketHorn.Core.Models.Decision
            {
                Mode = mode,
                Action = ResponseAction.BlockSourceIP,
                TargetIP = sourceIp,
                Reason = "High severity threat requires operator approval",
                RequiresOperatorApproval = true
            },
            DecisionMode.AutoBlock when shouldBlock => new PacketHorn.Core.Models.Decision
            {
                Mode = mode,
                Action = ResponseAction.BlockSourceIP,
                TargetIP = sourceIp,
                Reason = "AutoBlock mode and severity threshold met",
                RequiresOperatorApproval = false
            },
            _ => new PacketHorn.Core.Models.Decision
            {
                Mode = mode,
                Action = ResponseAction.AlertOnly,
                TargetIP = sourceIp,
                Reason = "Threat below block threshold",
                RequiresOperatorApproval = false
            }
        };
    }
}
