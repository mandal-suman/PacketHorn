using System.Collections.Generic;
using PacketHorn.Core.Interfaces;
using PacketHorn.Core.Models;
using PacketHorn.Detection.Evaluators;

namespace PacketHorn.Detection.Engine;

/// <summary>
/// Combined rule engine that evaluates both signature and behavior rules.
/// </summary>
public class RuleEngine : IRuleEngine
{
    private readonly SignatureEvaluator _signatureEvaluator;
    private readonly BehaviorEvaluator _behaviorEvaluator;

    public RuleEngine(SignatureEvaluator signatureEvaluator, BehaviorEvaluator behaviorEvaluator)
    {
        _signatureEvaluator = signatureEvaluator;
        _behaviorEvaluator = behaviorEvaluator;
    }

    /// <summary>
    /// Evaluates a packet against both signature and behavior rules.
    /// </summary>
    public List<DetectionMatch> EvaluatePacket(StructuredPacket packet)
    {
        var matches = new List<DetectionMatch>();

        // Evaluate signature rules
        matches.AddRange(_signatureEvaluator.Evaluate(packet));

        // Evaluate behavior rules
        matches.AddRange(_behaviorEvaluator.Evaluate(packet));

        return matches;
    }

    /// <summary>
    /// Performs cleanup of old behavior state entries.
    /// Call periodically to prevent memory growth.
    /// </summary>
    public void Cleanup()
    {
        _behaviorEvaluator.CleanupOldStates();
    }
}
