using System.Collections.Generic;
using PacketHorn.Core.Interfaces;
using PacketHorn.Core.Models;
using PacketHorn.Detection.Evaluators;

namespace PacketHorn.Detection.Engine;

public class RuleEngine : IRuleEngine
{
    private readonly SignatureEvaluator _signatureEvaluator;
    private readonly BehaviorEvaluator _behaviorEvaluator;

    public RuleEngine(SignatureEvaluator signatureEvaluator, BehaviorEvaluator behaviorEvaluator)
    {
        _signatureEvaluator = signatureEvaluator;
        _behaviorEvaluator = behaviorEvaluator;
    }

    public List<DetectionMatch> EvaluatePacket(StructuredPacket packet)
    {
        var matches = new List<DetectionMatch>();
        matches.AddRange(_signatureEvaluator.Evaluate(packet));
        matches.AddRange(_behaviorEvaluator.Evaluate(packet));
        return matches;
    }

    public void Cleanup()
    {
        _behaviorEvaluator.CleanupOldStates();
    }
}
