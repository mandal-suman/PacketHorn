using PacketHorn.Core.Enums;
using PacketHorn.Core.Interfaces;
using PacketHorn.Core.Models;

namespace PacketHorn.Response.Engine;

public class WindowsResponseEngine : IResponseEngine
{
    private readonly IFirewallController _firewallController;
    private readonly int _blockDurationSeconds;
    private readonly Func<string, string, bool>? _approvalCallback;
    private readonly Action<string>? _log;

    public WindowsResponseEngine(
        IFirewallController firewallController,
        int blockDurationSeconds = 15,
        Func<string, string, bool>? approvalCallback = null,
        Action<string>? log = null)
    {
        _firewallController = firewallController;
        _blockDurationSeconds = 15;
        _approvalCallback = approvalCallback;
        _log = log;
    }

    public void ProcessDecision(PacketHorn.Core.Models.Decision decision, DetectionResult detectionResult)
    {
        switch (decision.Action)
        {
            case ResponseAction.BlockSourceIP:
            {
                if (decision.RequiresOperatorApproval)
                {
                    var approved = _approvalCallback?.Invoke(decision.TargetIP, decision.Reason) ?? false;
                    if (!approved)
                    {
                        _log?.Invoke("[RESPONSE] Block canceled by operator.");
                        return;
                    }
                }

                var blocked = _firewallController.BlockIP(decision.TargetIP);
                _log?.Invoke(blocked
                    ? $"[RESPONSE] Blocked IP {decision.TargetIP} for {detectionResult.ThreatType} (TTL {_blockDurationSeconds}s)"
                    : $"[RESPONSE] Failed to block IP {decision.TargetIP}");

                if (blocked)
                {
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            await Task.Delay(TimeSpan.FromSeconds(_blockDurationSeconds));
                            var unblocked = _firewallController.UnblockIP(decision.TargetIP);
                            _log?.Invoke(unblocked
                                ? $"[RESPONSE] Auto-unblocked IP {decision.TargetIP} after {_blockDurationSeconds}s"
                                : $"[RESPONSE] Failed to auto-unblock IP {decision.TargetIP}");
                        }
                        catch (Exception ex)
                        {
                            _log?.Invoke($"[RESPONSE] Unblock timer error: {ex.Message}");
                        }
                    });
                }
                break;
            }
            case ResponseAction.AlertOnly:
                _log?.Invoke($"[RESPONSE] Alert logged for {detectionResult.ThreatType} from {detectionResult.SourceIP}");
                break;
            default:
                break;
        }
    }
}
