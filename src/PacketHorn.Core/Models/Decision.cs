using PacketHorn.Core.Enums;

namespace PacketHorn.Core.Models;

public class Decision
{
    public DecisionMode Mode { get; set; }
    public ResponseAction Action { get; set; }
    public string TargetIP { get; set; } = string.Empty;
    public string Reason { get; set; } = string.Empty;
    public bool RequiresOperatorApproval { get; set; }
}
