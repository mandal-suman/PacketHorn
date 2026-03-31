namespace PacketHorn.Core.Interfaces;

public interface IFirewallController
{
    bool BlockIP(string ipAddress);
    bool UnblockIP(string ipAddress);
}
