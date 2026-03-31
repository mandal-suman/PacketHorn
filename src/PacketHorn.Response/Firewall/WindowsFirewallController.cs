using System.Diagnostics;
using PacketHorn.Core.Interfaces;

namespace PacketHorn.Response.Firewall;

public class WindowsFirewallController : IFirewallController
{
    private readonly HashSet<string> _blockedIps = new(StringComparer.OrdinalIgnoreCase);

    public bool BlockIP(string ipAddress)
    {
        if (string.IsNullOrWhiteSpace(ipAddress))
            return false;

        if (_blockedIps.Contains(ipAddress))
            return true;

        var inboundRuleName = BuildRuleName(ipAddress, "IN");
        var outboundRuleName = BuildRuleName(ipAddress, "OUT");

        var inResult = RunNetsh($"advfirewall firewall add rule name=\"{inboundRuleName}\" dir=in action=block remoteip={ipAddress}");
        var outResult = RunNetsh($"advfirewall firewall add rule name=\"{outboundRuleName}\" dir=out action=block remoteip={ipAddress}");

        var success = inResult && outResult;
        if (success)
            _blockedIps.Add(ipAddress);

        return success;
    }

    public bool UnblockIP(string ipAddress)
    {
        if (string.IsNullOrWhiteSpace(ipAddress))
            return false;

        var inboundRuleName = BuildRuleName(ipAddress, "IN");
        var outboundRuleName = BuildRuleName(ipAddress, "OUT");

        var inResult = RunNetsh($"advfirewall firewall delete rule name=\"{inboundRuleName}\"");
        var outResult = RunNetsh($"advfirewall firewall delete rule name=\"{outboundRuleName}\"");

        _blockedIps.Remove(ipAddress);
        return inResult && outResult;
    }

    private static string BuildRuleName(string ipAddress, string direction)
    {
        var safeIp = new string(ipAddress.Select(ch => char.IsLetterOrDigit(ch) ? ch : '_').ToArray());
        return $"PacketHorn_Block_{safeIp}_{direction}";
    }

    private static bool RunNetsh(string arguments)
    {
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = arguments,
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                }
            };

            process.Start();
            process.WaitForExit();

            return process.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }
}
