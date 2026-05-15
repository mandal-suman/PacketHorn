using System;

namespace PacketHorn.Platform;

public class PrivilegeChecker
{
    public static bool IsRunningAsAdmin()
    {
        if (!OperatingSystem.IsWindows())
            return false;

        try
        {
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    public static bool HasPacketCapturePrivileges()
    {
        if (OperatingSystem.IsWindows())
            return IsRunningAsAdmin();
        return false;
    }

    public static string GetPrivilegeStatus()
    {
        if (OperatingSystem.IsWindows())
        {
            return IsRunningAsAdmin()
                ? "✓ Running with administrator privileges"
                : "✗ NOT running as administrator (packets may not be captured)";
        }
        return "⚠ Unknown platform privilege status";
    }
}
