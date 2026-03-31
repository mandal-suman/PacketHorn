using System;

namespace PacketHorn.Platform;

/// <summary>
/// Checks for administrative/root privileges.
/// </summary>
public class PrivilegeChecker
{
    /// <summary>
    /// Checks if the current process is running with administrator privileges (Windows).
    /// </summary>
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

    /// <summary>
    /// Checks if the current process has necessary privileges for packet capture.
    /// </summary>
    public static bool HasPacketCapturePrivileges()
    {
        if (OperatingSystem.IsWindows())
            return IsRunningAsAdmin();
        return false;
    }

    /// <summary>
    /// Gets a privilege summary message.
    /// </summary>
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
