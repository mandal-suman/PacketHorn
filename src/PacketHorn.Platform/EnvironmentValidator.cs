using System;
namespace PacketHorn.Platform;

public class EnvironmentValidator
{
    public static bool ValidateEnvironment(out List<string> warnings, out List<string> errors)
    {
        warnings = new();
        errors = new();

        var os = PlatformDetector.DetectOS();

        if (os == PlatformDetector.OS.Unknown)
        {
            errors.Add("Unknown or unsupported operating system");
            return false;
        }

        if (!PrivilegeChecker.HasPacketCapturePrivileges())
        {
            warnings.Add(PrivilegeChecker.GetPrivilegeStatus());
        }

        if (os == PlatformDetector.OS.Windows)
        {
            ValidateWindowsEnvironment(warnings, errors);
        }
        return errors.Count == 0;
    }

    private static void ValidateWindowsEnvironment(List<string> warnings, List<string> errors)
    {
        string npcapPath = @"C:\Windows\System32\Npcap";
        if (!Directory.Exists(npcapPath))
        {
            warnings.Add("Npcap may not be installed at the standard location");
            warnings.Add("Ensure Npcap is installed from: https://npcap.com/");
        }
        else
        {
            string npcapDll = Path.Combine(npcapPath, "wpcap.dll");
            if (!File.Exists(npcapDll))
            {
                warnings.Add("Npcap DLL (wpcap.dll) not found at standard location");
            }
        }
    }

    public static string GetValidationReport()
    {
        var result = $"═══════════════════════════════════════════════════════════════\n";
        result += $"  PacketHorn - System Validation Report\n";
        result += $"═══════════════════════════════════════════════════════════════\n\n";

        result += $"Platform: {PlatformDetector.GetOSName()} ({PlatformDetector.GetArchitecture()})\n";
        result += $"Version:  {PlatformDetector.GetOSVersion()}\n";
        result += $"Privilege: {PrivilegeChecker.GetPrivilegeStatus()}\n\n";

        if (ValidateEnvironment(out var warnings, out var errors))
        {
            result += $"✓ Validation PASSED\n";
        }
        else
        {
            result += $"✗ Validation FAILED\n";
        }

        if (warnings.Count > 0)
        {
            result += $"\nWarnings:\n";
            foreach (var warning in warnings)
            {
                result += $"  ⚠ {warning}\n";
            }
        }

        if (errors.Count > 0)
        {
            result += $"\nErrors:\n";
            foreach (var error in errors)
            {
                result += $"  ✗ {error}\n";
            }
        }

        result += $"\n═══════════════════════════════════════════════════════════════\n";
        return result;
    }
}
