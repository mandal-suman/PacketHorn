using System;

namespace PacketHorn.Platform;

public class PlatformDetector
{
    public enum OS
    {
        Windows,
        Unknown
    }

    public static OS DetectOS()
    {
        if (OperatingSystem.IsWindows())
            return OS.Windows;
        return OS.Unknown;
    }

    public static string GetOSName()
    {
        return DetectOS() switch
        {
            OS.Windows => "Windows",
            _ => "Unknown"
        };
    }

    public static string GetArchitecture()
    {
        return System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString();
    }

    public static string GetOSVersion()
    {
        try
        {
            if (OperatingSystem.IsWindows())
                return Environment.OSVersion.VersionString;
        }
        catch { }
        return "Unknown";
    }
}
