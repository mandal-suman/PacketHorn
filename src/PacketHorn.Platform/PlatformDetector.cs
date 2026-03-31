using System;

namespace PacketHorn.Platform;

/// <summary>
/// Detects the operating system and platform information.
/// </summary>
public class PlatformDetector
{
    /// <summary>
    /// Supported operating systems.
    /// </summary>
    public enum OS
    {
        Windows,
        Unknown
    }

    /// <summary>
    /// Detects the current operating system.
    /// </summary>
    public static OS DetectOS()
    {
        if (OperatingSystem.IsWindows())
            return OS.Windows;
        return OS.Unknown;
    }

    /// <summary>
    /// Gets the OS name as string.
    /// </summary>
    public static string GetOSName()
    {
        return DetectOS() switch
        {
            OS.Windows => "Windows",
            _ => "Unknown"
        };
    }

    /// <summary>
    /// Gets the current system architecture.
    /// </summary>
    public static string GetArchitecture()
    {
        return System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString();
    }

    /// <summary>
    /// Gets OS version information (if available).
    /// </summary>
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
