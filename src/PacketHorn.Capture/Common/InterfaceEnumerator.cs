using System;
using System.Collections.Generic;
using System.Linq;
using SharpPcap;

namespace PacketHorn.Capture.Common;

public static class InterfaceEnumerator
{
    public static IReadOnlyList<ICaptureDevice> GetDevices()
    {
        try
        {
            return CaptureDeviceList.Instance.ToList();
        }
        catch
        {
            return Array.Empty<ICaptureDevice>();
        }
    }

    public static List<(string Name, string Description)> GetAvailableInterfaces()
    {
        var interfaces = new List<(string, string)>();

        try
        {
            var devices = CaptureDeviceList.Instance;

            if (devices.Count == 0)
            {
                Console.WriteLine("WARNING: No network interfaces found for packet capture.");
                Console.WriteLine("Please ensure Npcap is installed and network interfaces are available.");
                return interfaces;
            }

            foreach (var device in devices)
            {
                interfaces.Add((device.Name, device.Description ?? "Unknown"));
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"ERROR: Failed to enumerate interfaces: {ex.Message}");
        }

        return interfaces;
    }

    public static ICaptureDevice? GetDefaultInterface()
    {
        try
        {
            var devices = CaptureDeviceList.Instance;
            return devices
                .Where(d => d != null)
                .OrderBy(d => d.Name.Contains("loopback", StringComparison.OrdinalIgnoreCase) ? 1 : 0)
                .FirstOrDefault();
        }
        catch
        {
            return null;
        }
    }

    public static ICaptureDevice? GetInterfaceByName(string interfaceName)
    {
        try
        {
            var devices = CaptureDeviceList.Instance;

            if (int.TryParse(interfaceName, out var index))
            {
                if (index >= 0 && index < devices.Count)
                    return devices[index];
            }

            return devices.FirstOrDefault(d =>
                d.Name.Equals(interfaceName, StringComparison.OrdinalIgnoreCase)
                || (d.Description?.Equals(interfaceName, StringComparison.OrdinalIgnoreCase) ?? false)
                || d.Name.Contains(interfaceName, StringComparison.OrdinalIgnoreCase)
                || (d.Description?.Contains(interfaceName, StringComparison.OrdinalIgnoreCase) ?? false));
        }
        catch
        {
            return null;
        }
    }

    public static void DisplayInterfaces()
    {
        Console.WriteLine("\n═══════════════════════════════════════════════════════════");
        Console.WriteLine("  Available Network Interfaces");
        Console.WriteLine("═══════════════════════════════════════════════════════════");

        var interfaces = GetAvailableInterfaces();
        
        if (interfaces.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  WARNING: No interfaces found!");
            Console.ResetColor();
            return;
        }

        for (int i = 0; i < interfaces.Count; i++)
        {
            var (name, description) = interfaces[i];
            Console.WriteLine($"  [{i}] {name}");
            Console.WriteLine($"      {description}");
        }

        Console.WriteLine("═══════════════════════════════════════════════════════════\n");
    }
}
