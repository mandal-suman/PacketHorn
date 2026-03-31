using PacketHorn.CLI.Tui;
using PacketHorn.Core.Configuration;
using PacketHorn.Platform;

namespace PacketHorn.CLI;

public static class Program
{
    public static void Main()
    {
        var projectRoot = ResolveProjectRoot(AppDomain.CurrentDomain.BaseDirectory);
        var configPath = Path.Combine(projectRoot, "config", "packethorn.conf");

        ConfigLoader.EnsureDefaultFile(configPath);
        var config = ConfigLoader.Load(configPath);

        Console.WriteLine(EnvironmentValidator.GetValidationReport());
        if (!EnvironmentValidator.ValidateEnvironment(out _, out _))
        {
            Console.WriteLine("System validation failed. Run as administrator and verify Npcap installation.");
            return;
        }

        var app = new TerminalDashboardApp(projectRoot, config);
        app.Run();
    }

    private static string ResolveProjectRoot(string startDirectory)
    {
        var current = new DirectoryInfo(startDirectory);
        while (current != null)
        {
            var hasMarker = File.Exists(Path.Combine(current.FullName, "PacketHorn.slnx"))
                || File.Exists(Path.Combine(current.FullName, "INSTRUCTIONS.md"));

            if (hasMarker)
                return current.FullName;

            current = current.Parent;
        }

        return startDirectory;
    }
}
