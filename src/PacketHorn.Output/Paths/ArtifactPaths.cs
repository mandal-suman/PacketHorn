using System.IO;

namespace PacketHorn.Output.Paths;

public sealed class ArtifactPaths
{
    public string ProjectRoot { get; init; } = string.Empty;
    public string LogsDirectory { get; init; } = string.Empty;
    public string PcapDirectory { get; init; } = string.Empty;
    public string ReportsDirectory { get; init; } = string.Empty;

    public static ArtifactPaths Resolve(string startDirectory)
    {
        var projectRoot = ResolveProjectRoot(startDirectory);
        var logsDir = Path.Combine(projectRoot, "logs");
        var pcapDir = Path.Combine(projectRoot, "outputs", "pcap");
        var reportsDir = Path.Combine(projectRoot, "outputs", "reports");

        Directory.CreateDirectory(logsDir);
        Directory.CreateDirectory(pcapDir);
        Directory.CreateDirectory(reportsDir);

        return new ArtifactPaths
        {
            ProjectRoot = projectRoot,
            LogsDirectory = logsDir,
            PcapDirectory = pcapDir,
            ReportsDirectory = reportsDir
        };
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
