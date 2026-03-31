using PacketHorn.Core.Enums;

namespace PacketHorn.Core.Configuration;

public sealed class AppConfig
{
    public CaptureConfig Capture { get; init; } = new();
    public DetectionConfig Detection { get; init; } = new();
    public FirewallConfig Firewall { get; init; } = new();
    public UiConfig Ui { get; init; } = new();
    public PathConfig Paths { get; init; } = new();

    public static AppConfig Default => new();
}

public sealed class CaptureConfig
{
    public string Interface { get; set; } = "AUTO";
    public bool Promiscuous { get; set; } = true;
    public int ReadTimeoutMs { get; set; } = 1000;
    public string Filter { get; set; } = string.Empty;
    public int BufferQueueSize { get; set; } = 2000;
}

public sealed class DetectionConfig
{
    public DecisionMode Mode { get; set; } = DecisionMode.AlertOnly;
}

public sealed class FirewallConfig
{
    public int BlockDurationSeconds { get; set; } = 15;
}

public sealed class UiConfig
{
    public bool UseTui { get; set; } = true;
    public int PacketListLimit { get; set; } = 100;
    public int DetectionListLimit { get; set; } = 100;
}

public sealed class PathConfig
{
    public string RulesDirectory { get; set; } = "rules";
    public string LogsDirectory { get; set; } = "logs";
    public string PcapDirectory { get; set; } = "outputs/pcap";
    public string ReportsDirectory { get; set; } = "outputs/reports";
}
