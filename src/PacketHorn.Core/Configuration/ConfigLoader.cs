using System.Globalization;
using PacketHorn.Core.Enums;

namespace PacketHorn.Core.Configuration;

public static class ConfigLoader
{
    public static AppConfig Load(string configPath)
    {
        var cfg = AppConfig.Default;
        if (!File.Exists(configPath))
            return cfg;

        foreach (var raw in File.ReadAllLines(configPath))
        {
            var line = raw.Trim();
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                continue;

            var idx = line.IndexOf('=');
            if (idx <= 0)
                continue;

            var key = line[..idx].Trim().ToLowerInvariant();
            var value = line[(idx + 1)..].Trim();
            Apply(cfg, key, value);
        }

        if (cfg.Firewall.BlockDurationSeconds != 15)
            cfg.Firewall.BlockDurationSeconds = 15;

        return cfg;
    }

    public static string ToText(AppConfig cfg)
    {
        return string.Join(Environment.NewLine, new[]
        {
            "# PacketHorn Configuration",
            "# All major runtime settings are controlled here.",
            "",
            "capture.interface=AUTO",
            $"capture.promiscuous={cfg.Capture.Promiscuous.ToString().ToLowerInvariant()}",
            $"capture.read_timeout_ms={cfg.Capture.ReadTimeoutMs}",
            $"capture.filter={cfg.Capture.Filter}",
            $"capture.buffer_queue_size={cfg.Capture.BufferQueueSize}",
            "",
            $"detection.mode={cfg.Detection.Mode}",
            "",
            "# Requirement: firewall block must be 15 seconds",
            "firewall.block_duration_sec=15",
            "",
            $"ui.use_tui={cfg.Ui.UseTui.ToString().ToLowerInvariant()}",
            $"ui.packet_list_limit={cfg.Ui.PacketListLimit}",
            $"ui.detection_list_limit={cfg.Ui.DetectionListLimit}",
            "",
            $"paths.rules_dir={cfg.Paths.RulesDirectory}",
            $"paths.logs_dir={cfg.Paths.LogsDirectory}",
            $"paths.pcap_dir={cfg.Paths.PcapDirectory}",
            $"paths.reports_dir={cfg.Paths.ReportsDirectory}"
        });
    }

    public static void EnsureDefaultFile(string configPath)
    {
        var dir = Path.GetDirectoryName(configPath);
        if (!string.IsNullOrWhiteSpace(dir))
            Directory.CreateDirectory(dir);

        var fi = new FileInfo(configPath);
        if (!fi.Exists || fi.Length == 0)
            File.WriteAllText(configPath, ToText(AppConfig.Default));
    }

    private static void Apply(AppConfig cfg, string key, string value)
    {
        switch (key)
        {
            case "capture.interface":
                cfg.Capture.Interface = value;
                break;
            case "capture.promiscuous":
                if (bool.TryParse(value, out var prom)) cfg.Capture.Promiscuous = prom;
                break;
            case "capture.read_timeout_ms":
                if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var timeout))
                    cfg.Capture.ReadTimeoutMs = Math.Max(1, timeout);
                break;
            case "capture.filter":
                cfg.Capture.Filter = value;
                break;
            case "capture.buffer_queue_size":
                if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var q))
                    cfg.Capture.BufferQueueSize = Math.Max(100, q);
                break;
            case "detection.mode":
                if (Enum.TryParse<DecisionMode>(value, true, out var mode))
                    cfg.Detection.Mode = mode;
                break;
            case "firewall.block_duration_sec":
                if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var secs))
                    cfg.Firewall.BlockDurationSeconds = secs;
                break;
            case "ui.use_tui":
                if (bool.TryParse(value, out var useTui)) cfg.Ui.UseTui = useTui;
                break;
            case "ui.packet_list_limit":
                if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var p)) cfg.Ui.PacketListLimit = Math.Max(10, p);
                break;
            case "ui.detection_list_limit":
                if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var d)) cfg.Ui.DetectionListLimit = Math.Max(10, d);
                break;
            case "paths.rules_dir":
                cfg.Paths.RulesDirectory = value;
                break;
            case "paths.logs_dir":
                cfg.Paths.LogsDirectory = value;
                break;
            case "paths.pcap_dir":
                cfg.Paths.PcapDirectory = value;
                break;
            case "paths.reports_dir":
                cfg.Paths.ReportsDirectory = value;
                break;
        }
    }
}
