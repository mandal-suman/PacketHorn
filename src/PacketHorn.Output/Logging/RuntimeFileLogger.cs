using System;
using System.IO;
using PacketHorn.Core.Enums;

namespace PacketHorn.Output.Logging;

public sealed class RuntimeFileLogger
{
    private readonly object _sync = new();
    private readonly string _logFilePath;

    public bool VerboseEnabled { get; set; } = true;

    public RuntimeFileLogger(string logsDirectory)
    {
        Directory.CreateDirectory(logsDirectory);
        var timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
        _logFilePath = Path.Combine(logsDirectory, $"packethorn_{timestamp}.log");
    }

    public string LogFilePath => _logFilePath;

    public void Log(LogLevel level, string message)
    {
        if (!VerboseEnabled && level == LogLevel.Debug)
            return;

        var line = $"[{DateTime.UtcNow:O}] [{level}] {message}";
        lock (_sync)
        {
            File.AppendAllText(_logFilePath, line + Environment.NewLine);
        }
    }
}
