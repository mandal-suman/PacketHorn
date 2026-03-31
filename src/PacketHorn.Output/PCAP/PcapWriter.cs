using System;
using System.IO;
using PacketHorn.Core.Models;

namespace PacketHorn.Output.PCAP;

public sealed class PcapWriter : IDisposable
{
    private readonly object _sync = new();
    private readonly FileStream _stream;
    private readonly BinaryWriter _writer;
    private bool _disposed;

    public PcapWriter(string filePath)
    {
        var directory = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrWhiteSpace(directory))
            Directory.CreateDirectory(directory);

        _stream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.Read);
        _writer = new BinaryWriter(_stream);
        WriteGlobalHeader();
    }

    public void WritePacket(RawPacket packet)
    {
        if (_disposed || packet.Data.Length == 0)
            return;

        var timestamp = packet.Timestamp == default ? DateTime.UtcNow : packet.Timestamp;
        var seconds = new DateTimeOffset(timestamp).ToUnixTimeSeconds();
        var micros = (int)((timestamp.Ticks % TimeSpan.TicksPerSecond) / 10);
        var length = packet.Length > 0 ? packet.Length : packet.Data.Length;

        lock (_sync)
        {
            _writer.Write((uint)seconds);
            _writer.Write((uint)micros);
            _writer.Write((uint)length);
            _writer.Write((uint)length);
            _writer.Write(packet.Data, 0, Math.Min(length, packet.Data.Length));
        }
    }

    private void WriteGlobalHeader()
    {
        _writer.Write(0xa1b2c3d4u);
        _writer.Write((ushort)2);
        _writer.Write((ushort)4);
        _writer.Write(0);
        _writer.Write(0u);
        _writer.Write(65535u);
        _writer.Write(1u);
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        _writer.Dispose();
        _stream.Dispose();
    }
}
