using System;
using PacketHorn.Core.Interfaces;
using PacketHorn.Core.Models;
using PacketHorn.Capture.Common;
using SharpPcap;

namespace PacketHorn.Capture.Windows;

public class WindowsCaptureEngine : ICaptureEngine
{
    private ICaptureDevice? _captureDevice;
    private bool _isCapturing;
    private bool _isDeviceOpen;
    private Action<RawPacket>? _onPacketCaptured;
    private ulong _packetCount;
    private readonly bool _promiscuous;
    private readonly int _readTimeoutMs;
    private readonly string _bpfFilter;

    public WindowsCaptureEngine(string? interfaceName = null, bool promiscuous = true, int readTimeoutMs = 1000, string bpfFilter = "")
    {
        _promiscuous = promiscuous;
        _readTimeoutMs = Math.Max(1, readTimeoutMs);
        _bpfFilter = bpfFilter ?? string.Empty;

        _captureDevice = !string.IsNullOrEmpty(interfaceName)
            ? InterfaceEnumerator.GetInterfaceByName(interfaceName)
            : InterfaceEnumerator.GetDefaultInterface();

        if (_captureDevice == null)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[WindowsCaptureEngine] No suitable network interface found.");
            Console.WriteLine("[WindowsCaptureEngine] Available interfaces:");
            Console.ResetColor();
            InterfaceEnumerator.DisplayInterfaces();
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[WindowsCaptureEngine] Selected interface: {_captureDevice.Name}");
            Console.WriteLine($"[WindowsCaptureEngine] Description: {_captureDevice.Description}");
            Console.ResetColor();
        }

        _isDeviceOpen = false;
        _packetCount = 0;
    }

    public void StartCapture(Action<RawPacket> onPacketCaptured)
    {
        if (_captureDevice == null)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[WindowsCaptureEngine] ERROR: No capture device selected. Cannot start capture.");
            Console.ResetColor();
            return;
        }

        _onPacketCaptured = onPacketCaptured;
        _isCapturing = true;
        
        try
        {
            var mode = _promiscuous ? DeviceModes.Promiscuous : DeviceModes.None;
            _captureDevice.Open(mode, _readTimeoutMs);
            _isDeviceOpen = true;

            if (!string.IsNullOrWhiteSpace(_bpfFilter))
                _captureDevice.Filter = _bpfFilter;
            
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"[WindowsCaptureEngine] ✓ Opened interface: {_captureDevice.Name}");
            Console.WriteLine($"[WindowsCaptureEngine] ✓ Starting live packet capture...");
            Console.ResetColor();

            _captureDevice.OnPacketArrival += OnPacketArrivalHandler;
            _captureDevice.StartCapture();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[WindowsCaptureEngine] ERROR starting capture: {ex.Message}");
            Console.ResetColor();
            _isCapturing = false;
        }
    }

    public void StopCapture()
    {
        _isCapturing = false;

        try
        {
            if (_captureDevice != null && _isDeviceOpen)
            {
                _captureDevice.StopCapture();
                _captureDevice.OnPacketArrival -= OnPacketArrivalHandler;
                _captureDevice.Close();
                _isDeviceOpen = false;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[WindowsCaptureEngine] Error stopping capture: {ex.Message}");
        }

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"[WindowsCaptureEngine] ✓ Capture stopped. (Captured {_packetCount} packets)");
        Console.ResetColor();
    }

    private void OnPacketArrivalHandler(object sender, PacketCapture e)
    {
        if (!_isCapturing || _onPacketCaptured == null)
            return;

        try
        {
            byte[] packetData = e.Data.ToArray();
            
            var rawPacket = new RawPacket
            {
                Data = packetData,
                Timestamp = DateTime.UtcNow,
                Length = packetData.Length
            };

            _packetCount++;
            _onPacketCaptured.Invoke(rawPacket);
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[WindowsCaptureEngine] Error processing packet: {ex.Message}");
            Console.ResetColor();
        }
    }
}
