using System;
using System.Collections.Generic;
using PacketHorn.Core.Interfaces;
using PacketHorn.Core.Models;
using PacketHorn.Core.Utilities;

namespace PacketHorn.Core.Pipeline;

public class PacketPipeline
{
    private readonly ICaptureEngine _captureEngine;
    private readonly BufferQueue<RawPacket> _ingressQueue;
    private readonly IStructuredPacketBuilder _packetBuilder;
    private readonly IRuleEngine? _ruleEngine;

    public PacketPipeline(ICaptureEngine captureEngine, BufferQueue<RawPacket> ingressQueue, IStructuredPacketBuilder packetBuilder, IRuleEngine? ruleEngine = null)
    {
        _captureEngine = captureEngine;
        _ingressQueue = ingressQueue;
        _packetBuilder = packetBuilder;
        _ruleEngine = ruleEngine;
    }

    public event EventHandler<DetectionEventArgs>? OnDetection;
    public event EventHandler<RawPacketEventArgs>? OnRawPacket;
    public event EventHandler<StructuredPacketEventArgs>? OnStructuredPacket;

    public void Start()
    {
        _captureEngine.StartCapture(OnPacketCaptured);
    }

    public void Stop()
    {
        _captureEngine.StopCapture();
        _ingressQueue.CompleteAdding();
    }

    private void OnPacketCaptured(RawPacket packet)
    {
        OnRawPacket?.Invoke(this, new RawPacketEventArgs { Packet = packet });
        _ingressQueue.Enqueue(packet);
    }

    public void ProcessNextPacket()
    {
        if (_ingressQueue.TryTake(out var rawPacket, 100))
        {
            var structuredPacket = _packetBuilder.Build(rawPacket);
            if (structuredPacket != null)
            {
                OnStructuredPacket?.Invoke(this, new StructuredPacketEventArgs { Packet = structuredPacket });

                // Evaluate rules if engine is configured
                if (_ruleEngine != null)
                {
                    var detections = _ruleEngine.EvaluatePacket(structuredPacket);
                    if (detections.Count > 0)
                    {
                        foreach (var detection in detections)
                        {
                            OnDetection?.Invoke(this, new DetectionEventArgs { Detection = detection });
                        }
                    }
                }
            }
        }
    }
}

/// <summary>
/// Event args for detection matches.
/// </summary>
public class DetectionEventArgs : EventArgs
{
    public DetectionMatch? Detection { get; set; }
}

public class RawPacketEventArgs : EventArgs
{
    public RawPacket? Packet { get; set; }
}

public class StructuredPacketEventArgs : EventArgs
{
    public StructuredPacket? Packet { get; set; }
}
