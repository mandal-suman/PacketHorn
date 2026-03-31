using System;

namespace PacketHorn.Core.Interfaces;

public interface ICaptureEngine
{
    void StartCapture(Action<Models.RawPacket> onPacketCaptured);
    void StopCapture();
}
