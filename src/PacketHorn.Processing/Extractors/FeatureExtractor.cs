using System;
using PacketHorn.Core.Interfaces;
using PacketHorn.Core.Models;
using PacketHorn.Core.Enums;

namespace PacketHorn.Processing.Extractors;

public class FeatureExtractor : IFeatureExtractor
{
    public void ExtractFeatures(StructuredPacket packet)
    {
        // E.g., entropy calculation, payload size analysis. Place holder implementation for Phase 4.
        if (string.IsNullOrEmpty(packet.Flags))
        {
            packet.Flags = "NONE";
        }
    }
}
