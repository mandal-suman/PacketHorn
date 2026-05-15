using System;
using PacketHorn.Core.Interfaces;
using PacketHorn.Core.Models;
using PacketHorn.Core.Enums;

namespace PacketHorn.Processing.Extractors;

public class FeatureExtractor : IFeatureExtractor
{
    public void ExtractFeatures(StructuredPacket packet)
    {
        if (string.IsNullOrEmpty(packet.Flags))
        {
            packet.Flags = "NONE";
        }
    }
}
