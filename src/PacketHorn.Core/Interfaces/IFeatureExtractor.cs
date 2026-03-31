using PacketHorn.Core.Models;

namespace PacketHorn.Core.Interfaces;

public interface IFeatureExtractor
{
    void ExtractFeatures(StructuredPacket packet);
}
