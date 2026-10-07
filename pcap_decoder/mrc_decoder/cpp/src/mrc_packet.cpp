#include "mrc_decoder/mrc_packet.hpp"

namespace mrc {
namespace {
uint32_t read_be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |
           (static_cast<uint32_t>(p[3]));
}
uint16_t read_be16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}
}  // namespace

std::optional<MrcPacket> parse_mrc(const uint8_t* data, size_t len) {
    if (data == nullptr || len < kHeaderSize) {
        return std::nullopt;
    }
    MrcPacket pkt;
    pkt.identifier = read_be32(data + kIdOffset);
    pkt.length     = read_be32(data + kLenOffset);
    pkt.type       = static_cast<PacketType>(read_be16(data + kPktTypeOffset));
    pkt.flags      = read_be16(data + kCtrlFlagsOffset);
    pkt.payload    = data + kPayloadOffset;
    pkt.payload_len = len - kPayloadOffset;
    return pkt;
}

}  // namespace mrc
