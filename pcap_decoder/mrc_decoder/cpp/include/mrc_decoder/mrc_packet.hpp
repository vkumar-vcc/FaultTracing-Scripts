// MRC packet parsing — layout per mrc_decoder-spec/assets/dissector.lua (MRC v0.4.9).
#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>

namespace mrc {

// MRC packet-type values (UDP payload, big-endian header).
enum class PacketType : uint16_t {
    Reserved      = 0x0000,
    LinData       = 0x0001,
    CanBaseData   = 0x0002,
    CanExtData    = 0x0003,
    BusCtlReqResp = 0x0004,
    BusCtlIndCfm  = 0x0005,
    ViuCtlIndCfm  = 0xFFFE,
    ViuCtlReqResp = 0xFFFF,
};

// Header field offsets/sizes (bytes) inside the UDP payload.
inline constexpr size_t kIdOffset       = 0;   // Identifier (frame id), 4 bytes
inline constexpr size_t kLenOffset      = 4;   // Length, 4 bytes
inline constexpr size_t kPktTypeOffset  = 8;   // Packet type, 2 bytes
inline constexpr size_t kCtrlFlagsOffset= 10;  // Flags, 2 bytes
inline constexpr size_t kPayloadOffset  = 12;  // Frame payload begins here
inline constexpr size_t kHeaderSize     = 12;

struct MrcPacket {
    uint32_t identifier = 0;    // frame identifier (CAN 11/29-bit or LIN id)
    uint32_t length     = 0;    // payload + 4 (packet type + flags)
    PacketType type     = PacketType::Reserved;
    uint16_t flags      = 0;
    const uint8_t* payload = nullptr;  // points into the source buffer
    size_t payload_len  = 0;

    bool is_data() const {
        return type == PacketType::LinData ||
               type == PacketType::CanBaseData ||
               type == PacketType::CanExtData;
    }
};

// Parse one MRC packet from a UDP payload. Returns nullopt if too short / malformed.
std::optional<MrcPacket> parse_mrc(const uint8_t* data, size_t len);

}  // namespace mrc
