// Decode model: parses SDB (AUTOSAR ARXML) into per-PDU signal layouts + Ethernet routing,
// then decodes MRC (ETH) and SOME/IP PDU payloads into signal samples.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace mrc {

// A single decoded signal sample.
struct SignalSample {
    double timestamp = 0.0;
    double value     = 0.0;
    uint32_t signal_index = 0;
};

// Static metadata for a signal (channel).
struct SignalInfo {
    std::string signal_group;   // MDF channel group (PDU short name)
    std::string signal_name;    // MDF channel (system-signal short name)
};

// One signal's bit layout + linear encoding within a PDU.
struct SignalLayout {
    uint32_t signal_index = 0;
    uint32_t start_bit    = 0;     // AUTOSAR START-POSITION
    uint32_t bit_length   = 0;     // I-SIGNAL LENGTH (bits)
    bool     big_endian   = false; // PACKING-BYTE-ORDER = MOST-SIGNIFICANT-BYTE-FIRST
    bool     is_signed    = false;
    double   factor       = 1.0;   // phys = raw * factor + offset
    double   offset       = 0.0;
};

// A PDU's decodable layout.
struct PduLayout {
    std::string name;
    uint32_t byte_length = 0;
    std::vector<SignalLayout> signals;
};

class DecodeModel {
public:
    // Parse a consolidated ARXML directory (or a single .arxml file) into `out`.
    static bool load_from_arxml(const std::string& arxml_path,
                                DecodeModel& out,
                                std::string& error);

    // Load Wireshark Signal-PDU dissector tables (SPA3 PDU_SPA3 directory) for the
    // Ethernet PDU-transport path: Signal_PDU_identifiers_ETH / _Binding_ / _signal_list_ETH
    // + decode_as_entries. Populates transport-id routing, signals, and PDU udp ports.
    bool load_pdu_tables(const std::string& dir, std::string& error);

    // ETH lookup key: (ip << 32) | (port << 16) | (frame_id & 0xFFFF).
    static uint64_t eth_key(uint32_t ip, uint16_t port, uint32_t frame_id) {
        return (static_cast<uint64_t>(ip) << 32) |
               (static_cast<uint64_t>(port) << 16) |
               (frame_id & 0xFFFFu);
    }

    bool is_pdu_port(uint16_t port) const { return pdu_ports_.count(port) != 0; }

    // Decode an MRC/CAN-over-Ethernet frame. Tries the exact eth key, then falls back
    // to matching by frame id alone until full topology routing is validated.
    void decode_eth(uint64_t key, const uint8_t* data, size_t len,
                    double ts, std::vector<SignalSample>& out) const;

    // Decode a UDP payload carrying one or more concatenated PDU-transport PDUs, each
    // framed as [transport_id u32-BE][length u32-BE][payload]. Loops until exhausted.
    void decode_pdu_stream(const uint8_t* payload, size_t len, double ts,
                           std::vector<SignalSample>& out) const;

    const SignalInfo* signal(uint32_t index) const;
    size_t signal_count() const { return signals_.size(); }
    size_t pdu_count() const { return pdus_.size(); }

    // --- test / advanced access ---
    // Decode a specific PDU layout against a payload; bit extraction + linear scaling.
    static void decode_pdu_layout(const PduLayout& pdu, const uint8_t* data, size_t len,
                                  double ts, std::vector<SignalSample>& out);
    const PduLayout* pdu_by_name(const std::string& name) const;

private:
    void register_signal(uint32_t index, const std::string& group, const std::string& name);

    std::unordered_map<uint32_t, SignalInfo> signals_;   // signal_index -> metadata
    std::vector<PduLayout> pdus_;                         // all decodable PDUs
    std::unordered_map<std::string, size_t> pdu_index_by_name_;
    std::unordered_map<uint64_t, size_t> pdu_by_eth_key_; // eth_key -> pdus_ index
    std::unordered_map<uint32_t, size_t> pdu_by_frame_id_;// frame_id(16b) -> pdus_ index
    std::unordered_map<uint32_t, size_t> pdu_by_transport_;// SOME/IP port -> pdus_ index
    std::unordered_set<uint16_t> pdu_ports_;
};

}  // namespace mrc
