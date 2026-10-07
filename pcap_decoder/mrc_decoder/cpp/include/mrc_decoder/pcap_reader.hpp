// Offline PCAP reader: yields UDP datagrams with capture timestamps.
#pragma once

#include <cstdint>
#include <functional>
#include <string>

namespace mrc {

// One decoded UDP datagram from the capture.
struct UdpDatagram {
    double   ts_seconds = 0.0;   // capture timestamp (seconds, from PCAP)
    uint32_t src_ip     = 0;     // source IPv4, host byte order
    uint32_t dst_ip     = 0;     // destination IPv4, host byte order
    uint16_t src_port   = 0;     // source UDP port, host byte order
    uint16_t dst_port   = 0;     // destination UDP port, host byte order
    const uint8_t* payload = nullptr;
    uint32_t payload_len = 0;
    const uint8_t* packet = nullptr;
    uint32_t packet_len = 0;
};

// One TCP segment (payload-bearing) from the capture. `seq` is the TCP sequence
// number of the first payload byte (host byte order); used for stream reassembly.
struct TcpSegment {
    double   ts_seconds = 0.0;
    uint32_t src_ip     = 0;
    uint32_t dst_ip     = 0;
    uint16_t src_port   = 0;
    uint16_t dst_port   = 0;
    uint32_t seq        = 0;
    const uint8_t* payload = nullptr;
    uint32_t payload_len = 0;
};

// Reads a .pcap/.pcapng file and invokes `on_datagram` for each UDP packet.
// Returns false (and sets `error`) if the file cannot be opened.
// Non-UDP / malformed packets are skipped. VLAN (802.1Q) tags are handled.
// `max_datagrams` > 0 stops after that many UDP datagrams (0 = read all).
bool read_pcap(const std::string& path,
               const std::function<void(const UdpDatagram&)>& on_datagram,
               std::string& error,
               uint64_t max_datagrams = 0);

// Single pass that dispatches both UDP datagrams and TCP segments. Either callback
// may be empty. `max_packets` > 0 stops after that many L4 packets (0 = read all).
bool read_pcap_l4(const std::string& path,
                  const std::function<void(const UdpDatagram&)>& on_udp,
                  const std::function<void(const TcpSegment&)>& on_tcp,
                  std::string& error,
                  uint64_t max_packets = 0);

}  // namespace mrc
