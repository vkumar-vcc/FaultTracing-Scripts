#include "mrc_decoder/pcap_reader.hpp"

#include <pcap.h>

#include <cstring>
#include <limits>

namespace mrc {
namespace {

constexpr uint16_t kEthTypeIpv4 = 0x0800;
constexpr uint16_t kEthType8021Q = 0x8100;
constexpr uint16_t kEthTypeTechnica = 0x99FE;  // Technica capture-module wrapper
constexpr uint8_t  kIpProtoUdp = 17;
constexpr uint8_t  kIpProtoTcp = 6;
constexpr uint32_t kNoOffset = std::numeric_limits<uint32_t>::max();

// Link-layer types we handle (values from libpcap DLT_*).
constexpr int kDltNull      = 0;
constexpr int kDltEn10mb    = 1;
constexpr int kDltRawBsd    = 12;
constexpr int kDltRawLinux  = 101;
constexpr int kDltLinuxSll  = 113;
constexpr int kDltLinuxSll2 = 276;

uint16_t be16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
uint32_t be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

// Return the byte offset of the IPv4 header for the given link type, or kNoOffset
// if the frame is not IPv4 / too short.
uint32_t ipv4_offset(int dlt, const uint8_t* pkt, uint32_t caplen) {
    switch (dlt) {
        case kDltEn10mb: {
            if (caplen < 14) return kNoOffset;
            uint16_t et = be16(pkt + 12);
            uint32_t off = 14;
            // Technica capture-module wrapper (EtherType 0x99FE): the original
            // (VLAN-tagged) IPv4 frame follows a variable-length Technica header.
            // Scan forward to the inner IPv4 EtherType + version nibble.
            if (et == kEthTypeTechnica) {
                for (uint32_t i = 14; i + 3 < caplen && i < 128; ++i) {
                    if (pkt[i] == 0x08 && pkt[i + 1] == 0x00 &&
                        (pkt[i + 2] & 0xF0) == 0x40)
                        return i + 2;
                }
                return kNoOffset;
            }
            while (et == kEthType8021Q) {           // strip VLAN tags
                if (caplen < off + 4) return kNoOffset;
                et = be16(pkt + off + 2);
                off += 4;
            }
            return et == kEthTypeIpv4 ? off : kNoOffset;
        }
        case kDltLinuxSll: {                          // cooked capture (tcpdump -i any)
            if (caplen < 16) return kNoOffset;
            return be16(pkt + 14) == kEthTypeIpv4 ? 16u : kNoOffset;
        }
        case kDltLinuxSll2: {
            if (caplen < 20) return kNoOffset;
            return be16(pkt + 0) == kEthTypeIpv4 ? 20u : kNoOffset;
        }
        case kDltRawBsd:
        case kDltRawLinux: {
            if (caplen < 20) return kNoOffset;
            return (pkt[0] >> 4) == 4 ? 0u : kNoOffset;  // IPv4 version nibble
        }
        case kDltNull: {                              // loopback: 4-byte address family
            if (caplen < 24) return kNoOffset;
            return (pkt[4] >> 4) == 4 ? 4u : kNoOffset;
        }
        default:
            return kNoOffset;
    }
}

// Parse IPv4 -> UDP starting at `off`. Fills `out`, returns true if a UDP datagram.
bool parse_udp(const uint8_t* pkt, uint32_t caplen, uint32_t off, double ts,
               UdpDatagram& out) {
    if (off == kNoOffset || caplen < off + 20) return false;
    const uint8_t* ip = pkt + off;
    uint8_t ihl = (ip[0] & 0x0F) * 4;
    if (ihl < 20 || caplen < off + ihl) return false;
    if (ip[9] != kIpProtoUdp) return false;
    uint32_t src_ip = be32(ip + 12);
    uint32_t dst_ip = be32(ip + 16);

    uint32_t udp_off = off + ihl;
    if (caplen < udp_off + 8) return false;
    const uint8_t* udp = pkt + udp_off;
    uint16_t src_port = be16(udp + 0);
    uint16_t dst_port = be16(udp + 2);
    uint16_t udp_len = be16(udp + 4);
    uint32_t payload_off = udp_off + 8;
    uint32_t payload_len = (udp_len >= 8) ? (udp_len - 8u) : 0u;
    if (payload_off + payload_len > caplen)
        payload_len = (caplen > payload_off) ? (caplen - payload_off) : 0;

    out.ts_seconds = ts;
    out.src_ip = src_ip;
    out.dst_ip = dst_ip;
    out.src_port = src_port;
    out.dst_port = dst_port;
    out.payload = pkt + payload_off;
    out.payload_len = payload_len;
    out.packet = pkt;
    out.packet_len = caplen;
    return payload_len > 0;
}

// Parse IPv4 -> TCP starting at `off`. Fills `out`, returns true if the segment
// carries payload. TCP has no length field, so the payload length is taken from
// the IPv4 total-length field (bounded by the captured length).
bool parse_tcp(const uint8_t* pkt, uint32_t caplen, uint32_t off, double ts,
               TcpSegment& out) {
    if (off == kNoOffset || caplen < off + 20) return false;
    const uint8_t* ip = pkt + off;
    uint8_t ihl = (ip[0] & 0x0F) * 4;
    if (ihl < 20 || caplen < off + ihl) return false;
    if (ip[9] != kIpProtoTcp) return false;
    uint16_t ip_total = be16(ip + 2);
    uint32_t src_ip = be32(ip + 12);
    uint32_t dst_ip = be32(ip + 16);

    uint32_t tcp_off = off + ihl;
    if (caplen < tcp_off + 20) return false;
    const uint8_t* tcp = pkt + tcp_off;
    uint16_t src_port = be16(tcp + 0);
    uint16_t dst_port = be16(tcp + 2);
    uint32_t seq = be32(tcp + 4);
    uint8_t data_off = static_cast<uint8_t>((tcp[12] >> 4) * 4);
    if (data_off < 20) return false;

    uint32_t payload_off = tcp_off + data_off;
    uint32_t ip_end = off + ip_total;  // end of the IP packet within the frame
    uint32_t payload_len =
        (ip_end > payload_off) ? (ip_end - payload_off) : 0u;
    if (payload_off + payload_len > caplen)
        payload_len = (caplen > payload_off) ? (caplen - payload_off) : 0u;

    out.ts_seconds = ts;
    out.src_ip = src_ip;
    out.dst_ip = dst_ip;
    out.src_port = src_port;
    out.dst_port = dst_port;
    out.seq = seq;
    out.payload = pkt + payload_off;
    out.payload_len = payload_len;
    return payload_len > 0;
}

}  // namespace

bool read_pcap(const std::string& path,
               const std::function<void(const UdpDatagram&)>& on_datagram,
               std::string& error,
               uint64_t max_datagrams) {
    return read_pcap_l4(path, on_datagram, {}, error, max_datagrams);
}

bool read_pcap_l4(const std::string& path,
                  const std::function<void(const UdpDatagram&)>& on_udp,
                  const std::function<void(const TcpSegment&)>& on_tcp,
                  std::string& error,
                  uint64_t max_packets) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t* handle = pcap_open_offline(path.c_str(), errbuf);
    if (handle == nullptr) {
        error = errbuf;
        return false;
    }
    int dlt = pcap_datalink(handle);
    struct pcap_pkthdr* header = nullptr;
    const u_char* data = nullptr;
    int rc;
    uint64_t emitted = 0;
    const auto dispatch = [&](const uint8_t* packet, uint32_t length, double timestamp) {
        uint32_t off = ipv4_offset(dlt, packet, length);
        if (off == kNoOffset || length < off + 20) return false;
        if (packet[off + 9] == kIpProtoUdp && on_udp) {
            UdpDatagram datagram;
            if (parse_udp(packet, length, off, timestamp, datagram)) {
                on_udp(datagram);
                return max_packets && ++emitted >= max_packets;
            }
        } else if (packet[off + 9] == kIpProtoTcp && on_tcp) {
            TcpSegment segment;
            if (parse_tcp(packet, length, off, timestamp, segment)) {
                on_tcp(segment);
                return max_packets && ++emitted >= max_packets;
            }
        }
        return false;
    };
    bool stop = false;
    while ((rc = pcap_next_ex(handle, &header, &data)) >= 0) {
        if (rc == 0) continue;  // timeout (live only)
        double ts = static_cast<double>(header->ts.tv_sec) +
                    static_cast<double>(header->ts.tv_usec) * 1e-6;
        uint32_t cmp_offset = 14;
        uint16_t ethertype = header->caplen >= 14 ? be16(data + 12) : 0;
        while ((ethertype == 0x8100 || ethertype == 0x88A8)
               && header->caplen >= cmp_offset + 4) {
            ethertype = be16(data + cmp_offset + 2);
            cmp_offset += 4;
        }
        bool vector_cmp = dlt == kDltEn10mb && ethertype == kEthTypeTechnica
            && header->caplen >= cmp_offset + 8
            && data[6] == 0 && data[7] == 0x16 && data[8] == 0x81;
        if (vector_cmp) {
            if (data[cmp_offset + 4] != 1) continue;
            uint32_t first = cmp_offset + 8;
            uint64_t latest = 0;
            for (uint32_t cursor = first; cursor + 16 <= header->caplen;) {
                uint32_t length = be16(data + cursor + 14);
                if (length > header->caplen - cursor - 16) break;
                uint64_t timestamp = (static_cast<uint64_t>(be32(data + cursor)) << 32)
                    | be32(data + cursor + 4);
                if (timestamp > latest) latest = timestamp;
                cursor += 16 + length;
            }
            for (uint32_t cursor = first; cursor + 16 <= header->caplen;) {
                uint32_t length = be16(data + cursor + 14);
                if (length > header->caplen - cursor - 16) break;
                uint8_t type = data[cursor + 13];
                if (type > 3 && length > 6) {
                    uint64_t timestamp = (static_cast<uint64_t>(be32(data + cursor)) << 32)
                        | be32(data + cursor + 4);
                    double inner_ts = ts - static_cast<double>(latest - timestamp) * 1e-9;
                    stop = dispatch(data + cursor + 22, length - 6, inner_ts);
                    if (stop) break;
                }
                cursor += 16 + length;
            }
        } else {
            stop = dispatch(data, header->caplen, ts);
        }
        if (stop) break;
    }
    if (rc == -1) {
        error = pcap_geterr(handle);
    }
    pcap_close(handle);
    return error.empty();
}

}  // namespace mrc
