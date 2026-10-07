// pybind11 module `mrc_engine` — lets the Tkinter GUI drive the C++ engine in-process.
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/functional.h>
#include <pybind11/numpy.h>

#include <cstring>
#include <map>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "mrc_decoder/engine.hpp"
#include "mrc_decoder/mrc_packet.hpp"
#include "mrc_decoder/pcap_reader.hpp"

namespace py = pybind11;

namespace {

// Fixed row width for extracted MRC frame payloads (CAN-FD / LIN max is 64 B).
constexpr size_t kFrameWidth = 64;

inline uint16_t be16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}
inline uint32_t be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

// Allocate a 1-D numpy array and copy the vector into it (unambiguous vs. the
// array_t(count, ptr) convenience ctor, which mis-resolved to a broadcast view).
template <typename T>
py::array_t<T> to_array(const std::vector<T>& v) {
    py::array_t<T> arr(std::vector<py::ssize_t>{static_cast<py::ssize_t>(v.size())});
    auto buf = arr.request();
    if (!v.empty()) std::memcpy(buf.ptr, v.data(), v.size() * sizeof(T));
    return arr;
}

// Reads `pcap_path`, keeps only UDP datagrams whose (src_ip, src_port) is a routed
// bus endpoint, parses the MRC header of each, and returns the routed CAN/LIN frames
// as compact numpy arrays for Python-side DBC/LDF decoding. This moves the whole
// 6M-packet dissection + MRC framing loop into C++ (the former dpkt bottleneck).
//
// routes: list of (src_ip_u32, src_port, bus_index). ip is the 4 IPv4 octets read
//         big-endian (matches socket.inet_aton + struct.unpack("!I")).
// max_datagrams caps the scan (0 = whole file).
py::dict extract_frames(const std::string& pcap_path, const py::list& routes,
                        uint64_t max_datagrams) {
    std::unordered_map<uint64_t, int32_t> route_map;
    route_map.reserve(routes.size() * 2);
    for (const auto& item : routes) {
        auto t = item.cast<std::tuple<uint32_t, uint16_t, int32_t>>();
        uint64_t key = (static_cast<uint64_t>(std::get<0>(t)) << 16) | std::get<1>(t);
        route_map[key] = std::get<2>(t);
    }

    std::vector<int32_t> bus_index;
    std::vector<int32_t> frame_id;
    std::vector<uint8_t> pkt_type;
    std::vector<double> ts;
    std::vector<uint8_t> plen;
    std::vector<uint8_t> payload;  // flat N * kFrameWidth

    std::string error;
    {
        py::gil_scoped_release rel;
        mrc::read_pcap(
            pcap_path,
            [&](const mrc::UdpDatagram& dg) {
                // A VIU bus endpoint may be the SOURCE (VIU->VCU direct frames)
                // or the DESTINATION (VCU->VIU "dp"/exposed frames); match both.
                uint64_t skey = (static_cast<uint64_t>(dg.src_ip) << 16) | dg.src_port;
                uint64_t dkey = (static_cast<uint64_t>(dg.dst_ip) << 16) | dg.dst_port;
                auto it = route_map.find(skey);
                if (it == route_map.end()) it = route_map.find(dkey);
                if (it == route_map.end()) return;
                auto pkt = mrc::parse_mrc(dg.payload, dg.payload_len);
                if (!pkt || !pkt->is_data()) return;

                bus_index.push_back(it->second);
                frame_id.push_back(static_cast<int32_t>(pkt->identifier & 0xFFFFu));
                pkt_type.push_back(static_cast<uint8_t>(pkt->type));
                ts.push_back(dg.ts_seconds);
                size_t n = pkt->payload_len < kFrameWidth ? pkt->payload_len : kFrameWidth;
                plen.push_back(static_cast<uint8_t>(n));
                size_t base = payload.size();
                payload.resize(base + kFrameWidth, 0);
                if (n) std::memcpy(payload.data() + base, pkt->payload, n);
            },
            error, max_datagrams);
    }

    const size_t n = bus_index.size();
    py::array_t<uint8_t> payload_arr(std::vector<py::ssize_t>{
        static_cast<py::ssize_t>(n), static_cast<py::ssize_t>(kFrameWidth)});
    if (n) std::memcpy(payload_arr.request().ptr, payload.data(), payload.size());
    py::dict out;
    out["bus_index"] = to_array(bus_index);
    out["frame_id"] = to_array(frame_id);
    out["pkt_type"] = to_array(pkt_type);
    out["timestamp"] = to_array(ts);
    out["length"] = to_array(plen);
    out["payload"] = payload_arr;
    out["error"] = error;
    return out;
}

// One C++ pass over the pcap counting UDP datagrams per (src_ip, src_port). Used to
// auto-select the routing table without dissecting packets in Python. `max_datagrams`
// caps the scan (0 = whole file) since a prefix is enough to identify the table.
py::dict endpoint_counts(const std::string& pcap_path, uint64_t max_datagrams) {
    std::unordered_map<uint64_t, uint64_t> counts;
    std::string error;
    {
        py::gil_scoped_release rel;
        mrc::read_pcap(
            pcap_path,
            [&](const mrc::UdpDatagram& dg) {
                // Count both endpoints so a VIU bus is found whether it is the
                // source (direct) or destination (dp/exposed) of the datagram.
                ++counts[(static_cast<uint64_t>(dg.src_ip) << 16) | dg.src_port];
                ++counts[(static_cast<uint64_t>(dg.dst_ip) << 16) | dg.dst_port];
            },
            error, max_datagrams);
    }
    std::vector<uint32_t> ip;
    std::vector<uint16_t> port;
    std::vector<uint64_t> cnt;
    ip.reserve(counts.size());
    port.reserve(counts.size());
    cnt.reserve(counts.size());
    for (const auto& kv : counts) {
        ip.push_back(static_cast<uint32_t>(kv.first >> 16));
        port.push_back(static_cast<uint16_t>(kv.first & 0xFFFFu));
        cnt.push_back(kv.second);
    }
    const size_t n = ip.size();
    (void)n;
    py::dict out;
    out["ip"] = to_array(ip);
    out["port"] = to_array(port);
    out["count"] = to_array(cnt);
    out["error"] = error;
    return out;
}

// --- SOME/IP-over-TCP reassembly -------------------------------------------
// Per-direction TCP stream state: contiguous bytes pending SOME/IP framing plus
// a small out-of-order buffer keyed by sequence number.
struct FlowState {
    uint32_t next_seq = 0;
    bool started = false;
    bool desynced = false;
    std::vector<uint8_t> buf;
    std::map<uint32_t, std::vector<uint8_t>> ooo;
};

// Largest SOME/IP message length field we accept (sanity bound; real messages are
// a few kB). Beyond this we treat the stream as desynced.
constexpr uint32_t kMaxSomeipLen = 1u << 20;

// Collected SOME/IP messages (flat, GIL-free).
struct SomeipSink {
    std::vector<double> ts;
    std::vector<uint16_t> service;
    std::vector<uint16_t> method;
    std::vector<uint8_t> msgtype;
    std::vector<uint8_t> payload;      // flat concatenation
    std::vector<int64_t> payload_off;  // start of each message payload
    std::vector<int32_t> payload_len;
};

// Frame complete SOME/IP messages out of a flow's contiguous buffer.
void frame_someip(FlowState& fs, double ts, SomeipSink& sink) {
    size_t pos = 0;
    const size_t n = fs.buf.size();
    while (n - pos >= 16) {
        const uint8_t* p = fs.buf.data() + pos;
        uint32_t length = be32(p + 4);
        if (length < 8 || length > kMaxSomeipLen) {
            fs.desynced = true;  // misaligned/corrupt stream: stop framing it
            pos = n;
            break;
        }
        size_t total = 8u + length;
        if (n - pos < total) break;  // wait for more segments
        uint32_t pl = length - 8u;
        sink.ts.push_back(ts);
        sink.service.push_back(be16(p + 0));
        sink.method.push_back(be16(p + 2));
        sink.msgtype.push_back(p[14]);
        sink.payload_off.push_back(static_cast<int64_t>(sink.payload.size()));
        sink.payload_len.push_back(static_cast<int32_t>(pl));
        if (pl) sink.payload.insert(sink.payload.end(), p + 16, p + 16 + pl);
        pos += total;
    }
    if (pos) fs.buf.erase(fs.buf.begin(), fs.buf.begin() + static_cast<long>(pos));
}

void drain_ooo(FlowState& fs) {
    for (;;) {
        auto it = fs.ooo.begin();
        if (it == fs.ooo.end()) break;
        int32_t d = static_cast<int32_t>(it->first - fs.next_seq);
        if (d > 0) break;  // gap remains
        const auto& seg = it->second;
        if (d == 0) {
            fs.buf.insert(fs.buf.end(), seg.begin(), seg.end());
            fs.next_seq += static_cast<uint32_t>(seg.size());
        } else {
            uint32_t already = static_cast<uint32_t>(-d);
            if (already < seg.size()) {
                fs.buf.insert(fs.buf.end(), seg.begin() + already, seg.end());
                fs.next_seq += static_cast<uint32_t>(seg.size()) - already;
            }
        }
        fs.ooo.erase(it);
    }
}

void feed_tcp(FlowState& fs, const mrc::TcpSegment& seg, SomeipSink& sink) {
    if (fs.desynced) return;
    if (!fs.started) {
        fs.started = true;
        fs.next_seq = seg.seq;  // frame from the first observed data byte
    }
    int32_t diff = static_cast<int32_t>(seg.seq - fs.next_seq);
    if (diff == 0) {
        fs.buf.insert(fs.buf.end(), seg.payload, seg.payload + seg.payload_len);
        fs.next_seq += seg.payload_len;
        drain_ooo(fs);
        frame_someip(fs, seg.ts_seconds, sink);
    } else if (diff > 0) {
        if (fs.ooo.size() < 128 && fs.ooo.find(seg.seq) == fs.ooo.end())
            fs.ooo[seg.seq].assign(seg.payload, seg.payload + seg.payload_len);
    } else {
        uint32_t already = static_cast<uint32_t>(-diff);
        if (already < seg.payload_len) {
            fs.buf.insert(fs.buf.end(), seg.payload + already,
                          seg.payload + seg.payload_len);
            fs.next_seq += seg.payload_len - already;
            drain_ooo(fs);
            frame_someip(fs, seg.ts_seconds, sink);
        }
    }
}

// Single pass over the pcap: UDP datagrams routed to MRC frames (as extract_frames)
// and TCP segments on `someip_ports` reassembled into SOME/IP messages. Returns one
// dict with both result sets so the capture is read exactly once.
py::dict extract_all(const std::string& pcap_path, const py::list& routes,
                     const std::vector<uint16_t>& someip_ports,
                     uint64_t max_packets,
                     const std::vector<uint16_t>& pdu_ports) {
    std::unordered_map<uint64_t, int32_t> route_map;
    route_map.reserve(routes.size() * 2);
    for (const auto& item : routes) {
        auto t = item.cast<std::tuple<uint32_t, uint16_t, int32_t>>();
        uint64_t key = (static_cast<uint64_t>(std::get<0>(t)) << 16) | std::get<1>(t);
        route_map[key] = std::get<2>(t);
    }
    std::unordered_set<uint16_t> si_ports(someip_ports.begin(), someip_ports.end());
    std::unordered_set<uint16_t> signal_pdu_ports(pdu_ports.begin(), pdu_ports.end());
    std::vector<uint32_t> pdu_id;
    std::vector<double> pdu_ts;
    std::vector<uint8_t> pdu_payload;
    std::vector<int64_t> pdu_off;
    std::vector<uint32_t> pdu_len;
    uint64_t pdu_errors = 0;
    uint64_t pdu_duplicates = 0;

    std::vector<int32_t> bus_index;
    std::vector<int32_t> frame_id;
    std::vector<uint8_t> pkt_type;
    std::vector<double> ts;
    std::vector<uint8_t> plen;
    std::vector<uint8_t> payload;  // flat N * kFrameWidth

    SomeipSink sink;
    using FlowKey = std::tuple<uint32_t, uint32_t, uint16_t, uint16_t>;
    std::map<FlowKey, FlowState> flows;
    std::map<FlowKey, std::pair<double, std::vector<uint8_t>>> previous_pdus;

    std::string error;
    {
        py::gil_scoped_release rel;
        mrc::read_pcap_l4(
            pcap_path,
            [&](const mrc::UdpDatagram& dg) {
                if (signal_pdu_ports.count(dg.dst_port)) {
                    FlowKey key{dg.src_ip, dg.dst_ip, dg.src_port, dg.dst_port};
                    auto previous = previous_pdus.find(key);
                    bool duplicate = false;
                    if (previous != previous_pdus.end()) {
                        double delta = dg.ts_seconds - previous->second.first;
                        const auto& bytes = previous->second.second;
                        duplicate = delta >= 0 && delta < 0.0001
                            && bytes.size() == dg.packet_len
                            && std::memcmp(bytes.data(), dg.packet, dg.packet_len) == 0;
                    }
                    previous_pdus[key] = {dg.ts_seconds,
                        std::vector<uint8_t>(dg.packet, dg.packet + dg.packet_len)};
                    if (duplicate) {
                        ++pdu_duplicates;
                        return;
                    }
                    size_t offset = 0;
                    while (offset + 8 <= dg.payload_len) {
                        uint32_t identifier = be32(dg.payload + offset);
                        uint32_t length = be32(dg.payload + offset + 4);
                        if (!length || length > dg.payload_len - offset - 8) break;
                        pdu_id.push_back(identifier);
                        pdu_ts.push_back(dg.ts_seconds);
                        pdu_off.push_back(static_cast<int64_t>(pdu_payload.size()));
                        pdu_len.push_back(length);
                        pdu_payload.insert(pdu_payload.end(), dg.payload + offset + 8,
                                           dg.payload + offset + 8 + length);
                        offset += 8 + length;
                    }
                    if (offset != dg.payload_len) ++pdu_errors;
                }
                uint64_t skey = (static_cast<uint64_t>(dg.src_ip) << 16) | dg.src_port;
                uint64_t dkey = (static_cast<uint64_t>(dg.dst_ip) << 16) | dg.dst_port;
                auto it = route_map.find(skey);
                if (it == route_map.end()) it = route_map.find(dkey);
                if (it == route_map.end()) return;
                auto pkt = mrc::parse_mrc(dg.payload, dg.payload_len);
                if (!pkt || !pkt->is_data()) return;
                bus_index.push_back(it->second);
                frame_id.push_back(static_cast<int32_t>(pkt->identifier & 0xFFFFu));
                pkt_type.push_back(static_cast<uint8_t>(pkt->type));
                ts.push_back(dg.ts_seconds);
                size_t n = pkt->payload_len < kFrameWidth ? pkt->payload_len : kFrameWidth;
                plen.push_back(static_cast<uint8_t>(n));
                size_t base = payload.size();
                payload.resize(base + kFrameWidth, 0);
                if (n) std::memcpy(payload.data() + base, pkt->payload, n);
            },
            [&](const mrc::TcpSegment& seg) {
                if (si_ports.find(seg.dst_port) == si_ports.end() &&
                    si_ports.find(seg.src_port) == si_ports.end())
                    return;
                FlowKey k{seg.src_ip, seg.dst_ip, seg.src_port, seg.dst_port};
                feed_tcp(flows[k], seg, sink);
            },
            error, max_packets);
    }

    const size_t n = bus_index.size();
    py::array_t<uint8_t> payload_arr(std::vector<py::ssize_t>{
        static_cast<py::ssize_t>(n), static_cast<py::ssize_t>(kFrameWidth)});
    if (n) std::memcpy(payload_arr.request().ptr, payload.data(), payload.size());

    py::dict out;
    out["bus_index"] = to_array(bus_index);
    out["frame_id"] = to_array(frame_id);
    out["pkt_type"] = to_array(pkt_type);
    out["timestamp"] = to_array(ts);
    out["length"] = to_array(plen);
    out["payload"] = payload_arr;
    out["someip_timestamp"] = to_array(sink.ts);
    out["someip_service"] = to_array(sink.service);
    out["someip_method"] = to_array(sink.method);
    out["someip_msgtype"] = to_array(sink.msgtype);
    out["someip_payload"] = to_array(sink.payload);
    out["someip_payload_off"] = to_array(sink.payload_off);
    out["someip_payload_len"] = to_array(sink.payload_len);
    out["pdu_id"] = to_array(pdu_id);
    out["pdu_timestamp"] = to_array(pdu_ts);
    out["pdu_payload"] = to_array(pdu_payload);
    out["pdu_payload_off"] = to_array(pdu_off);
    out["pdu_payload_len"] = to_array(pdu_len);
    out["pdu_errors"] = pdu_errors;
    out["pdu_duplicates"] = pdu_duplicates;
    out["error"] = error;
    return out;
}

}  // namespace

PYBIND11_MODULE(mrc_engine, m) {
    m.doc() = "MRC decoder C++ engine (PCAP -> MDF)";

    py::class_<mrc::EngineOptions>(m, "EngineOptions")
        .def(py::init<>())
        .def_readwrite("sdb_arxml_dir", &mrc::EngineOptions::sdb_arxml_dir)
        .def_readwrite("output_dir", &mrc::EngineOptions::output_dir)
        .def_readwrite("merge_output", &mrc::EngineOptions::merge_output)
        .def_readwrite("pcap_files", &mrc::EngineOptions::pcap_files);

    py::class_<mrc::FileResult>(m, "FileResult")
        .def_readonly("input", &mrc::FileResult::input)
        .def_readonly("output", &mrc::FileResult::output)
        .def_readonly("samples", &mrc::FileResult::samples)
        .def_readonly("ok", &mrc::FileResult::ok)
        .def_readonly("error", &mrc::FileResult::error);

    py::class_<mrc::RunResult>(m, "RunResult")
        .def_readonly("files", &mrc::RunResult::files)
        .def_readonly("merged_output", &mrc::RunResult::merged_output)
        .def_readonly("ok", &mrc::RunResult::ok);

    // progress: callable(idx, total, file, samples) or None
    m.def("run",
          [](const mrc::EngineOptions& opts, py::object progress) {
              mrc::ProgressFn fn;
              if (!progress.is_none()) {
                  fn = [progress](size_t i, size_t n, const std::string& f, uint64_t s) {
                      py::gil_scoped_acquire gil;
                      progress(i, n, f, s);
                  };
              }
              py::gil_scoped_release rel;
              return mrc::run(opts, fn);
          },
          py::arg("options"), py::arg("progress") = py::none());

    // Fast routed-frame extractor for the SPA2 (DBC/LDF) decode path.
    m.def("extract_frames", &extract_frames, py::arg("pcap_path"), py::arg("routes"),
          py::arg("max_datagrams") = 0,
          "Extract routed MRC CAN/LIN frames from a pcap as numpy arrays "
          "(bus_index, frame_id, pkt_type, timestamp, length, payload[N,64]).");

    // Single-pass extractor: MRC CAN/LIN frames (UDP) AND SOME/IP messages (TCP,
    // reassembled) in one read of the capture.
    m.def("extract_all", &extract_all, py::arg("pcap_path"), py::arg("routes"),
            py::arg("someip_ports"), py::arg("max_packets") = 0,
            py::arg("pdu_ports") = std::vector<uint16_t>{},
          "Single pass: routed MRC frames + reassembled SOME/IP messages. Returns the "
          "extract_frames arrays plus someip_timestamp/service/method/msgtype and "
          "someip_payload(flat)/someip_payload_off/someip_payload_len.");

    m.def("endpoint_counts", &endpoint_counts, py::arg("pcap_path"),
          py::arg("max_datagrams") = 0,
          "Count UDP datagrams per (src_ip, src_port); returns numpy arrays "
          "(ip, port, count) for routing-table auto-selection.");
}
