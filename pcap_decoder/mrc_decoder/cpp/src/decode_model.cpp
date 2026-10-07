#include "mrc_decoder/decode_model.hpp"

#include <pugixml.hpp>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <utility>

namespace mrc {
namespace fs = std::filesystem;

namespace {

// Last path segment of an AUTOSAR reference like "/Communication/ISignal/foo".
std::string leaf(const std::string& ref) {
    auto pos = ref.find_last_of('/');
    return pos == std::string::npos ? ref : ref.substr(pos + 1);
}

std::string child_text(const pugi::xml_node& n, const char* name) {
    return n.child(name).text().as_string();
}

// Extract a raw integer of `bits` bits from `data` starting at bit `start`.
// big_endian=false: Intel / MOST-SIGNIFICANT-BYTE-LAST (LSB-0 numbering).
// big_endian=true : Motorola / MOST-SIGNIFICANT-BYTE-FIRST (MSB-0 numbering).
uint64_t extract_bits(const uint8_t* data, uint32_t start, uint32_t bits, bool big_endian) {
    uint64_t raw = 0;
    if (big_endian) {
        for (uint32_t i = 0; i < bits; ++i) {
            uint32_t p = start + i;
            raw = (raw << 1) | ((data[p / 8] >> (7 - (p % 8))) & 1u);
        }
    } else {
        for (uint32_t i = 0; i < bits; ++i) {
            uint32_t p = start + i;
            raw |= (static_cast<uint64_t>((data[p / 8] >> (p % 8)) & 1u)) << i;
        }
    }
    return raw;
}

// COMPU-METHOD linear coeffs: phys = (n0 + n1*x) / d0.
struct Linear { double factor = 1.0; double offset = 0.0; };

Linear parse_linear(const pugi::xml_node& compu) {
    Linear lin;
    auto coeffs = compu.select_node(".//COMPU-RATIONAL-COEFFS").node();
    if (!coeffs) return lin;
    std::vector<double> num, den;
    for (auto v : coeffs.child("COMPU-NUMERATOR").children("V"))
        num.push_back(v.text().as_double());
    for (auto v : coeffs.child("COMPU-DENOMINATOR").children("V"))
        den.push_back(v.text().as_double());
    double d0 = (!den.empty() && den[0] != 0.0) ? den[0] : 1.0;
    lin.offset = (num.size() > 0 ? num[0] : 0.0) / d0;
    lin.factor = (num.size() > 1 ? num[1] : 1.0) / d0;
    return lin;
}

// Per-file lookup tables (unflattened systems are self-contained).
struct FileMaps {
    std::unordered_map<std::string, std::pair<uint32_t, std::string>> isignal;  // leaf -> (bits, compu leaf)
    std::unordered_map<std::string, Linear> compu;                             // leaf -> linear
};

void collect_file_maps(const pugi::xml_node& root, FileMaps& m) {
    for (auto cm : root.select_nodes(".//COMPU-METHOD")) {
        std::string name = child_text(cm.node(), "SHORT-NAME");
        if (!name.empty()) m.compu[name] = parse_linear(cm.node());
    }
    for (auto is : root.select_nodes(".//I-SIGNAL")) {
        auto node = is.node();
        std::string name = child_text(node, "SHORT-NAME");
        if (name.empty()) continue;
        uint32_t bitlen = static_cast<uint32_t>(node.child("LENGTH").text().as_uint());
        std::string compu_ref;
        if (auto rn = node.select_node(".//COMPU-METHOD-REF").node())
            compu_ref = leaf(rn.text().as_string());
        m.isignal[name] = {bitlen, compu_ref};
    }
}

}  // namespace

void DecodeModel::register_signal(uint32_t index, const std::string& group,
                                  const std::string& name) {
    signals_[index] = SignalInfo{group, name};
}

const SignalInfo* DecodeModel::signal(uint32_t index) const {
    auto it = signals_.find(index);
    return it == signals_.end() ? nullptr : &it->second;
}

const PduLayout* DecodeModel::pdu_by_name(const std::string& name) const {
    auto it = pdu_index_by_name_.find(name);
    return it == pdu_index_by_name_.end() ? nullptr : &pdus_[it->second];
}

bool DecodeModel::load_from_arxml(const std::string& arxml_path,
                                  DecodeModel& out, std::string& error) {
    std::vector<std::string> files;
    if (fs::is_directory(arxml_path)) {
        for (auto& e : fs::directory_iterator(arxml_path))
            if (e.path().extension() == ".arxml") files.push_back(e.path().string());
    } else if (fs::exists(arxml_path)) {
        files.push_back(arxml_path);
    } else {
        error = "ARXML path not found: " + arxml_path;
        return false;
    }
    if (files.empty()) { error = "no .arxml files in " + arxml_path; return false; }

    uint32_t next_index = 0;

    for (const auto& file : files) {
        pugi::xml_document doc;
        if (!doc.load_file(file.c_str())) continue;  // skip unparseable
        pugi::xml_node root = doc.document_element();

        FileMaps maps;
        collect_file_maps(root, maps);

        std::unordered_map<std::string, size_t> local_pdu_index;  // pdu name -> pdus_ idx
        for (auto pn : root.select_nodes(".//I-SIGNAL-I-PDU")) {
            auto node = pn.node();
            PduLayout pdu;
            pdu.name = child_text(node, "SHORT-NAME");
            pdu.byte_length = static_cast<uint32_t>(node.child("LENGTH").text().as_uint());
            if (pdu.name.empty()) continue;

            for (auto mn : node.select_nodes(".//I-SIGNAL-TO-I-PDU-MAPPING")) {
                auto map = mn.node();
                std::string sig_ref = leaf(map.child("I-SIGNAL-REF").text().as_string());
                if (sig_ref.empty()) continue;
                auto it = maps.isignal.find(sig_ref);
                if (it == maps.isignal.end()) continue;

                SignalLayout sl;
                sl.signal_index = next_index++;
                sl.start_bit = static_cast<uint32_t>(
                    map.child("START-POSITION").text().as_uint());
                sl.bit_length = it->second.first;
                sl.big_endian =
                    child_text(map, "PACKING-BYTE-ORDER") == "MOST-SIGNIFICANT-BYTE-FIRST";
                if (!it->second.second.empty()) {
                    auto ci = maps.compu.find(it->second.second);
                    if (ci != maps.compu.end()) {
                        sl.factor = ci->second.factor;
                        sl.offset = ci->second.offset;
                    }
                }
                out.register_signal(sl.signal_index, pdu.name, sig_ref);
                pdu.signals.push_back(sl);
            }
            if (pdu.signals.empty()) continue;

            size_t idx = out.pdus_.size();
            local_pdu_index[pdu.name] = idx;
            out.pdu_index_by_name_[pdu.name] = idx;
            out.pdus_.push_back(std::move(pdu));
        }

        // Routing by frame id. Handles both CAN and LIN:
        //   *-FRAME-TRIGGERING(IDENTIFIER, FRAME-REF) -> frame short-name ->
        //   (CAN-FRAME | LIN-UNCONDITIONAL-FRAME) PDU-TO-FRAME-MAPPING -> PDU-REF.
        // Build frame short-name -> PDU leaf once, then map each triggering id.
        std::unordered_map<std::string, std::string> frame_to_pdu;
        auto index_frames = [&](const char* xpath) {
            for (auto fn : root.select_nodes(xpath)) {
                std::string fname = child_text(fn.node(), "SHORT-NAME");
                auto pref = fn.node().select_node(".//PDU-TO-FRAME-MAPPING//PDU-REF").node();
                if (!fname.empty() && pref)
                    frame_to_pdu[fname] = leaf(pref.text().as_string());
            }
        };
        index_frames(".//CAN-FRAME");
        index_frames(".//LIN-UNCONDITIONAL-FRAME");

        auto route_triggerings = [&](const char* xpath) {
            for (auto tn : root.select_nodes(xpath)) {
                auto node = tn.node();
                uint32_t frame_id =
                    static_cast<uint32_t>(node.child("IDENTIFIER").text().as_uint());
                auto fref = node.select_node(".//FRAME-REF").node();
                auto fi = frame_to_pdu.find(leaf(fref.text().as_string()));
                if (fi == frame_to_pdu.end()) continue;
                auto pit = local_pdu_index.find(fi->second);
                if (pit != local_pdu_index.end())
                    out.pdu_by_frame_id_[frame_id & 0xFFFFu] = pit->second;
            }
        };
        route_triggerings(".//CAN-FRAME-TRIGGERING");
        route_triggerings(".//LIN-FRAME-TRIGGERING");
    }

    return true;
}

void DecodeModel::decode_pdu_layout(const PduLayout& pdu, const uint8_t* data, size_t len,
                                    double ts, std::vector<SignalSample>& out) {
    for (const auto& s : pdu.signals) {
        if (s.bit_length == 0 || s.bit_length > 64) continue;
        if ((s.start_bit + s.bit_length + 7) / 8 > len) continue;  // not enough bytes
        uint64_t raw = extract_bits(data, s.start_bit, s.bit_length, s.big_endian);
        double value;
        if (s.is_signed && s.bit_length < 64 && (raw & (1ull << (s.bit_length - 1)))) {
            int64_t sraw = static_cast<int64_t>(raw | (~0ull << s.bit_length));
            value = static_cast<double>(sraw) * s.factor + s.offset;
        } else {
            value = static_cast<double>(raw) * s.factor + s.offset;
        }
        out.push_back(SignalSample{ts, value, s.signal_index});
    }
}

void DecodeModel::decode_eth(uint64_t key, const uint8_t* data, size_t len,
                             double ts, std::vector<SignalSample>& out) const {
    auto it = pdu_by_eth_key_.find(key);
    if (it != pdu_by_eth_key_.end()) {
        decode_pdu_layout(pdus_[it->second], data, len, ts, out);
        return;
    }
    // Fall back to routing by frame id (low 16 bits) until topology routing lands.
    auto fit = pdu_by_frame_id_.find(static_cast<uint32_t>(key & 0xFFFFu));
    if (fit != pdu_by_frame_id_.end())
        decode_pdu_layout(pdus_[fit->second], data, len, ts, out);
}

void DecodeModel::decode_pdu_stream(const uint8_t* p, size_t len, double ts,
                                    std::vector<SignalSample>& out) const {
    // Concatenated PDU-transport framing: [transport_id u32-BE][length u32-BE][payload].
    size_t off = 0;
    while (off + 8 <= len) {
        uint32_t tid = (static_cast<uint32_t>(p[off]) << 24) |
                       (static_cast<uint32_t>(p[off + 1]) << 16) |
                       (static_cast<uint32_t>(p[off + 2]) << 8) |
                       static_cast<uint32_t>(p[off + 3]);
        uint32_t plen = (static_cast<uint32_t>(p[off + 4]) << 24) |
                        (static_cast<uint32_t>(p[off + 5]) << 16) |
                        (static_cast<uint32_t>(p[off + 6]) << 8) |
                        static_cast<uint32_t>(p[off + 7]);
        size_t body = off + 8;
        size_t avail = len - body;
        if (plen > avail) plen = static_cast<uint32_t>(avail);  // clamp truncated tail
        auto it = pdu_by_transport_.find(tid);
        if (it != pdu_by_transport_.end())
            decode_pdu_layout(pdus_[it->second], p + body, plen, ts, out);
        if (plen == 0) break;  // guard against zero-length loops
        off = body + plen;
    }
}

namespace {

// Split a Wireshark-UAT CSV line into fields, stripping surrounding quotes/space.
void split_csv(const std::string& line, std::vector<std::string>& out) {
    out.clear();
    std::string field;
    std::stringstream ss(line);
    while (std::getline(ss, field, ',')) {
        size_t a = field.find_first_not_of(" \t\r\n\"");
        size_t b = field.find_last_not_of(" \t\r\n\"");
        out.push_back(a == std::string::npos ? std::string() : field.substr(a, b - a + 1));
    }
}

uint32_t parse_hex(const std::string& s) {
    return s.empty() ? 0u : static_cast<uint32_t>(std::stoul(s, nullptr, 16));
}

// One raw signal row from Signal_PDU_signal_list_ETH.
struct PduSignalRow {
    std::string name;
    uint32_t bit_width  = 0;
    bool big_endian     = false;
    bool is_signed      = false;
    bool is_padding     = false;
    double factor       = 1.0;
    double offset       = 0.0;
};

}  // namespace

bool DecodeModel::load_pdu_tables(const std::string& dir, std::string& error) {
    fs::path base(dir);
    const fs::path id_path   = base / "Signal_PDU_identifiers_ETH";
    const fs::path bind_path = base / "Signal_PDU_Binding_PDU_Transport_ETH";
    const fs::path sig_path  = base / "Signal_PDU_signal_list_ETH";
    const fs::path deca_path = base / "decode_as_entries";
    for (const auto& p : {id_path, bind_path, sig_path, deca_path}) {
        if (!fs::exists(p)) { error = "missing PDU table: " + p.string(); return false; }
    }

    std::string line;
    std::vector<std::string> parts;

    // identifiers: signal_pdu_id(hex) -> name
    std::unordered_map<uint32_t, std::string> pdu_names;
    {
        std::ifstream f(id_path);
        while (std::getline(f, line)) {
            if (line.empty() || line[0] == '#') continue;
            split_csv(line, parts);
            if (parts.size() >= 2) pdu_names[parse_hex(parts[0])] = parts[1];
        }
    }

    // signal list: signal_pdu_id(hex) -> ordered signal rows
    std::unordered_map<uint32_t, std::vector<PduSignalRow>> pdu_signals;
    {
        std::ifstream f(sig_path);
        while (std::getline(f, line)) {
            if (line.empty() || line[0] == '#') continue;
            split_csv(line, parts);
            if (parts.size() < 11) continue;
            PduSignalRow r;
            uint32_t sigpdu = parse_hex(parts[0]);
            r.name       = parts[3];
            r.is_signed  = parts[5] == "sint";
            r.big_endian = parts[6] == "TRUE";
            r.bit_width  = static_cast<uint32_t>(std::stoul(parts[8]));
            r.factor     = std::stod(parts[9]);
            r.offset     = std::stod(parts[10]);
            if (parts.size() > 13) r.is_padding = parts[13] == "TRUE";
            pdu_signals[sigpdu].push_back(std::move(r));
        }
    }

    // binding: transport_id(hex) -> signal_pdu_id(hex), only for known PDUs
    std::vector<std::pair<uint32_t, uint32_t>> bindings;  // (transport_id, signal_pdu_id)
    {
        std::ifstream f(bind_path);
        while (std::getline(f, line)) {
            if (line.empty() || line[0] == '#') continue;
            split_csv(line, parts);
            if (parts.size() < 2) continue;
            uint32_t tid = parse_hex(parts[0]);
            uint32_t spid = parse_hex(parts[1]);
            if (pdu_names.count(spid)) bindings.emplace_back(tid, spid);
        }
    }

    uint32_t next_index = static_cast<uint32_t>(signals_.size());
    for (const auto& [tid, spid] : bindings) {
        auto sit = pdu_signals.find(spid);
        if (sit == pdu_signals.end()) continue;
        std::string full = pdu_names[spid];
        std::string short_name = full.substr(0, full.find('.'));

        PduLayout pdu;
        pdu.name = short_name;
        uint32_t bit_offset = 0;
        for (const auto& r : sit->second) {
            if (r.bit_width == 0) continue;
            if (r.is_padding || r.bit_width > 64) { bit_offset += r.bit_width; continue; }
            SignalLayout sl;
            sl.signal_index = next_index++;
            sl.start_bit    = bit_offset;
            sl.bit_length   = r.bit_width;
            sl.big_endian   = r.big_endian;
            sl.is_signed    = r.is_signed;
            sl.factor       = r.factor;
            sl.offset       = r.offset;
            register_signal(sl.signal_index, short_name, r.name);
            pdu.signals.push_back(sl);
            bit_offset += r.bit_width;
        }
        if (pdu.signals.empty()) continue;
        pdu.byte_length = (bit_offset + 7) / 8;

        size_t idx = pdus_.size();
        pdu_by_transport_[tid] = idx;
        pdu_index_by_name_[short_name] = idx;
        pdus_.push_back(std::move(pdu));
    }

    // decode_as_entries: UDP ports that carry PDU Transport.
    {
        std::ifstream f(deca_path);
        while (std::getline(f, line)) {
            if (line.find("udp.port") == std::string::npos) continue;
            if (line.find("PDU Transport") == std::string::npos) continue;
            // format: decode_as_entry: udp.port,<port>,<name>,PDU Transport
            auto comma = line.find(',');
            if (comma == std::string::npos) continue;
            auto comma2 = line.find(',', comma + 1);
            std::string port_s = line.substr(comma + 1,
                (comma2 == std::string::npos ? line.size() : comma2) - comma - 1);
            try {
                pdu_ports_.insert(static_cast<uint16_t>(std::stoul(port_s)));
            } catch (...) {}
        }
    }

    return true;
}

}  // namespace mrc
