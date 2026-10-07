#include "mrc_decoder/engine.hpp"

#include <csignal>
#include <filesystem>

#include "mrc_decoder/mdf_writer.hpp"
#include "mrc_decoder/mrc_packet.hpp"
#include "mrc_decoder/pcap_reader.hpp"

namespace mrc {
namespace fs = std::filesystem;

namespace {
volatile std::sig_atomic_t g_stop = 0;
void on_signal(int) { g_stop = 1; }

std::string base_name_no_ext(const std::string& path) {
    return fs::path(path).stem().string();
}

// Decode every UDP datagram in one PCAP into the writer. Returns sample count.
uint64_t decode_file(const std::string& pcap, const DecodeModel& model,
                     MdfWriter& writer, std::string& error) {
    uint64_t samples = 0;
    std::vector<SignalSample> scratch;
    auto handler = [&](const UdpDatagram& dg) {
        if (model.is_pdu_port(dg.dst_port)) {
            scratch.clear();
            // PDU transport: the UDP payload holds one or more concatenated
            // [transport_id][length][payload] PDUs; the model loops and routes them.
            model.decode_pdu_stream(dg.payload, dg.payload_len, dg.ts_seconds, scratch);
        } else {
            auto pkt = parse_mrc(dg.payload, dg.payload_len);
            if (!pkt || !pkt->is_data()) return;
            uint64_t key = DecodeModel::eth_key(dg.src_ip, dg.dst_port,
                                                pkt->identifier & 0xFFFFu);
            scratch.clear();
            model.decode_eth(key, pkt->payload, pkt->payload_len, dg.ts_seconds, scratch);
        }
        for (const auto& s : scratch) { writer.add(s, model); ++samples; }
    };
    read_pcap(pcap, handler, error);
    return samples;
}
}  // namespace

RunResult run(const EngineOptions& opts, const ProgressFn& progress) {
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    RunResult result;

    DecodeModel model;
    std::string err;
    if (!opts.sdb_arxml_dir.empty()) {
        if (!DecodeModel::load_from_arxml(opts.sdb_arxml_dir, model, err)) {
            result.ok = false;
            FileResult fr; fr.ok = false; fr.error = "SDB load failed: " + err;
            result.files.push_back(fr);
            return result;
        }
    }
    if (!opts.pdu_table_dir.empty()) {
        if (!model.load_pdu_tables(opts.pdu_table_dir, err)) {
            result.ok = false;
            FileResult fr; fr.ok = false; fr.error = "PDU table load failed: " + err;
            result.files.push_back(fr);
            return result;
        }
    }
    if (opts.sdb_arxml_dir.empty() && opts.pdu_table_dir.empty()) {
        result.ok = false;
        FileResult fr; fr.ok = false;
        fr.error = "no decode source: provide --sdb (ARXML) and/or --pdu-config";
        result.files.push_back(fr);
        return result;
    }

    fs::create_directories(opts.output_dir);

    MdfWriter merged;         // used only when merge_output
    double merge_offset = 0.0;

    const size_t n = opts.pcap_files.size();
    for (size_t i = 0; i < n && !g_stop; ++i) {
        const std::string& pcap = opts.pcap_files[i];
        FileResult fr; fr.input = pcap;

        if (opts.merge_output) {
            merged.set_time_offset(merge_offset);
            std::string derr;
            fr.samples = decode_file(pcap, model, merged, derr);
            fr.ok = derr.empty();
            fr.error = derr;
            merge_offset = merged.max_timestamp();  // next file starts after this one
        } else {
            MdfWriter writer;
            std::string derr;
            fr.samples = decode_file(pcap, model, writer, derr);
            if (!derr.empty()) {
                fr.ok = false; fr.error = derr;
            } else {
                std::string out = (fs::path(opts.output_dir) /
                                   (base_name_no_ext(pcap) + "_MRCDECODED.mf4")).string();
                std::string werr;
                fr.ok = writer.write(out, werr);
                fr.error = werr;
                if (fr.ok) fr.output = out;
            }
        }
        result.files.push_back(fr);
        if (progress) progress(i + 1, n, pcap, fr.samples);
    }

    if (opts.merge_output && !g_stop) {
        std::string out = (fs::path(opts.output_dir) / "merged_MRCDECODED.mf4").string();
        std::string werr;
        if (merged.write(out, werr)) {
            result.merged_output = out;
        }
    }

    result.ok = true;
    return result;
}

}  // namespace mrc
