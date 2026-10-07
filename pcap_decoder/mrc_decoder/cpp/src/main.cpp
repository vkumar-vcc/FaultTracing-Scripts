// mrc_decoder CLI entry point.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "mrc_decoder/engine.hpp"

namespace {
void usage(const char* prog) {
    std::fprintf(stderr,
        "Usage: %s [--sdb <arxml_dir>] [--pdu-config <dir>] [--merge-output] -o <out_dir> <cap1.pcap> [cap2.pcap ...]\n"
        "\n"
        "  --sdb <arxml_dir>    Consolidated ARXML directory (resolved from an SDB version\n"
        "                       by the Python sdb_fetcher; pass the resulting folder here).\n"
        "  --pdu-config <dir>   Wireshark Signal-PDU table directory (e.g. SPA3/PDU_SPA3)\n"
        "                       for the Ethernet PDU-transport decode path.\n"
        "  -o, --output <dir>   Output directory for MDF files (default: current dir).\n"
        "  --merge-output       Write a single merged_MRCDECODED.mf4 (flat concat).\n"
        "\n"
        "At least one of --sdb or --pdu-config must be provided.\n",
        prog);
}
}  // namespace

int main(int argc, char** argv) {
    mrc::EngineOptions opts;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--sdb" && i + 1 < argc) {
            opts.sdb_arxml_dir = argv[++i];
        } else if (a == "--pdu-config" && i + 1 < argc) {
            opts.pdu_table_dir = argv[++i];
        } else if ((a == "-o" || a == "--output") && i + 1 < argc) {
            opts.output_dir = argv[++i];
        } else if (a == "--merge-output") {
            opts.merge_output = true;
        } else if (a == "-h" || a == "--help") {
            usage(argv[0]);
            return 0;
        } else if (!a.empty() && a[0] == '-') {
            std::fprintf(stderr, "Unknown option: %s\n", a.c_str());
            usage(argv[0]);
            return 2;
        } else {
            opts.pcap_files.push_back(a);
        }
    }

    if ((opts.sdb_arxml_dir.empty() && opts.pdu_table_dir.empty()) ||
        opts.pcap_files.empty()) {
        usage(argv[0]);
        return 2;
    }

    auto progress = [](size_t idx, size_t total, const std::string& file, uint64_t n) {
        std::fprintf(stderr, "[%zu/%zu] %s -> %llu samples\n",
                     idx, total, file.c_str(), static_cast<unsigned long long>(n));
    };

    mrc::RunResult r = mrc::run(opts, progress);

    int failures = 0;
    for (const auto& f : r.files) {
        if (!f.ok) {
            ++failures;
            std::fprintf(stderr, "FAILED: %s (%s)\n", f.input.c_str(), f.error.c_str());
        } else if (!f.output.empty()) {
            std::fprintf(stdout, "%s\n", f.output.c_str());
        }
    }
    if (!r.merged_output.empty()) {
        std::fprintf(stdout, "%s\n", r.merged_output.c_str());
    }
    return (r.ok && failures == 0) ? 0 : 1;
}
