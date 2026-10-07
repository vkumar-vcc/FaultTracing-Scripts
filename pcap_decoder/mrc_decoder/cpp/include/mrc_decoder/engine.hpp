// Engine: orchestrates the sequential batch decode of PCAP files to MDF.
#pragma once

#include <functional>
#include <string>
#include <vector>

#include "mrc_decoder/decode_model.hpp"

namespace mrc {

struct EngineOptions {
    std::string sdb_arxml_dir;                // consolidated ARXML directory (optional)
    std::string pdu_table_dir;                // SPA3 Signal-PDU table dir (optional)
    std::string output_dir = ".";             // where MDF files are written
    bool merge_output = false;                 // --merge-output
    std::vector<std::string> pcap_files;       // input captures (processed in order)
};

// Progress callback: (file_index, file_count, current_file, decoded_samples).
using ProgressFn = std::function<void(size_t, size_t, const std::string&, uint64_t)>;

struct FileResult {
    std::string input;
    std::string output;      // empty if skipped/failed
    uint64_t    samples = 0;
    bool        ok = false;
    std::string error;
};

struct RunResult {
    std::vector<FileResult> files;
    std::string merged_output;   // set when merge_output and success
    bool ok = false;
};

// Runs the batch. `progress` may be null.
RunResult run(const EngineOptions& opts, const ProgressFn& progress);

}  // namespace mrc
