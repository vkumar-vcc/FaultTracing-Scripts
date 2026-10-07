// MDF (MF4) writer: one channel group per signal_group, capture-time master.
#pragma once

#include <memory>
#include <string>
#include <vector>

#include "mrc_decoder/decode_model.hpp"

namespace mrc {

// Accumulates decoded samples and writes an MF4 file.
// Layout: one channel group per `signal_group`, one channel per signal,
// master (time) channel driven by capture timestamps.
class MdfWriter {
public:
    MdfWriter();
    ~MdfWriter();

    // Add a decoded sample (looked up against the model for group/name).
    void add(const SignalSample& s, const DecodeModel& model);

    // For --merge-output: shift every subsequently-added sample's time by `offset`
    // seconds so files concatenate without overlap. Returns the max timestamp seen
    // so far (used to compute the next file's offset).
    void set_time_offset(double offset);
    double max_timestamp() const;

    // Write the accumulated data to `path`. Returns false on error.
    bool write(const std::string& path, std::string& error);

    void clear();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace mrc
