#include "mrc_decoder/mdf_writer.hpp"

#include <algorithm>
#include <map>
#include <vector>

namespace mrc {

// Accumulated per-signal series, grouped by signal_group for MDF channel groups.
struct MdfWriter::Impl {
    struct Series {
        std::string group;
        std::string name;
        std::vector<double> time;
        std::vector<double> value;
    };
    std::map<uint32_t, Series> series;   // by signal_index
    double time_offset = 0.0;
    double max_ts = 0.0;
};

MdfWriter::MdfWriter() : impl_(std::make_unique<Impl>()) {}
MdfWriter::~MdfWriter() = default;

void MdfWriter::add(const SignalSample& s, const DecodeModel& model) {
    auto& it = impl_->series[s.signal_index];
    if (it.name.empty()) {
        const SignalInfo* info = model.signal(s.signal_index);
        if (info) {
            it.group = info->signal_group;
            it.name = info->signal_name;
        } else {
            it.group = "UNKNOWN";
            it.name = "signal_" + std::to_string(s.signal_index);
        }
    }
    double t = s.timestamp + impl_->time_offset;
    it.time.push_back(t);
    it.value.push_back(s.value);
    impl_->max_ts = std::max(impl_->max_ts, t);
}

void MdfWriter::set_time_offset(double offset) { impl_->time_offset = offset; }
double MdfWriter::max_timestamp() const { return impl_->max_ts; }
void MdfWriter::clear() { impl_->series.clear(); impl_->max_ts = 0.0; }

bool MdfWriter::write(const std::string& path, std::string& error) {
#if defined(MRC_HAVE_MDFLIB)
    // INTEGRATION TODO (mdflib):
    //   1. Create an MdfWriter (MdfWriterType::Mdf4Basic), Init(path).
    //   2. One data group; for each distinct signal_group create a channel group
    //      with a master (time) channel + one channel per signal in that group.
    //   3. Stream the accumulated (time, value) pairs and FinalizeMeasurement().
    //   Exact API depends on the installed mdflib version; wire it here.
    (void)path;
    error = "mdflib writing not yet implemented (integration TODO)";
    return false;
#else
    // Fallback when mdflib is not available at build time: emit a CSV sidecar so
    // the pipeline is verifiable end-to-end. Replace with true MF4 once mdflib
    // is linked (define MRC_HAVE_MDFLIB).
    std::string csv = path;
    auto pos = csv.rfind(".mf4");
    if (pos != std::string::npos) csv.replace(pos, 4, ".csv");
    FILE* f = std::fopen(csv.c_str(), "w");
    if (!f) { error = "cannot open output: " + csv; return false; }
    std::fprintf(f, "signal_group,signal_name,timestamp,value\n");
    for (const auto& [idx, s] : impl_->series) {
        (void)idx;
        for (size_t i = 0; i < s.time.size(); ++i) {
            std::fprintf(f, "%s,%s,%.9f,%.9g\n",
                         s.group.c_str(), s.name.c_str(), s.time[i], s.value[i]);
        }
    }
    std::fclose(f);
    return true;
#endif
}

}  // namespace mrc
