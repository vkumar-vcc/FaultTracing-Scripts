// Unit test: build a synthetic ARXML, load the decode model, verify decoded values.
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include "mrc_decoder/decode_model.hpp"

using namespace mrc;

static const char* kArxml = R"ARXML(<?xml version="1.0" encoding="UTF-8"?>
<AUTOSAR>
 <AR-PACKAGES><AR-PACKAGE><SHORT-NAME>Communication</SHORT-NAME><ELEMENTS>
  <COMPU-METHOD><SHORT-NAME>cm_speed</SHORT-NAME>
   <COMPU-INTERNAL-TO-PHYS><COMPU-SCALES><COMPU-SCALE><COMPU-RATIONAL-COEFFS>
     <COMPU-NUMERATOR><V>-40</V><V>0.1</V></COMPU-NUMERATOR>
     <COMPU-DENOMINATOR><V>1</V></COMPU-DENOMINATOR>
   </COMPU-RATIONAL-COEFFS></COMPU-SCALE></COMPU-SCALES></COMPU-INTERNAL-TO-PHYS>
  </COMPU-METHOD>
  <I-SIGNAL><SHORT-NAME>sigA</SHORT-NAME><LENGTH>8</LENGTH>
   <NETWORK-REPRESENTATION-PROPS><SW-DATA-DEF-PROPS-VARIANTS><SW-DATA-DEF-PROPS-CONDITIONAL>
     <COMPU-METHOD-REF DEST="COMPU-METHOD">/Communication/cm_speed</COMPU-METHOD-REF>
   </SW-DATA-DEF-PROPS-CONDITIONAL></SW-DATA-DEF-PROPS-VARIANTS></NETWORK-REPRESENTATION-PROPS>
  </I-SIGNAL>
  <I-SIGNAL><SHORT-NAME>sigB</SHORT-NAME><LENGTH>16</LENGTH></I-SIGNAL>
  <I-SIGNAL-I-PDU><SHORT-NAME>pduX</SHORT-NAME><LENGTH>4</LENGTH>
   <I-SIGNAL-TO-PDU-MAPPINGS>
     <I-SIGNAL-TO-I-PDU-MAPPING><SHORT-NAME>m1</SHORT-NAME>
       <I-SIGNAL-REF DEST="I-SIGNAL">/Communication/sigA</I-SIGNAL-REF>
       <START-POSITION>0</START-POSITION>
       <PACKING-BYTE-ORDER>MOST-SIGNIFICANT-BYTE-LAST</PACKING-BYTE-ORDER>
     </I-SIGNAL-TO-I-PDU-MAPPING>
     <I-SIGNAL-TO-I-PDU-MAPPING><SHORT-NAME>m2</SHORT-NAME>
       <I-SIGNAL-REF DEST="I-SIGNAL">/Communication/sigB</I-SIGNAL-REF>
       <START-POSITION>8</START-POSITION>
       <PACKING-BYTE-ORDER>MOST-SIGNIFICANT-BYTE-LAST</PACKING-BYTE-ORDER>
     </I-SIGNAL-TO-I-PDU-MAPPING>
   </I-SIGNAL-TO-PDU-MAPPINGS>
  </I-SIGNAL-I-PDU>
  <CAN-FRAME><SHORT-NAME>frameX</SHORT-NAME>
   <PDU-TO-FRAME-MAPPINGS><PDU-TO-FRAME-MAPPING><SHORT-NAME>p2f</SHORT-NAME>
     <PDU-REF DEST="I-SIGNAL-I-PDU">/Communication/pduX</PDU-REF>
   </PDU-TO-FRAME-MAPPING></PDU-TO-FRAME-MAPPINGS>
  </CAN-FRAME>
  <CAN-FRAME-TRIGGERING><SHORT-NAME>ftX</SHORT-NAME><IDENTIFIER>256</IDENTIFIER>
   <FRAME-REF DEST="CAN-FRAME">/Communication/frameX</FRAME-REF>
  </CAN-FRAME-TRIGGERING>
 </ELEMENTS></AR-PACKAGE></AR-PACKAGES>
</AUTOSAR>
)ARXML";

static bool approx(double a, double b) { return std::fabs(a - b) < 1e-6; }

int main() {
    std::string path = "/tmp/mrc_decode_fixture.arxml";
    { std::ofstream f(path); f << kArxml; }

    DecodeModel model;
    std::string err;
    if (!DecodeModel::load_from_arxml(path, model, err)) {
        std::fprintf(stderr, "load failed: %s\n", err.c_str());
        return 1;
    }
    assert(model.pdu_count() == 1);
    assert(model.signal_count() == 2);

    const PduLayout* pdu = model.pdu_by_name("pduX");
    assert(pdu && pdu->signals.size() == 2);

    // payload: sigA=0xC8(200) -> 200*0.1-40 = -20 ; sigB=0x1234 little-endian = 4660
    std::vector<uint8_t> payload = {0xC8, 0x34, 0x12, 0x00};
    std::vector<SignalSample> out;
    // Route by frame id 256 (0x100) via decode_eth fallback.
    model.decode_eth(DecodeModel::eth_key(0, 0, 256), payload.data(), payload.size(), 1.5, out);
    assert(out.size() == 2);

    double a = -1e9, b = -1e9;
    for (auto& s : out) {
        const SignalInfo* info = model.signal(s.signal_index);
        assert(info);
        if (info->signal_name == "sigA") a = s.value;
        if (info->signal_name == "sigB") b = s.value;
        assert(info->signal_group == "pduX");
        assert(approx(s.timestamp, 1.5));
    }
    if (!approx(a, -20.0)) { std::fprintf(stderr, "sigA=%f expected -20\n", a); return 1; }
    if (!approx(b, 4660.0)) { std::fprintf(stderr, "sigB=%f expected 4660\n", b); return 1; }

    std::printf("decode_model test OK (sigA=%.1f, sigB=%.0f)\n", a, b);
    return 0;
}
