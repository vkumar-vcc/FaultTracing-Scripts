import struct
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))


ARXML = """<?xml version="1.0" encoding="UTF-8"?>
<AUTOSAR xmlns="http://autosar.org/schema/r4.0">
  <SW-BASE-TYPE><SHORT-NAME>uint8</SHORT-NAME><BASE-TYPE-SIZE>8</BASE-TYPE-SIZE><BASE-TYPE-ENCODING>NONE</BASE-TYPE-ENCODING></SW-BASE-TYPE>
  <SW-BASE-TYPE><SHORT-NAME>sint16</SHORT-NAME><BASE-TYPE-SIZE>16</BASE-TYPE-SIZE><BASE-TYPE-ENCODING>2C</BASE-TYPE-ENCODING></SW-BASE-TYPE>
  <COMPU-METHOD><SHORT-NAME>Lin2</SHORT-NAME><CATEGORY>LINEAR</CATEGORY>
    <COMPU-INTERNAL-TO-PHYS><COMPU-SCALES><COMPU-SCALE><COMPU-RATIONAL-COEFFS>
      <COMPU-NUMERATOR><V>1</V><V>2</V></COMPU-NUMERATOR>
      <COMPU-DENOMINATOR><V>1</V></COMPU-DENOMINATOR>
    </COMPU-RATIONAL-COEFFS></COMPU-SCALE></COMPU-SCALES></COMPU-INTERNAL-TO-PHYS>
  </COMPU-METHOD>
  <I-SIGNAL><SHORT-NAME>sigA</SHORT-NAME><LENGTH>8</LENGTH>
    <NETWORK-REPRESENTATION-PROPS><SW-DATA-DEF-PROPS-VARIANTS><SW-DATA-DEF-PROPS-CONDITIONAL>
      <BASE-TYPE-REF>/x/uint8</BASE-TYPE-REF><COMPU-METHOD-REF>/x/Lin2</COMPU-METHOD-REF>
    </SW-DATA-DEF-PROPS-CONDITIONAL></SW-DATA-DEF-PROPS-VARIANTS></NETWORK-REPRESENTATION-PROPS>
  </I-SIGNAL>
  <I-SIGNAL><SHORT-NAME>sigB</SHORT-NAME><LENGTH>16</LENGTH>
    <NETWORK-REPRESENTATION-PROPS><SW-DATA-DEF-PROPS-VARIANTS><SW-DATA-DEF-PROPS-CONDITIONAL>
      <BASE-TYPE-REF>/x/sint16</BASE-TYPE-REF>
    </SW-DATA-DEF-PROPS-CONDITIONAL></SW-DATA-DEF-PROPS-VARIANTS></NETWORK-REPRESENTATION-PROPS>
  </I-SIGNAL>
  <I-SIGNAL-I-PDU><SHORT-NAME>ExamplePdu</SHORT-NAME><LENGTH>3</LENGTH>
    <I-SIGNAL-TO-I-PDU-MAPPINGS>
      <I-SIGNAL-TO-I-PDU-MAPPING><SHORT-NAME>isSigA_ExamplePduIPdu01_mrx</SHORT-NAME>
        <I-SIGNAL-REF>/x/sigA</I-SIGNAL-REF><PACKING-BYTE-ORDER>MOST-SIGNIFICANT-BYTE-LAST</PACKING-BYTE-ORDER><START-POSITION>0</START-POSITION>
      </I-SIGNAL-TO-I-PDU-MAPPING>
      <I-SIGNAL-TO-I-PDU-MAPPING><SHORT-NAME>isSigB_ExamplePduIPdu01_mrx</SHORT-NAME>
        <I-SIGNAL-REF>/x/sigB</I-SIGNAL-REF><PACKING-BYTE-ORDER>MOST-SIGNIFICANT-BYTE-LAST</PACKING-BYTE-ORDER><START-POSITION>8</START-POSITION>
      </I-SIGNAL-TO-I-PDU-MAPPING>
    </I-SIGNAL-TO-I-PDU-MAPPINGS>
  </I-SIGNAL-I-PDU>
  <SOCKET-ADDRESS><SHORT-NAME>SaRx</SHORT-NAME>
    <APPLICATION-ENDPOINT><SHORT-NAME>Ep</SHORT-NAME>
      <TP-CONFIGURATION><UDP-TP><UDP-TP-PORT><PORT-NUMBER>14000</PORT-NUMBER></UDP-TP-PORT></UDP-TP></TP-CONFIGURATION>
    </APPLICATION-ENDPOINT>
    <STATIC-SOCKET-CONNECTIONS><STATIC-SOCKET-CONNECTION><SHORT-NAME>Conn</SHORT-NAME>
      <I-PDU-IDENTIFIERS><SO-CON-I-PDU-IDENTIFIER-REF-CONDITIONAL>
        <SO-CON-I-PDU-IDENTIFIER-REF DEST="SO-CON-I-PDU-IDENTIFIER">/Comm/SetA/Id1</SO-CON-I-PDU-IDENTIFIER-REF>
      </SO-CON-I-PDU-IDENTIFIER-REF-CONDITIONAL></I-PDU-IDENTIFIERS>
    </STATIC-SOCKET-CONNECTION></STATIC-SOCKET-CONNECTIONS>
  </SOCKET-ADDRESS>
  <SOCKET-CONNECTION-IPDU-IDENTIFIER-SET><SHORT-NAME>SetA</SHORT-NAME>
    <I-PDU-IDENTIFIERS><SO-CON-I-PDU-IDENTIFIER><SHORT-NAME>Id1</SHORT-NAME>
      <PDU-TRIGGERING-REF DEST="PDU-TRIGGERING">/x/PtExample</PDU-TRIGGERING-REF></SO-CON-I-PDU-IDENTIFIER></I-PDU-IDENTIFIERS>
  </SOCKET-CONNECTION-IPDU-IDENTIFIER-SET>
  <PDU-TRIGGERING><SHORT-NAME>PtExample</SHORT-NAME><I-PDU-REF>/x/ExamplePdu</I-PDU-REF></PDU-TRIGGERING>
</AUTOSAR>
"""

CSV = "Name,Id,Lbit\nExamplePdu,100,24\nTcpThing,TCP,0\n"


class PduGenerateTest(unittest.TestCase):
    def _generate(self, folder: Path):
        from spa2_decoder.pdu_generate import generate

        (folder / "sys.arxml").write_text(ARXML, encoding="utf-8")
        (folder / "backbone.csv").write_text(CSV, encoding="utf-8")
        out = folder / "pdu"
        result = generate(folder / "sys.arxml", folder / "backbone.csv", out)
        return out, result

    def test_generated_files_match_expected(self):
        with tempfile.TemporaryDirectory() as folder:
            out, result = self._generate(Path(folder))
            self.assertEqual((result["pdus"], result["signals"], result["ports"]), (1, 2, 1))
            identifiers = (out / "Signal_PDU_identifiers_ETH").read_text().splitlines()
            self.assertIn('"1","ExamplePdu.ExamplePdu"', identifiers)
            binding = (out / "Signal_PDU_Binding_PDU_Transport_ETH").read_text().splitlines()
            self.assertIn('"100","1"', binding)
            signals = (out / "Signal_PDU_signal_list_ETH").read_text()
            self.assertIn('"1","3","0","isSigA","ExamplePdu.ExamplePdu.isSigA","uint","FALSE","8","8","2","1"', signals)
            self.assertIn('"1","3","1","isSigB","ExamplePdu.ExamplePdu.isSigB","sint","FALSE","16","16","1","0"', signals)
            decode_as = (out / "decode_as_entries").read_text()
            self.assertIn("decode_as_entry: udp.port,14000,(none),PDU Transport", decode_as)

    def test_roundtrip_through_loader(self):
        from spa2_decoder.pdu import decode_record, load_config

        with tempfile.TemporaryDirectory() as folder:
            out, _ = self._generate(Path(folder))
            layouts, ports = load_config(out)
            self.assertEqual(ports, {14000})
            signals = {}
            self.assertTrue(decode_record(layouts[0x100], bytes([0x05, 0x34, 0x12]), 1.0, signals))
            self.assertEqual(signals["PDU::ExamplePdu::isSigA"].values, [11.0])
            self.assertEqual(signals["PDU::ExamplePdu::isSigB"].values, [4660.0])

    def test_missing_ports_raises(self):
        from spa2_decoder.pdu_generate import generate

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            no_socket = ARXML.replace(ARXML[ARXML.index("  <SOCKET-ADDRESS"):ARXML.index("</AUTOSAR>")], "")
            (root / "sys.arxml").write_text(no_socket, encoding="utf-8")
            (root / "backbone.csv").write_text(CSV, encoding="utf-8")
            with self.assertRaises(ValueError):
                generate(root / "sys.arxml", root / "backbone.csv", root / "pdu")

    def test_cli(self):
        from spa2_decoder.pdu_generate import main

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "sys.arxml").write_text(ARXML, encoding="utf-8")
            (root / "backbone.csv").write_text(CSV, encoding="utf-8")
            code = main(["--arxml", str(root / "sys.arxml"), "--csv", str(root / "backbone.csv"),
                         "-o", str(root / "pdu")])
            self.assertEqual(code, 0)
            self.assertTrue((root / "pdu" / "decode_as_entries").is_file())


if __name__ == "__main__":
    unittest.main()
