import sys
import struct
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))


class PduTest(unittest.TestCase):
    def test_existing_mrc_api(self):
        import dpkt
        from spa2_decoder.decode import load_engine

        payload = struct.pack('>IIHH', 0x123, 6, 2, 0) + b'\x12\x34'
        udp = dpkt.udp.UDP(sport=13000, dport=14000, data=payload)
        udp.ulen = len(udp)
        ip = dpkt.ip.IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02', p=17, data=udp)
        ip.len = len(ip)
        packet = bytes(dpkt.ethernet.Ethernet(type=0x0800, data=ip))
        with tempfile.TemporaryDirectory() as folder:
            capture = Path(folder) / 'mrc.pcap'
            with capture.open('wb') as output:
                dpkt.pcap.Writer(output).writepkt(packet, ts=1.0)
            engine = load_engine()
            routes = [(0x0a000001, 13000, 0)]
            arrays = engine.extract_frames(str(capture), routes)
            self.assertEqual(arrays['frame_id'].tolist(), [0x123])
            self.assertEqual(arrays['payload'][0, :2].tolist(), [0x12, 0x34])
            combined = engine.extract_all(str(capture), routes, [])
            self.assertEqual(combined['frame_id'].tolist(), [0x123])
            self.assertEqual(len(combined['pdu_id']), 0)

    def test_native_framing_and_cmp(self):
        import dpkt
        from spa2_decoder.decode import load_engine

        engine = load_engine()
        self.assertIsNotNone(engine)
        records = struct.pack('>II', 0x100, 2) + b'\x12\x34'
        records += struct.pack('>II', 0x101, 1) + b'\x56'
        udp = dpkt.udp.UDP(sport=13000, dport=14000, data=records)
        udp.ulen = len(udp)
        ip = dpkt.ip.IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02',
                        p=17, data=udp)
        ip.len = len(ip)
        packet = bytes(dpkt.ethernet.Ethernet(src=b'\x02\x00\x00\x00\x00\x01',
                        dst=b'\x02\x00\x00\x00\x00\x02', type=0x0800, data=ip))
        cmp_payload = b'\x00' * 6 + packet
        wrapped = b'\x00' * 6 + b'\x00\x16\x81\x00\x00\x01' + b'\x99\xfe'
        wrapped += struct.pack('>BBHBBH', 1, 0, 1, 1, 0, 0)
        wrapped += struct.pack('>QIBBH', 1000000000, 1, 0, 0x80, len(cmp_payload)) + cmp_payload
        wrapped += struct.pack('>QIBBH', 1001000000, 1, 0, 0x80, len(cmp_payload)) + cmp_payload
        with tempfile.TemporaryDirectory() as folder:
            capture = Path(folder) / 'test.pcap'
            with capture.open('wb') as output:
                writer = dpkt.pcap.Writer(output)
                writer.writepkt(packet, ts=2.0)
                writer.writepkt(packet, ts=2.000001)
                writer.writepkt(wrapped, ts=3.0)
            arrays = engine.extract_all(str(capture), [], [], 0, [14000])
            self.assertEqual(arrays['error'], '')
            self.assertEqual(arrays['pdu_id'].tolist(), [0x100, 0x101] * 3)
            self.assertEqual(arrays['pdu_duplicates'], 1)
            self.assertEqual(arrays['pdu_errors'], 0)
            self.assertAlmostEqual(arrays['pdu_timestamp'][2], 2.999)
            self.assertAlmostEqual(arrays['pdu_timestamp'][4], 3.0)
            limited = engine.extract_all(str(capture), [], [], 1, [14000])
            self.assertEqual(len(limited['pdu_id']), 2)
            wrong_port = engine.extract_all(str(capture), [], [], 0, [14001])
            self.assertEqual(len(wrong_port['pdu_id']), 0)

    def test_native_truncated_record(self):
        import dpkt
        from spa2_decoder.decode import load_engine

        udp = dpkt.udp.UDP(sport=13000, dport=14000,
                          data=struct.pack('>II', 0x100, 200) + b'\x00')
        udp.ulen = len(udp)
        ip = dpkt.ip.IP(p=17, data=udp)
        ip.len = len(ip)
        packet = bytes(dpkt.ethernet.Ethernet(type=0x0800, data=ip))
        with tempfile.TemporaryDirectory() as folder:
            capture = Path(folder) / 'bad.pcap'
            with capture.open('wb') as output:
                dpkt.pcap.Writer(output).writepkt(packet, ts=1.0)
            arrays = load_engine().extract_all(str(capture), [], [], 0, [14000])
            self.assertEqual(len(arrays['pdu_id']), 0)
            self.assertEqual(arrays['pdu_errors'], 1)

    def test_layout_binding_and_scaling(self):
        from spa2_decoder.pdu import load_config, decode_record

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'Signal_PDU_identifiers_ETH').write_text('"1","Example.Example"\n')
            (root / 'Signal_PDU_Binding_PDU_Transport_ETH').write_text('"100","1"\n')
            (root / 'Signal_PDU_signal_list_ETH').write_text(
                '"1","3","0","Pad","x","uint","TRUE","8","4","1","0","FALSE","-1","TRUE"\n'
                '"1","3","1","Signed","x","sint","TRUE","8","4","2","1","FALSE","-1","FALSE"\n'
                '"1","3","2","Little","x","uint","FALSE","16","16","1","0","FALSE","-1","FALSE"\n')
            (root / 'decode_as_entries').write_text(
                'decode_as_entry: udp.port,14000,(none),PDU Transport\n')
            layouts, ports = load_config(root)
            self.assertEqual(ports, {14000})
            self.assertEqual(layouts[0x100].min_bytes, 3)
            signals = {}
            self.assertTrue(decode_record(layouts[0x100], bytes([0xAF, 0x34, 0x12]), 1.0, signals))
            self.assertEqual(signals['PDU::Example::Signed'].values, [-1.0])
            self.assertEqual(signals['PDU::Example::Little'].values, [4660.0])
            self.assertFalse(decode_record(layouts[0x100], b'\x00', 2.0, signals))

    def test_reduction_preserves_step_edges(self):
        from spa2_decoder.pdu import PduLayout, PduSignal, decode_record

        layout = PduLayout('Example', 1, (PduSignal('Value', 0, 8, True, False, 1, 0),))
        signals = {}
        for timestamp, value in enumerate([0, 0, 0, 1, 1, 1, 0]):
            decode_record(layout, bytes([value]), float(timestamp), signals)
        self.assertEqual(signals['PDU::Example::Value'].timestamps, [0, 2, 3, 5, 6])

    def test_accumulation_statistics(self):
        import numpy as np
        from spa2_decoder.pdu import PduLayout, PduSignal, PduStats, accumulate

        arrays = {'pdu_errors': 1, 'pdu_duplicates': 2,
                  'pdu_id': np.array([1, 2, 1]), 'pdu_timestamp': np.array([1., 2., 3.]),
                  'pdu_payload': np.array([10], dtype=np.uint8),
                  'pdu_payload_off': np.array([0, 0, 1]), 'pdu_payload_len': np.array([1, 1, 0])}
        layouts = {1: PduLayout('Example', 1, (PduSignal('Value', 0, 8, True, False, 1, 0),))}
        signals, stats = {}, PduStats()
        accumulate(arrays, layouts, signals, stats, False)
        self.assertEqual((stats.records, stats.decoded, stats.unknown, stats.errors), (3, 1, 1, 2))
        self.assertEqual(stats.duplicates, 2)
        self.assertEqual(signals['PDU::Example::Value'].values, [10.])


if __name__ == '__main__':
    unittest.main()