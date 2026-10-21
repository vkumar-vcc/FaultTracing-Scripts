"""Regression tests for pcapng capture reading."""
import struct
import tempfile
import unittest
from pathlib import Path

from analyzer_core.capture import CaptureReader, _idb_meta, _resync_pcapng


def _block(kind, body):
    length = 12 + len(body)
    return struct.pack('<II', kind, length) + body + struct.pack('<I', length)


def _capture():
    section = _block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    interface = _block(1, struct.pack('<HHI', 1, 0, 65535))
    someip = struct.pack('>HHIHHBBBB', 0x1234, 1, 8, 1, 2, 1, 1, 0, 0)
    udp = struct.pack('>HHHH', 30490, 30490, 8 + len(someip), 0) + someip
    ipv4 = struct.pack(
        '>BBHHHBBHII', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
        0xC0000201, 0xC0000202,
    ) + udp
    frame = b'\0' * 12 + b'\x08\x00' + ipv4
    packet = _block(
        6, struct.pack('<IIIII', 0, 0, 1500000, len(frame), len(frame))
        + frame + b'\0' * (-len(frame) % 4),
    )
    return section + interface + packet, packet


class CaptureReaderTests(unittest.TestCase):
    def test_interface_metadata(self):
        data, _ = _capture()
        self.assertEqual(_idb_meta(data), ((1,), (1e-6,)))

    def test_resync_validates_packet_block(self):
        _, packet = _capture()
        self.assertEqual(_resync_pcapng(b'\0' * 4 + packet, 4 + len(packet)), 4)

    def test_single_and_multiple_workers(self):
        data, _ = _capture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.pcapng'
            path.write_bytes(data)
            for workers in (1, 2):
                with self.subTest(workers=workers):
                    results = list(CaptureReader(str(path), workers))
                    self.assertEqual(len(results), 1)
                    records, hosts, conversations, frames = results[0]
                    self.assertEqual(frames, 1)
                    self.assertEqual(records, [
                        (0, 1.5, 0xC0000201, 0xC0000202, 0x1234, 1, 1, 2, 0, 0),
                    ])
                    self.assertEqual(set(hosts), {0xC0000201})
                    self.assertEqual(conversations, {
                        (0xC0000201, 0xC0000202, 0, 17, 30490, 30490):
                            [1, 1.5, 1.5, 44, 1],
                    })


if __name__ == '__main__':
    unittest.main()
