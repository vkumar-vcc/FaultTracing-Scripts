import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from streamlit.testing.v1 import AppTest

from streamlit_workflow import decode_sat_readout, run_standby_summary


APP = Path(__file__).with_name("decoder.py")
SAMPLE_READOUT = """Tester -> 1D12 224721
Complete Response: 1D12 6247216B560000
Timestamp when shutdown was requested to ShutdownManagerHIA 1: 1791450000
Shutdown Type 1: Sleep
VCUShutdownIntent from VMM 1: StandbyWithInSystemTestRequested
ISTWakeUpTimer 1: 60
Flag indicating shutdown not successful 1: False

Tester -> 1D0D 22FE03
Complete Response: 1D0D 62FE0300000000
Time of error in Error slot 1: 2026-10-08T09:00:01
Error slot 1 - Error code: 01
"""


class CombinedAppTests(unittest.TestCase):
    def test_app_renders_vin_and_readout_workflow(self):
        app = AppTest.from_file(str(APP)).run(timeout=20)

        self.assertFalse(app.exception)
        self.assertEqual(app.title[0].value, "Vehicle readout analysis")
        self.assertIn("VIN", [widget.label for widget in app.text_input])
        self.assertEqual(
            [widget.label for widget in app.selectbox][:1], ["Readout source"]
        )
        self.assertEqual(
            [widget.label for widget in app.file_uploader],
            ["SDDB file"],
        )
        self.assertIn("Load readouts", [widget.label for widget in app.button])
        self.assertTrue(any(
            "load readouts" in element.value.lower() for element in app.info
        ))

    def test_upload_source_offers_log_upload(self):
        app = AppTest.from_file(str(APP)).run(timeout=20)
        app.selectbox(key="readout_source").select("Upload or server path").run()

        self.assertFalse(app.exception)
        self.assertEqual(
            [widget.label for widget in app.file_uploader],
            ["Log or YAML readout", "SDDB file"],
        )

    def test_vin_readout_source_prompts_for_loaded_vin_readouts(self):
        app = AppTest.from_file(str(APP)).run(timeout=20)

        self.assertFalse(app.exception)
        self.assertTrue(any(
            "load readouts" in element.value.lower() for element in app.info
        ))

    def test_translated_readout_is_input_to_standby_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            sddb_path = Path(directory) / "minimal.sddb"
            sddb_path.write_text(
                '<Database><ECU Name="HIA" address="1D0D"></ECU></Database>',
                encoding="utf-8",
            )
            diagnostics = io.StringIO()
            with contextlib.redirect_stdout(diagnostics):
                translated, blocks, sat_diagnostics = decode_sat_readout(
                    SAMPLE_READOUT,
                    "readout.log",
                    str(sddb_path),
                    sddb_path.name,
                )

        self.assertIn("# SAT_Readout_decoder", translated)
        self.assertEqual(len(blocks), 2)
        self.assertTrue(all(block["content"] for block in blocks))

        exit_code, summary, error = run_standby_summary(
            translated,
            no_error_reference=True,
        )
        self.assertEqual(exit_code, 0, error)
        self.assertIn("Shutdown Type", summary)
        self.assertIn("FE03 error slots", summary)
        self.assertNotIn("error_reference", sat_diagnostics)


if __name__ == "__main__":
    unittest.main()
