import ast
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from streamlit_workflow import decode_sat_readout, run_standby_summary
from interpretation import finding, source_readout_blocks
from compare import compare_blocks, comparison_markdown, group_changed_rows


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


class ReadoutInteractionTests(unittest.TestCase):
    def test_comparison_groups_fields_by_readout_in_ui_and_download(self):
        older = [
            {
                "row_id": index, "ecu_id": "1D0D", "ecu_name": "HIA",
                "readout": request, "description": description, "content": content,
            }
            for index, (request, description, content) in enumerate([
                ("22 D0 DF", "ADC", "Voltage A: 12 V\nVoltage B: 13 V"),
                ("22 D9 03", "Startup", "Start time: 100 ms"),
            ])
        ]
        newer = [
            {**older[0], "content": "Voltage A: 13 V\nVoltage B: 14 V"},
            {**older[1], "content": "Start time: 90 ms"},
        ]
        results = compare_blocks(older, newer, {"1D0D"})
        groups = group_changed_rows(results[0]["rows"])
        self.assertEqual(list(groups), ["22 D0 DF | ADC", "22 D9 03 | Startup"])
        self.assertEqual([len(rows) for rows in groups.values()], [2, 1])
        report = comparison_markdown("older.log", "newer.log", results)
        self.assertIn("#### 22 D0 DF | ADC (2 fields changed)", report)
        self.assertIn("| Field | Older | Newer | Change |", report)

        app = AppTest.from_string(
            APP.read_text(encoding="utf-8")
            + """
readouts = [{"path": "older.log", "label": "Older"}]
render_compare(st.session_state["test_result"], "newer.log")
"""
        )
        app.session_state["test_result"] = {
            "signature": "compare-test", "blocks": newer, "ecu_names": {"1D0D": "HIA"},
        }
        app.session_state["comparison"] = {
            "signature": "compare-test", "other_name": "older.log", "other_blocks": older,
        }
        app.run(timeout=20)
        self.assertFalse(app.exception)
        self.assertIn(
            "22 D0 DF | ADC · 2 fields changed", [item.label for item in app.expander]
        )
        app.text_input(key="compare_filter").set_value("Voltage A").run()
        self.assertFalse(app.exception)
        labels = [item.label for item in app.expander]
        self.assertIn("22 D0 DF | ADC · 1 fields changed", labels)
        self.assertNotIn("22 D9 03 | Startup · 1 fields changed", labels)

    def test_summary_finding_shows_original_source_response(self):
        content = "Tester -> 1D0D 22FE14\nComplete Response: 1D0D 62FE1401\nFailure counter: 1"
        app = AppTest.from_string(
            APP.read_text(encoding="utf-8")
            + '\nrender_interpretation(st.session_state["test_result"], [])\n'
        )
        app.session_state["test_result"] = {
            "blocks": [{"ecu_id": "1D0D", "readout": "22 FE 14", "content": content}],
            "interpretation": {
                "app_states": {},
                "findings": [finding(
                    "HPA standby and resume", "issue", "Recorded standby failure",
                    sources=["HIA 22 FE 14", "HIA 22 FE 4D"],
                )],
                "timeline": [],
                "missing": [],
                "errors": [],
            },
        }
        app.run(timeout=20)
        self.assertFalse(app.exception)
        self.assertIn("Source readouts / raw response", [item.label for item in app.expander])
        self.assertEqual(app.code[0].value, content)
        self.assertTrue(any("not present" in item.value for item in app.info))

    def test_source_readouts_match_ecu_and_all_grouped_requests(self):
        blocks = [
            {"ecu_id": "1D0D", "readout": "19 03", "content": "first"},
            {"ecu_id": "1D0D", "readout": "1904", "content": "second"},
            {"ecu_id": "1D0E", "readout": "19 03", "content": "other ECU"},
            {"ecu_id": "1D0D", "readout": "22 FE 14", "content": "other DID"},
        ]
        self.assertEqual(source_readout_blocks(blocks, "HIA 19 03 / 19 04"), blocks[:2])
        self.assertEqual(source_readout_blocks(blocks, "HIA 22 FE 14"), blocks[3:])
        self.assertEqual(source_readout_blocks(blocks, "HPA 22 FE 14"), [])

    def browser_app(self):
        app = AppTest.from_string(
            APP.read_text(encoding="utf-8")
            + """
render_translated_browser(st.session_state["test_result"])
"""
        )
        app.session_state["test_result"] = {
            "signature": "interaction-test",
            "blocks": [
                {
                    "row_id": row_id,
                    "ecu_id": ecu_id,
                    "ecu_name": ecu_id,
                    "readout": "22 FE 03",
                    "description": "Errors",
                    "lookup_text": f"{ecu_id} 22 FE 03 ERRORS",
                    "content": f"Decoded {row_id}",
                }
                for row_id, ecu_id in enumerate(["HIA", "HIA", "HIB"])
            ],
        }
        return app.run(timeout=20)

    def test_lookup_accepts_compact_spaced_and_mixed_case_hex(self):
        app = self.browser_app()
        app.session_state["test_result"]["blocks"][0]["lookup_text"] = "HIA 22 47 CF STATUS"
        app.run()
        for query in ("22 47 cf", "2247cf", "22 47CF", "2247CF", "47cf", "HIA 2247cf"):
            with self.subTest(query=query):
                app.text_input(key="readout_lookup_input").set_value(query)
                app.button(key="FormSubmitter:translated_metadata_lookup-Lookup").click().run()
                self.assertFalse(app.exception)
                self.assertEqual(app.session_state["rt_visible_ids"], [0])

        app.text_input(key="readout_lookup_input").set_value("HIA")
        app.button(key="FormSubmitter:translated_metadata_lookup-Lookup").click().run()
        self.assertEqual(app.session_state["rt_visible_ids"], [0, 1])
        app.text_input(key="readout_lookup_input").set_value("2247ce")
        app.button(key="FormSubmitter:translated_metadata_lookup-Lookup").click().run()
        self.assertFalse(app.exception)
        self.assertTrue(app.info)
        app.button(key="FormSubmitter:translated_metadata_lookup-Reset").click().run()
        self.assertEqual(app.session_state["rt_visible_ids"], [0, 1, 2])

    def test_tree_uses_stable_dataframe_for_expansion_and_selection(self):
        app = self.browser_app()
        self.assertFalse(app.exception)
        tree = app.dataframe[0]
        self.assertEqual(tree.proto.editing_mode, 0)
        self.assertEqual(len(tree.value), 2)
        columns = json.loads(tree.proto.columns)
        for name in ("Open", "Show"):
            self.assertEqual(columns[name]["width"], 40)
            self.assertTrue(columns[name]["pinned"])
            self.assertEqual(columns[name]["label"], " ")

        app.button(key="rt_expand_all").click().run()
        self.assertFalse(app.exception)
        self.assertEqual(len(app.dataframe[0].value), 5)
        self.assertEqual(app.session_state["rt_expanded"], {"HIA", "HIB"})

        app.button(key="rt_select_all").click().run()
        self.assertFalse(app.exception)
        self.assertEqual(app.session_state["rt_selected"], {0, 1, 2})
        self.assertTrue(all(
            value == ":material/check_box:"
            for value in app.dataframe[0].value["Show"]
        ))

        app.button(key="rt_collapse_all").click().run()
        self.assertFalse(app.exception)
        self.assertEqual(len(app.dataframe[0].value), 2)
        self.assertEqual(app.session_state["rt_selected"], {0, 1, 2})

        app.button(key="rt_clear_selection").click().run()
        self.assertFalse(app.exception)
        self.assertEqual(app.session_state["rt_selected"], set())

    def test_content_search_and_lookup_filters_work_together(self):
        app = self.browser_app()
        app.session_state["test_result"]["blocks"][0]["content"] = "Status: 22 47 CF"
        app.text_input(key="readout_search_input").set_value("2247cf")
        app.button(key="FormSubmitter:translated_content_search-Search").click().run()
        self.assertFalse(app.exception)
        self.assertEqual(app.session_state["rt_visible_ids"], [0])
        app.text_input(key="readout_lookup_input").set_value("HIB")
        app.button(key="FormSubmitter:translated_metadata_lookup-Lookup").click().run()
        self.assertFalse(app.exception)
        self.assertEqual(app.session_state["rt_visible_ids"], [])
        app.button(key="FormSubmitter:translated_metadata_lookup-Reset").click().run()
        self.assertEqual(app.session_state["rt_visible_ids"], [0])
        app.button(key="FormSubmitter:translated_content_search-Clear").click().run()
        self.assertFalse(app.exception)
        self.assertEqual(app.session_state["rt_visible_ids"], [0, 1, 2])

    def test_show_callback_toggles_ecu_and_individual_readouts(self):
        app = AppTest.from_string(
            APP.read_text(encoding="utf-8")
            + """
from types import SimpleNamespace
st.session_state["rt_grouped"] = {
    "HIA": [{"row_id": 0}, {"row_id": 1}],
}
st.session_state["rt_nodes"] = [
    ("ecu", "HIA", None), ("readout", "HIA", 0), ("readout", "HIA", 1),
]
st.session_state["rt_expanded"] = set()
st.session_state["rt_open_click"] = SimpleNamespace(row=0)
toggle_ecu_click()
assert st.session_state["rt_expanded"] == {"HIA"}
toggle_ecu_click()
assert st.session_state["rt_expanded"] == set()
st.session_state["rt_selected"] = set()
for row, expected in [(0, {0, 1}), (1, {1}), (0, {0, 1}), (0, set())]:
    st.session_state["rt_show_click"] = SimpleNamespace(row=row)
    toggle_readout_click()
    assert st.session_state["rt_selected"] == expected
assert st.session_state["rt_dirty"]
"""
        ).run(timeout=20)
        self.assertFalse(app.exception)

    def test_baseline_lookup_is_a_fragment_and_retains_results(self):
        result = {
            "rows": [],
            "seconds": 1,
            "looked_up": 0,
            "ignored": [],
            "not_found": [],
        }
        app = AppTest.from_string(
            APP.read_text(encoding="utf-8")
            + """
render_baselines(st.session_state["test_result"], [])
"""
        )
        app.session_state["test_result"] = {}
        with (
            patch("baselines.stored_username", return_value=""),
            patch("baselines.connect") as connect_mock,
            patch("baselines.lookup_main_int_baselines", return_value=result) as lookup_mock,
        ):
            app.run(timeout=20)
            self.assertFalse(app.exception)
            button = app.button(key="lookup_baselines")
            function = next(
                node for node in ast.parse(APP.read_text(encoding="utf-8")).body
                if isinstance(node, ast.FunctionDef) and node.name == "render_baselines"
            )
            self.assertIn(
                "st.fragment", [ast.unparse(node) for node in function.decorator_list]
            )
            button.click().run()
            self.assertFalse(app.exception)
            connect_mock.assert_called_once()
            lookup_mock.assert_called_once()
            self.assertEqual(app.session_state["test_result"]["baselines"], result)
            self.assertEqual(app.status[0].state, "complete")


if __name__ == "__main__":
    unittest.main()
