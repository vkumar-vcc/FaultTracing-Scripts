from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

from streamlit.testing.v1 import AppTest
import wsl_host


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import hosted_app


class HostingTests(unittest.TestCase):
    def test_home_renders_without_loading_tools(self):
        with patch.object(sys, "argv", ["hosted_app.py"]):
            app = AppTest.from_file(str(ROOT / "hosted_app.py")).run()
        self.assertEqual(list(app.exception), [])
        self.assertEqual(app.title[0].value, "Fault tracing tools")
        self.assertEqual(len(app.get("html")), 1 + len(hosted_app.TOOLS))

    def test_navigation_uses_same_origin_and_same_tab(self):
        navigation = hosted_app.navigation_html()
        for key in hosted_app.TOOLS:
            self.assertIn(f'href="/{key}/" target="_self"', navigation)
        self.assertIn('href="/" target="_self"', navigation)
        self.assertNotIn("localhost", navigation)

    def test_each_tool_executes_original_entrypoint(self):
        for key, (_, script) in hosted_app.TOOLS.items():
            with self.subTest(tool=key), patch.object(sys, "argv", ["hosted_app.py", key]), \
                    patch.object(sys, "path", list(sys.path)), \
                    patch.object(hosted_app.runpy, "run_path") as run_path, \
                    patch.object(hosted_app.st, "set_page_config"), \
                    patch.object(hosted_app.st, "html"):
                forwarded = []
                run_path.side_effect = lambda *args, **kwargs: forwarded.append(list(sys.argv))
                hosted_app.main()
                run_path.assert_called_once_with(str(script), run_name="__main__")
                self.assertEqual(forwarded, [[str(script)]])
                self.assertEqual(sys.argv, ["hosted_app.py", key])
                self.assertIn(str(script.parent), sys.path)
                hosted_app.main()
                self.assertEqual(run_path.call_count, 2)

    def test_can_argument_is_forwarded_without_router_argument(self):
        with patch.object(sys, "argv", ["hosted_app.py", "can", r"C:\logs\capture.parquet"]), \
                patch.object(sys, "path", list(sys.path)), \
                patch.object(hosted_app.runpy, "run_path") as run_path, \
                patch.object(hosted_app.st, "set_page_config"), \
                patch.object(hosted_app.st, "html"):
            forwarded = []
            run_path.side_effect = lambda *args, **kwargs: forwarded.append(list(sys.argv))
            hosted_app.main()
            self.assertEqual(forwarded[0][1:], [r"C:\logs\capture.parquet"])
            self.assertEqual(sys.argv[1:], ["can", r"C:\logs\capture.parquet"])

    def test_script_arguments_restored_when_tool_stops(self):
        with patch.object(sys, "argv", ["hosted_app.py", "can"]), \
                patch.object(sys, "path", list(sys.path)), \
                patch.object(hosted_app.runpy, "run_path", side_effect=SystemExit), \
                patch.object(hosted_app.st, "set_page_config"), \
                patch.object(hosted_app.st, "html"):
            with self.assertRaises(SystemExit):
                hosted_app.main()
            self.assertEqual(sys.argv, ["hosted_app.py", "can"])

    def test_unknown_tool_reports_error(self):
        app = AppTest.from_file(str(ROOT / "hosted_app.py"))
        with patch.object(sys, "argv", ["hosted_app.py", "unknown"]):
            app.run()
        self.assertEqual(list(app.exception), [])
        self.assertEqual(app.error[0].value, "Unknown hosted tool: unknown")

    def test_wsl_supervisor_stops_only_its_child(self):
        child = Mock()
        child.poll.return_value = None
        with patch.object(sys, "argv", ["wsl_host.py", "/tmp/stop", "run", "hosted_app.py"]), \
                patch.object(wsl_host.Path, "exists", return_value=True), \
                patch.object(wsl_host.subprocess, "Popen", return_value=child) as popen:
            self.assertEqual(wsl_host.main(), 0)
        popen.assert_called_once_with([sys.executable, "-m", "streamlit", "run", "hosted_app.py"])
        child.terminate.assert_called_once_with()
        child.wait.assert_called_once_with(timeout=10)
        child.kill.assert_not_called()

    def test_wsl_supervisor_preserves_server_failure(self):
        child = Mock(returncode=7)
        child.poll.return_value = 7
        with patch.object(sys, "argv", ["wsl_host.py", "/tmp/stop", "run", "hosted_app.py"]), \
                patch.object(wsl_host.Path, "exists", return_value=False), \
                patch.object(wsl_host.subprocess, "Popen", return_value=child):
            self.assertEqual(wsl_host.main(), 7)
        child.terminate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
