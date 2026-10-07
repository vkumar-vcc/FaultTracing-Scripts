import importlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
decoder_ui = importlib.import_module('decoder_ui')


class StreamlitUITest(unittest.TestCase):
    def test_windows_path(self):
        self.assertEqual(str(decoder_ui.linux_path(r'C:\logs\capture.pcapng.zst')),
                         '/mnt/c/logs/capture.pcapng.zst')

    def test_resolve_configured_token(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            (home / '.netrc').write_text(
                'machine ara-artifactory.volvocars.biz login vkumar36 password NETRCTOKEN\n')
            with patch('pathlib.Path.home', return_value=home), patch.dict('os.environ', {}, clear=True):
                self.assertEqual(decoder_ui.resolve_configured_token(), 'NETRCTOKEN')
            with patch.dict('os.environ', {'ARTIFACTORY_TOKEN': 'ENVTOK'}, clear=True):
                self.assertEqual(decoder_ui.resolve_configured_token(), 'ENVTOK')
            token_file = home / 'tok'
            token_file.write_text('  FILETOK \n')
            with patch.dict('os.environ', {'ARTIFACTORY_TOKEN_FILE': str(token_file)}, clear=True):
                self.assertEqual(decoder_ui.resolve_configured_token(), 'FILETOK')

    def test_save_uploaded_files(self):
        class Upload:
            def __init__(self, name, data):
                self.name = name
                self._data = data

            def getbuffer(self):
                return memoryview(self._data)

        with tempfile.TemporaryDirectory() as folder:
            files = [Upload('cap1.pcapng', b'abc'),
                     Upload('/evil/../cap2.pcap.zst', b'xyz')]
            out = decoder_ui.save_uploaded_files(files, folder)
            paths = out.splitlines()
            self.assertEqual([Path(p).name for p in paths], ['cap1.pcapng', 'cap2.pcap.zst'])
            self.assertTrue(all(Path(p).is_file() for p in paths))
            self.assertEqual(decoder_ui.save_uploaded_files(files, folder), out)
            self.assertEqual(decoder_ui.save_uploaded_files([], folder), '')

    def test_command_and_inputs(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            capture = root / 'capture with spaces.pcapng'
            capture.touch()
            manifest = root / 'manifest.yaml'
            manifest.write_text('{}')
            self.assertEqual(decoder_ui.collect_inputs(f'{root}\n{capture}'), [capture])
            command = decoder_ui.build_command(str(capture), str(root), str(manifest), root / 'out',
                                    True, True, True, True, 'TC-5_routing_table.yml', 10)
            for flag in ('--someip', '--per-file', '--keep-all', '--csv', '--max-packets'):
                self.assertIn(flag, command)
            self.assertIn(str(capture), command)
            self.assertEqual(command[command.index('--max-packets') + 1], '10')
            with self.assertRaises(ValueError):
                decoder_ui.collect_inputs(str(root / 'missing.pcap'))
            with self.assertRaises(ValueError):
                decoder_ui.build_command(str(capture), '', str(manifest), root / 'out',
                              False, False, False, False, None, 0)

    def test_spa3_command(self):
        with tempfile.TemporaryDirectory() as folder:
            capture = Path(folder) / 'capture.pcap'
            capture.touch()
            command = decoder_ui.build_command(str(capture), '', '', Path(folder) / 'out',
                       True, False, False, False, None, 0,
                       pdu_config=str(ROOT / 'SPA3_PDU'), mrc_enabled=False)
            self.assertIn('--pdu-config', command)
            self.assertIn('--no-mrc', command)
            self.assertNotIn('--db-dir', command)
            self.assertNotIn('--routing-dir', command)
            with self.assertRaises(ValueError):
                decoder_ui.build_command(str(capture), '', '', Path(folder) / 'out',
                           True, False, False, False, None, 0,
                           pdu_config='', mrc_enabled=False)

    def test_platform_drives_decoders(self):
        from streamlit.testing.v1 import AppTest

        app = AppTest.from_file(str(ROOT / 'streamlit_app.py')).run(timeout=20)
        self.assertTrue(any('MRC CAN/LIN' in caption.value for caption in app.caption))
        app.selectbox(key='sdb_platform').select('SPA3').run()
        self.assertFalse(app.exception)
        self.assertTrue(any('SPA3 signal PDUs' in caption.value for caption in app.caption))
        app.selectbox(key='sdb_platform').select('SPA2').run()
        self.assertTrue(any('MRC CAN/LIN' in caption.value for caption in app.caption))

    def test_generate_pdu_config_updates_dir(self):
        from streamlit.testing.v1 import AppTest

        result = {'out_dir': '/tmp/generated_pdu', 'pdus': 1817, 'signals': 34425,
                  'ports': 48, 'cached': False}
        with patch.dict('os.environ', {'ARTIFACTORY_TOKEN': '', 'ARTIFACTORY_API_KEY': ''}), \
                patch('decoder_ui.list_pdu_config_versions', return_value=[]), \
                patch('decoder_ui.list_sdb_versions', return_value=['2050.1.1']), \
                patch('decoder_ui.generate_pdu_config', return_value=result):
            app = AppTest.from_file(str(ROOT / 'streamlit_app.py')).run(timeout=20)
            app.selectbox(key='sdb_platform').select('SPA3').run()
            app.text_input(key='sdb_api_key').set_value('test-key')
            app.run()
            app.selectbox(key='pdu_sdb_version').select('2050.1.1').run()
            next(button for button in app.button
                 if button.label == 'Generate PDU config').click().run()
            self.assertFalse(app.exception)
            self.assertEqual(app.session_state['pdu_config_dir'], '/tmp/generated_pdu')

    def test_subprocess_logs_and_cleanup(self):
        with tempfile.TemporaryDirectory() as folder:
            job = decoder_ui.DecodeJob([sys.executable, '-c', 'print("decoded")'], Path(folder))
            self.assertEqual(job.process.wait(timeout=10), 0)
            self.assertEqual(job.poll(), 0)
            self.assertIn('decoded', job.log_tail())
            self.assertFalse(Path(job.temp_dir).exists())

    def test_cancel(self):
        with tempfile.TemporaryDirectory() as folder:
            job = decoder_ui.DecodeJob([sys.executable, '-c', 'import time; time.sleep(60)'], Path(folder))
            job.cancel()
            self.assertTrue(job.cancelled)
            self.assertIsNotNone(job.poll())
            self.assertFalse(Path(job.temp_dir).exists())

    def test_page_and_validation(self):
        from streamlit.testing.v1 import AppTest

        app = AppTest.from_file(str(ROOT / 'streamlit_app.py')).run(timeout=20)
        self.assertFalse(app.exception)
        self.assertEqual(app.title[0].value, 'PCAP decoder')
        next(button for button in app.button if button.label == 'Decode').click().run()
        self.assertFalse(app.exception)
        self.assertTrue(app.error)

    def test_download_platforms_and_manifest(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            manifest = root / 'manifest.yaml'
            manifest.write_text('- example.dbc')
            result = Mock(db_dir=root / 'db', db_files=['example.dbc'], manifest_path=manifest)
            with patch('mrc_decoder.python.sdb_fetcher.fetch_sdb', return_value=result) as fetch:
                self.assertEqual(decoder_ui.download_sdb('SPA2', '2026.26.1', 'test-key'),
                                 (root / 'db', manifest))
                fetch.assert_called_once_with('2026.26.1', 'test-key', project='p519')
            with patch('mrc_decoder.python.sdb_fetcher.gpa_complete.fetch_databases',
                       return_value=(root / 'db', ['example.dbc'])) as fetch:
                self.assertEqual(decoder_ui.download_sdb('SPA3', '2026.28.1', 'test-key'),
                                 (root / 'db', manifest))
                fetch.assert_called_once_with('gpa', '2026.28.1', 'test-key')
            with self.assertRaises(ValueError):
                decoder_ui.download_sdb('SPA2', '2026.26.1', '')

    def test_version_listing(self):
        from mrc_decoder.python.sdb_fetcher import SdbFetcher

        session = Mock()
        session.headers = {}
        session.get.return_value.status_code = 200
        session.get.return_value.json.return_value = {'children': [
            {'uri': '/2026.26.1', 'folder': True},
            {'uri': '/2026.28.1', 'folder': True},
            {'uri': '/maven-metadata.xml', 'folder': False},
        ]}
        fetcher = SdbFetcher('test-key', session=session)
        self.assertEqual(fetcher.list_versions('gpa'), ['2026.28.1', '2026.26.1'])
        session.get.assert_called_once_with(
            'https://ara-artifactory.volvocars.biz/artifactory/api/storage/'
            'SDB-Hub-LTS/com/volvo/sdb/complete/gpa', timeout=30)

    def test_download_selects_paths_in_page(self):
        from streamlit.testing.v1 import AppTest

        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            root = home / '.cache/mrc_decoder/sdb/p519_2026.26.1'
            with patch('pathlib.Path.home', return_value=home), patch.dict(
                    'os.environ', {'ARTIFACTORY_TOKEN': '', 'ARTIFACTORY_API_KEY': ''}):
                app = AppTest.from_file(str(ROOT / 'streamlit_app.py')).run(timeout=20)
                app.text_input(key='sdb_api_key').set_value('test-key')
                with patch('decoder_ui.list_sdb_versions', return_value=['2026.26.1']):
                    app.run()
                app.selectbox(key='download_sdb_version_SPA2').select('2026.26.1').run()
                (root / 'db').mkdir(parents=True)
                (root / 'manifest.yaml').write_text('- example.dbc')
                with patch('decoder_ui.download_sdb', return_value=(root / 'db', root / 'manifest.yaml')):
                    next(button for button in app.button if button.label == 'Download SDB').click().run()
                self.assertFalse(app.exception)
                self.assertEqual(app.selectbox(key='existing_sdb_version_SPA2').value, '2026.26.1')
                self.assertEqual(app.text_input(key='sdb_db').value, str(root / 'db'))
                self.assertEqual(app.text_input(key='sdb_manifest').value, str(root / 'manifest.yaml'))

    def test_spa3_uses_cached_pdu_config_without_token(self):
        from streamlit.testing.v1 import AppTest

        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            pdu = home / '.cache/mrc_decoder/sdb/gpa_2026.36.2/pdu'
            pdu.mkdir(parents=True)
            (pdu / 'Signal_PDU_identifiers_ETH').write_text('"1","P.P"\n')
            (pdu / 'Signal_PDU_Binding_PDU_Transport_ETH').write_text('"100","1"\n')
            (pdu / 'Signal_PDU_signal_list_ETH').write_text(
                '"1","1","0","isX","P.P.isX","uint","FALSE","8","8","1","0","FALSE","-1","FALSE"\n')
            (pdu / 'decode_as_entries').write_text(
                'decode_as_entry: udp.port,14000,(none),PDU Transport\n')
            with patch('pathlib.Path.home', return_value=home), patch.dict(
                    'os.environ', {'ARTIFACTORY_TOKEN': '', 'ARTIFACTORY_API_KEY': ''}):
                app = AppTest.from_file(str(ROOT / 'streamlit_app.py')).run(timeout=20)
                next(s for s in app.selectbox if s.label == 'SDB platform').select('SPA3').run()
                app.selectbox(key='pdu_sdb_version').select('2026.36.2').run()
                next(b for b in app.button if b.label == 'Use PDU config').click().run()
                self.assertFalse(app.exception)
                self.assertEqual(app.session_state['pdu_config_dir'], str(pdu))

    def test_spa3_generate_requires_key_without_sources(self):
        from streamlit.testing.v1 import AppTest

        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            (home / '.cache/mrc_decoder/sdb').mkdir(parents=True)
            with patch('pathlib.Path.home', return_value=home), patch.dict(
                    'os.environ', {'ARTIFACTORY_TOKEN': '', 'ARTIFACTORY_API_KEY': ''}):
                app = AppTest.from_file(str(ROOT / 'streamlit_app.py')).run(timeout=20)
                next(s for s in app.selectbox if s.label == 'SDB platform').select('SPA3').run()
                app.session_state['sdb_versions'] = {'SPA3': ['9.9.9']}
                app.run()
                app.selectbox(key='pdu_sdb_version').select('9.9.9').run()
                next(b for b in app.button if b.label == 'Generate PDU config').click().run()
                self.assertFalse(app.exception)
                self.assertIn('Artifactory API key', app.error[0].value)

    def test_spa3_has_no_sdb_download(self):
        from streamlit.testing.v1 import AppTest

        app = AppTest.from_file(str(ROOT / 'streamlit_app.py')).run(timeout=20)
        next(s for s in app.selectbox if s.label == 'SDB platform').select('SPA3').run()
        self.assertFalse(app.exception)
        self.assertNotIn('Download SDB', [button.label for button in app.button])

    def test_existing_and_download_choices_are_separate(self):
        from streamlit.testing.v1 import AppTest

        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            for version in ('2026.8.1', '2026.28.1'):
                cached = home / f'.cache/mrc_decoder/sdb/p519_{version}'
                (cached / 'db').mkdir(parents=True)
                (cached / 'manifest.yaml').write_text('- example.dbc')
            with patch('pathlib.Path.home', return_value=home), patch.dict(
                    'os.environ', {'ARTIFACTORY_TOKEN': '', 'ARTIFACTORY_API_KEY': ''}):
                app = AppTest.from_file(str(ROOT / 'streamlit_app.py')).run(timeout=20)
                self.assertEqual(app.selectbox(key='existing_sdb_version_SPA2').options,
                                 ['2026.28.1', '2026.8.1'])
                app.text_input(key='sdb_api_key').set_value('test-key')
                with patch('decoder_ui.list_sdb_versions', return_value=['2026.30.1']):
                    app.run()
                self.assertEqual(app.selectbox(key='download_sdb_version_SPA2').options, ['2026.30.1'])
                app.selectbox(key='download_sdb_version_SPA2').select('2026.30.1').run()
                active = home / '.cache/mrc_decoder/sdb/p519_2026.28.1'
                self.assertEqual(app.text_input(key='sdb_manifest').value, str(active / 'manifest.yaml'))
                with patch('decoder_ui.download_sdb', side_effect=ValueError('Download failed')):
                    next(button for button in app.button if button.label == 'Download SDB').click().run()
                self.assertFalse(app.exception)
                self.assertEqual(app.text_input(key='sdb_manifest').value, str(active / 'manifest.yaml'))


if __name__ == '__main__':
    unittest.main()