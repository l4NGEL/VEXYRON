"""Smoke: pages render, settings persist on this PC via lab_config.json."""
from __future__ import annotations

import json
import os
import shutil
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

WEBAPP_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(WEBAPP_DIR))

os.environ.pop("PENTEST_LAB_WEBAPP_PORT", None)

import app as webapp  # noqa: E402


def _html(resp) -> str:
    return resp.get_data(as_text=True)


class SettingsPersistSmoke(unittest.TestCase):
    def setUp(self):
        self._cfg_fd, self._cfg_path = tempfile.mkstemp(prefix="lab_config_", suffix=".json")
        os.close(self._cfg_fd)
        os.remove(self._cfg_path)
        self._cfg_patch = mock.patch.object(webapp, "CONFIG_PATH", self._cfg_path)
        self._cfg_patch.start()
        self.client = webapp.app.test_client()

    def tearDown(self):
        self._cfg_patch.stop()
        if os.path.isfile(self._cfg_path):
            os.remove(self._cfg_path)

    def test_pages_render(self):
        for path in ("/", "/history", "/reports", "/keys", "/vulndb", "/settings"):
            with self.subTest(path=path):
                resp = self.client.get(path)
                self.assertEqual(resp.status_code, 200, path)

    def test_settings_shows_this_machine(self):
        resp = self.client.get("/settings")
        self.assertEqual(resp.status_code, 200)
        body = _html(resp)
        reports = webapp.get_reports_dir()
        self.assertIn(socket.gethostname(), body)
        self.assertIn(reports, body)
        self.assertTrue(reports.startswith(webapp.PROJECT_ROOT) or os.path.isdir(reports))
        self.assertIn("Bu PC’de kaydet", body)
        self.assertIn('name="webapp_port"', body)
        self.assertIn('name="reports_dir"', body)

    def test_save_port_and_reports_dir_on_this_pc(self):
        custom = tempfile.mkdtemp(prefix="pentest-lab-reports-")
        try:
            resp = self.client.post(
                "/settings",
                data={"webapp_port": "8088", "reports_dir": custom},
                follow_redirects=True,
            )
            self.assertEqual(resp.status_code, 200)
            body = _html(resp)
            self.assertIn("Bu PC’de kaydedildi", body)
            self.assertTrue(os.path.isfile(self._cfg_path))
            saved = json.loads(Path(self._cfg_path).read_text(encoding="utf-8"))
            self.assertEqual(saved["webapp_port"], 8088)
            self.assertEqual(os.path.abspath(saved["reports_dir"]), os.path.abspath(custom))
            self.assertEqual(webapp.get_reports_dir(), os.path.abspath(custom))
            self.assertIn(os.path.abspath(custom), body)
        finally:
            shutil.rmtree(custom, ignore_errors=True)

    def test_project_reports_path_stays_portable(self):
        default = webapp._default_reports_dir()
        resp = self.client.post(
            "/settings",
            data={"webapp_port": "5059", "reports_dir": default},
        )
        self.assertEqual(resp.status_code, 200)
        saved = json.loads(Path(self._cfg_path).read_text(encoding="utf-8"))
        self.assertEqual(saved["reports_dir"], "")
        self.assertEqual(webapp.get_reports_dir(), default)

    def test_reset_reports_uses_this_pc_default(self):
        custom = tempfile.mkdtemp(prefix="pentest-lab-reports-")
        try:
            self.client.post("/settings", data={"webapp_port": "5059", "reports_dir": custom})
            resp = self.client.post(
                "/settings",
                data={"webapp_port": "5059", "reports_dir": custom, "reset_reports": "on"},
            )
            self.assertEqual(resp.status_code, 200)
            saved = json.loads(Path(self._cfg_path).read_text(encoding="utf-8"))
            self.assertEqual(saved["reports_dir"], "")
            self.assertEqual(webapp.get_reports_dir(), webapp._default_reports_dir())
        finally:
            shutil.rmtree(custom, ignore_errors=True)

    def test_chrome_blocked_port_rejected(self):
        resp = self.client.post(
            "/settings",
            data={"webapp_port": "5060", "reports_dir": webapp._default_reports_dir()},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Chrome", _html(resp))
        self.assertFalse(os.path.isfile(self._cfg_path))


class LiveProcessSmoke(unittest.TestCase):
    """If webapp is already running, confirm this PC's path is on the page."""

    def test_live_settings_page_if_up(self):
        try:
            import urllib.request

            with urllib.request.urlopen("http://127.0.0.1:5059/settings", timeout=2) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                self.assertEqual(resp.status, 200)
        except OSError:
            self.skipTest("webapp 5059 üzerinde değil")
        self.assertIn(webapp._default_reports_dir(), body)
        self.assertIn("127.0.0.1:5059", body)
        self.assertIn("Bu PC’de kaydet", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
