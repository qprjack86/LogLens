import io
import zipfile
import unittest
from datetime import datetime, timedelta

from werkzeug.datastructures import FileStorage

import app as app_module


class UploadParsingTests(unittest.TestCase):
    def setUp(self):
        app_module.app.config["TESTING"] = True
        app_module.APP_STATE.clear()

    def _zip_upload(self, filename, entries):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for entry_name, content in entries.items():
                zf.writestr(entry_name, content)
        buffer.seek(0)
        return FileStorage(stream=buffer, filename=filename, content_type="application/zip")

    def test_select_zip_candidates_prefers_priority_and_size(self):
        zip_file = self._zip_upload(
            "fslogix.zip",
            {
                "small/Profile_A.log": "a" * 10,
                "large/Profile_B.log": "b" * 100,
                "other.txt": "c" * 300,
            },
        )

        zip_file.stream.seek(0)
        with zipfile.ZipFile(zip_file.stream) as zip_handle:
            candidates = app_module._select_zip_candidates(
                zip_handle,
                [name for name in zip_handle.namelist() if not name.endswith("/")],
                "FSLOGIX",
            )

        self.assertEqual(candidates[0], "large/Profile_B.log")

    def test_parse_uploads_extracts_multiple_zip_candidates(self):
        zip_file = self._zip_upload(
            "intune.zip",
            {
                "IntuneManagementExtension.log": "Error: first",
                "AgentExecutor.log": "Error: second",
            },
        )

        with app_module.app.test_request_context("/"):
            combined, file_names, detected = app_module.parse_uploads([zip_file])

        self.assertIn("IntuneManagementExtension.log", combined)
        self.assertIn("AgentExecutor.log", combined)
        self.assertEqual(file_names, ["intune.zip"])
        self.assertEqual(detected, "INTUNE")

    def test_prune_state_removes_stale_and_limits_size(self):
        now = datetime.now()
        for index in range(app_module.MAX_STATE_SESSIONS + 3):
            app_module.APP_STATE[f"sid-{index}"] = {
                "last_accessed": now - timedelta(minutes=app_module.STATE_TTL_MINUTES + 5)
            }

        app_module._prune_state(now)
        self.assertEqual(len(app_module.APP_STATE), 0)

    def test_update_detected_type_respects_precedence(self):
        self.assertEqual(app_module.update_detected_type("GENERIC", "INTUNE"), "INTUNE")
        self.assertEqual(app_module.update_detected_type("INTUNE", "GENERIC"), "INTUNE")
        self.assertEqual(app_module.update_detected_type("INTUNE", "FSLOGIX"), "FSLOGIX")


if __name__ == "__main__":
    unittest.main()
