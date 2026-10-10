from __future__ import annotations

import json
import threading
import time
import unittest
from pathlib import Path

import requests
from proxy import proxy as addon
from proxy.proxy import get_storage_dir, list_stored_files
from main import start_proxy_server
from proxy.test_server import app

STORAGE_DIR = get_storage_dir()
PROXY_PORT = 8088
PROXY_URL = f"http://127.0.0.1:{PROXY_PORT}"
TEST_SERVER_URL = "http://127.0.0.1:5000"


class EndToEndIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # 1. Start test flask server
        cls.flask_thread = threading.Thread(
            target=lambda: app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False),
            daemon=True,
        )
        cls.flask_thread.start()

        # 2. Start proxy server
        cls.proxy_master, cls.proxy_loop, cls.proxy_thread = start_proxy_server("127.0.0.1", PROXY_PORT)
        time.sleep(1.5)

    @classmethod
    def tearDownClass(cls):
        try:
            if cls.proxy_master and cls.proxy_loop:
                cls.proxy_loop.call_soon_threadsafe(cls.proxy_master.shutdown)
        except Exception:
            pass

    def test_01_health_check(self):
        resp = requests.get(f"{TEST_SERVER_URL}/health", timeout=5)
        self.assertEqual(resp.status_code, 200)

    def test_02_multipart_upload_interception(self):
        sample_doc = b"CONFIDENTIAL_PII_DATA: Alice, SSN: 000-11-2222"
        prompt = "Analyze this customer record"
        resp = requests.post(
            f"{TEST_SERVER_URL}/upload",
            data={"prompt": prompt},
            files={"file": ("customer_record.txt", sample_doc, "text/plain")},
            proxies={"http": PROXY_URL, "https": PROXY_URL},
            timeout=10,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data.get("received_prompt"), prompt)
        self.assertEqual(data.get("files_received"), 0)

        # Verify saved in storage
        matching = [
            f for f in list_stored_files()
            if "customer_record.txt" in f["name"]
        ]
        self.assertTrue(len(matching) > 0, "File was not saved to local storage")

    def test_03_storage_listing(self):
        files = list_stored_files()
        self.assertIsInstance(files, list)
        self.assertTrue(len(files) > 0)
        self.assertIn("name", files[0])
        self.assertIn("size_bytes", files[0])


if __name__ == "__main__":
    unittest.main()
