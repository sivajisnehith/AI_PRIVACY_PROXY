from __future__ import annotations

import hashlib
import uuid
import unittest
import sys
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from proxy import proxy as addon
except ImportError:
    import proxy as addon


def make_multipart() -> tuple[bytes, str]:
    boundary = "privacy-test-boundary"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="prompt"\r\n\r\n'
        "synthetic prompt marker\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="private.txt"\r\n'
        "Content-Type: text/plain\r\n\r\n"
        "synthetic document bytes marker\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")
    return body, f"multipart/form-data; boundary={boundary}"


class Request:
    def __init__(self, *, host="127.0.0.1", port=5000, path="/upload", body=b"", content_type=""):
        self.pretty_host = host
        self.port = port
        self.path = path
        self.method = "POST"
        self.raw_content = body
        self.headers = {"content-type": content_type, "content-length": str(len(body))}


class Flow:
    def __init__(self, request: Request):
        self.request = request
        self.response = None


class TestStorage:
    def __init__(self):
        self.path = addon.STORAGE_DIR / f".test-{uuid.uuid4().hex}"

    def __enter__(self):
        self.path.mkdir()
        return self.path

    def __exit__(self, *_):
        for item in self.path.iterdir():
            if item.is_file():
                item.unlink()
        self.path.rmdir()


class ProxyRequestTests(unittest.TestCase):
    def setUp(self):
        self.body, self.content_type = make_multipart()

    def test_local_upload_saves_exact_file_and_forwards_prompt_without_file(self):
        flow = Flow(Request(body=self.body, content_type=self.content_type))
        with TestStorage() as directory, patch.object(addon, "STORAGE_DIR", directory):
            addon.request(flow)
            files = list(directory.iterdir())
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0].read_bytes(), b"synthetic document bytes marker")

        parts = addon._parse_multipart(flow.request.raw_content, self.content_type)
        self.assertIsNotNone(parts)
        self.assertEqual([(p.name, p.content) for p in parts], [("prompt", b"synthetic prompt marker")])
        self.assertEqual(flow.request.headers["content-length"], str(len(flow.request.raw_content)))
        self.assertNotIn(b"synthetic document bytes marker", flow.request.raw_content)

    def test_existing_storage_file_is_not_overwritten(self):
        content = b"new document"
        digest = hashlib.sha256(content).hexdigest()[:16]
        expected = Path(f"{digest}_report.txt")
        with TestStorage() as directory, patch.object(addon, "STORAGE_DIR", directory):
            existing = directory / expected
            existing.write_bytes(b"pre-existing user data")
            saved = addon._store_file("report.txt", content)
            self.assertIsNotNone(saved)
            self.assertEqual(existing.read_bytes(), b"pre-existing user data")
            self.assertEqual(saved.read_bytes(), content)
            self.assertNotEqual(saved, existing)

    def test_save_failure_rejects_request_without_forwarding(self):
        flow = Flow(Request(body=self.body, content_type=self.content_type))
        with patch.object(addon, "_store_file", return_value=None):
            addon.request(flow)
        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 500)
        self.assertEqual(flow.request.raw_content, self.body)

    def test_observation_logs_route_and_shape_without_request_secrets(self):
        body, content_type = make_multipart()
        request = Request(
            host="chatgpt.example",
            port=443,
            path="/api/files/upload/private-secret?token=query-secret",
            body=body,
            content_type=content_type,
        )
        request.headers["cookie"] = "cookie-secret"
        request.headers["authorization"] = "Bearer authorization-secret"
        flow = Flow(request)
        with patch.object(addon, "OBSERVE_REQUESTS", True), self.assertLogs(addon.logger, level="INFO") as captured:
            addon.request(flow)
        output = "\n".join(captured.output)
        self.assertIn("host=chatgpt.example", output)
        self.assertIn("path=/api/files/upload/:segment", output)
        self.assertIn("prompt:23B", output)
        self.assertIn("file:31B", output)
        for secret in (
            "synthetic prompt marker", "synthetic document bytes marker",
            "private-secret", "query-secret", "cookie-secret", "authorization-secret", "private.txt",
        ):
            self.assertNotIn(secret, output)
        self.assertEqual(flow.request.raw_content, body)
        self.assertIsNone(flow.response)

    def test_observation_reports_json_shape_but_not_values(self):
        body = b'{"message":{"text":"prompt-secret","attachments":[{"file_id":"id-secret"}]}}'
        flow = Flow(Request(
            host="chatgpt.example", port=443, path="/api/messages",
            body=body, content_type="application/json",
        ))
        with patch.object(addon, "OBSERVE_REQUESTS", True), self.assertLogs(addon.logger, level="INFO") as captured:
            addon.request(flow)
        output = "\n".join(captured.output)
        self.assertIn("message.text:string", output)
        self.assertIn("message.attachments[].file_id:string", output)
        self.assertNotIn("prompt-secret", output)
        self.assertNotIn("id-secret", output)
        self.assertEqual(flow.request.raw_content, body)

    def test_observation_handles_unbuffered_upload_headers_without_secrets(self):
        request = Request(host="chatgpt.example", port=443, path="/api/files/opaque123")
        request.raw_content = None
        request.headers["content-length"] = "4096"
        request.headers["authorization"] = "Bearer header-secret"
        flow = Flow(request)
        with patch.object(addon, "OBSERVE_REQUESTS", True), self.assertLogs(addon.logger, level="INFO") as captured:
            addon.requestheaders(flow)
        output = "\n".join(captured.output)
        self.assertIn("path=/api/files/:segment", output)
        self.assertIn("bytes=4096", output)
        self.assertNotIn("header-secret", output)

    def test_unrelated_request_is_not_modified(self):
        body = b'{"text":"do not change"}'
        flow = Flow(Request(host="example.org", port=443, path="/api/upload", body=body, content_type="application/json"))
        addon.request(flow)
        self.assertEqual(flow.request.raw_content, body)
        self.assertIsNone(flow.response)

    def test_chatgpt_oaiusercontent_upload_captures_file_and_mocks_response(self):
        file_bytes = b"%PDF-1.4 test sensitive document content"
        req = Request(
            host="sdmntpraustraliaeast.oaiusercontent.com",
            port=443,
            path="/files/user-123/document.pdf",
            body=file_bytes,
            content_type="application/pdf",
        )
        req.method = "PUT"
        flow = Flow(req)
        with TestStorage() as directory, patch.object(addon, "STORAGE_DIR", directory):
            addon.request(flow)
            files = list(directory.iterdir())
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0].read_bytes(), file_bytes)
            self.assertIn("document.pdf", files[0].name)
            self.assertIsNotNone(flow.response)
            self.assertEqual(flow.response.status_code, 200)

    def test_chatgpt_file_finalization_mocked(self):
        import json
        req = Request(
            host="chatgpt.com",
            port=443,
            path="/backend-api/files/file-abc123xyz",
            body=json.dumps({"file_id": "file-abc123xyz", "index_for_retrieval": True, "file_name": "resume.pdf"}).encode("utf-8"),
            content_type="application/json",
        )
        req.method = "POST"
        flow = Flow(req)
        addon.request(flow)
        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 200)
        data = json.loads(flow.response.content.decode("utf-8"))
        self.assertEqual(data["id"], "file-abc123xyz")
        self.assertEqual(data["status"], "success")
        self.assertTrue(data["ready"])
        self.assertEqual(data["file_name"], "resume.pdf")

    def test_chatgpt_file_readiness_get_mocked(self):
        import json
        req = Request(
            host="chatgpt.com",
            port=443,
            path="/backend-api/files/file-abc123xyz",
            body=b"",
            content_type="application/json",
        )
        req.method = "GET"
        flow = Flow(req)
        addon.request(flow)
        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 200)
        data = json.loads(flow.response.content.decode("utf-8"))
        self.assertEqual(data["id"], "file-abc123xyz")
        self.assertEqual(data["status"], "success")
        self.assertTrue(data["ready"])

    def test_chatgpt_conversation_strips_attachment_and_preserves_prompt(self):
        import json
        payload = {
            "action": "next",
            "attachment_mime_types": ["application/pdf"],
            "messages": [
                {
                    "id": "msg-123",
                    "author": {"role": "user"},
                    "content": {
                        "content_type": "multimodal_text",
                        "parts": ["Please summarize this financial report."],
                    },
                    "metadata": {
                        "attachments": [
                            {"id": "file-abc", "name": "finance.pdf", "mime_type": "application/pdf"}
                        ],
                        "file_upload_slot_prefetch_attribution": {"actual_path": "finance.pdf"},
                    },
                }
            ],
        }
        body = json.dumps(payload).encode("utf-8")
        req = Request(
            host="chatgpt.com",
            port=443,
            path="/backend-api/conversation",
            body=body,
            content_type="application/json",
        )
        flow = Flow(req)
        addon.request(flow)
        self.assertIsNone(flow.response)  # forwarded to upstream
        new_data = json.loads(flow.request.raw_content.decode("utf-8"))
        # Attachment list cleared
        self.assertEqual(new_data["attachment_mime_types"], [])
        msg = new_data["messages"][0]
        # Attachment removed from metadata
        self.assertNotIn("attachments", msg["metadata"])
        self.assertNotIn("file_upload_slot_prefetch_attribution", msg["metadata"])
        # Prompt preserved
        self.assertEqual(msg["content"]["content_type"], "text")
        self.assertEqual(msg["content"]["parts"], ["Please summarize this financial report."])


if __name__ == "__main__":
    unittest.main()
