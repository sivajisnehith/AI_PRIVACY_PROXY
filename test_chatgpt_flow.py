"""End-to-end simulation of ChatGPT document upload and sanitization flow.

Tests the full 4-stage lifecycle:
1. Metadata registration: POST chatgpt.com/backend-api/files
2. Binary payload upload: PUT *.oaiusercontent.com/files/...
3. Retrieval finalization: POST chatgpt.com/backend-api/files/{file_id}
4. Conversation prompt: POST chatgpt.com/backend-api/conversation
"""

import json
import unittest
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from unittest.mock import patch
from proxy import proxy as addon


class RequestMock:
    def __init__(self, host: str, path: str, method: str, body: bytes = b"", content_type: str = "application/json"):
        self.pretty_host = host
        self.path = path
        self.method = method
        self.raw_content = body
        self.headers = {
            "content-type": content_type,
            "content-length": str(len(body)),
            "origin": "https://chatgpt.com",
            "host": host,
        }
        self.port = 443


class FlowMock:
    def __init__(self, request: RequestMock):
        self.request = request
        self.response = None


class ChatGPTLiveFlowTests(unittest.TestCase):
    @patch.object(addon, "get_decoy_file", return_value=(None, None))
    def test_full_document_upload_and_chat_lifecycle(self, _mock_decoy):
        file_id = "file-secret-98765"
        file_name = "Quarterly_Financials_Confidential.pdf"
        sensitive_content = b"%PDF-1.4 CONFIDENTIAL FINANCIAL DATA: Revenue=$50M, Profit=$12M -- DO NOT LEAK"
        user_prompt = "Please explain the revenue growth shown in this document."

        # Step 1: Frontend registers file metadata
        step1_body = json.dumps({
            "file_name": file_name,
            "file_size": len(sensitive_content),
            "use_case": "my_files",
            "mime_type": "application/pdf",
        }).encode("utf-8")
        step1_req = RequestMock("chatgpt.com", "/backend-api/files", "POST", step1_body)
        step1_flow = FlowMock(step1_req)
        addon.request(step1_flow)
        # Should pass through to OpenAI (response remains None)
        self.assertIsNone(step1_flow.response)

        # Step 2: Frontend uploads document bytes to storage
        step2_req = RequestMock(
            "sdmntprcentralindia.oaiusercontent.com",
            f"/files/{file_id}",
            "PUT",
            sensitive_content,
            content_type="application/pdf",
        )
        step2_flow = FlowMock(step2_req)
        addon.request(step2_flow)
        # Should be intercepted: 200 OK directly to client, not forwarded to cloud
        self.assertIsNotNone(step2_flow.response)
        self.assertEqual(step2_flow.response.status_code, 200)

        # Verify document was saved on disk
        stored_files = list(addon.STORAGE_DIR.glob(f"*{Path(file_name).stem}*"))
        self.assertTrue(len(stored_files) >= 1, "File was not saved to storage directory")
        matching = [f for f in stored_files if f.read_bytes() == sensitive_content]
        self.assertTrue(len(matching) >= 1, "Stored file content does not match sensitive original")

        # Step 3: Frontend finalizes upload and requests indexing
        step3_body = json.dumps({
            "file_id": file_id,
            "file_name": file_name,
            "index_for_retrieval": True,
            "mime_type": "application/pdf",
            "use_case": "my_files",
        }).encode("utf-8")
        step3_req = RequestMock("chatgpt.com", f"/backend-api/files/{file_id}", "POST", step3_body)
        step3_flow = FlowMock(step3_req)
        addon.request(step3_flow)
        # Must be intercepted locally with simulated success (bypassing cloud indexer)
        self.assertIsNotNone(step3_flow.response)
        self.assertEqual(step3_flow.response.status_code, 200)
        final_data = json.loads(step3_flow.response.content.decode("utf-8"))
        self.assertEqual(final_data["id"], file_id)
        self.assertEqual(final_data["status"], "success")
        self.assertTrue(final_data["ready"])
        self.assertEqual(final_data["file_name"], file_name)

        # Step 4: Frontend submits conversation prompt with attachment
        step4_payload = {
            "action": "next",
            "attachment_mime_types": ["application/pdf"],
            "messages": [
                {
                    "id": "msg-001",
                    "author": {"role": "user"},
                    "content": {
                        "content_type": "multimodal_text",
                        "parts": [user_prompt],
                    },
                    "metadata": {
                        "attachments": [
                            {"id": file_id, "name": file_name, "mime_type": "application/pdf"}
                        ],
                        "file_upload_slot_prefetch_attribution": {"actual_path": file_name},
                    },
                }
            ],
        }
        step4_body = json.dumps(step4_payload).encode("utf-8")
        step4_req = RequestMock("chatgpt.com", "/backend-api/conversation", "POST", step4_body)
        step4_flow = FlowMock(step4_req)
        addon.request(step4_flow)
        # Must be forwarded upstream (response is None), but content is sanitized
        self.assertIsNone(step4_flow.response)
        sanitized_data = json.loads(step4_flow.request.raw_content.decode("utf-8"))

        # Verify all attachment pointers are stripped
        self.assertEqual(sanitized_data["attachment_mime_types"], [])
        msg = sanitized_data["messages"][0]
        self.assertNotIn("attachments", msg.get("metadata", {}))
        self.assertNotIn("file_upload_slot_prefetch_attribution", msg.get("metadata", {}))

        # Verify the prompt text is preserved
        self.assertEqual(msg["content"]["content_type"], "text")
        self.assertEqual(msg["content"]["parts"], [user_prompt])

    def test_decoy_substitution_lifecycle(self):
        file_id = "file-secret-11223"
        file_name = "My_Sensitive_Notes.pdf"
        sensitive_content = b"TOP SECRET SOURCE CODE AND ARCHITECTURE DETAILS"
        user_prompt = "Summarize the attached document."

        # Step 1: Pre-register file metadata
        step1_body = json.dumps({
            "file_name": file_name,
            "file_size": len(sensitive_content),
            "use_case": "my_files",
            "mime_type": "application/pdf",
        }).encode("utf-8")
        step1_req = RequestMock("chatgpt.com", "/backend-api/files", "POST", step1_body)
        step1_flow = FlowMock(step1_req)
        addon.request(step1_flow)

        # Step 2: Binary upload PUT
        step2_req = RequestMock(
            "sdmntprcentralindia.oaiusercontent.com",
            f"/files/{file_id}",
            "PUT",
            sensitive_content,
            content_type="application/pdf",
        )
        step2_flow = FlowMock(step2_req)
        addon.request(step2_flow)

        # In decoy mode, request is forwarded (response is None) with swapped decoy payload
        self.assertIsNone(step2_flow.response)
        decoy_p, decoy_b = addon.get_decoy_file()
        self.assertIsNotNone(decoy_b)
        self.assertEqual(step2_flow.request.raw_content, decoy_b)
        self.assertEqual(step2_flow.request.headers["content-length"], str(len(decoy_b)))

        # Verify original was safely preserved on local disk
        stored_files = list(addon.STORAGE_DIR.glob(f"*{Path(file_name).stem}*"))
        matching = [f for f in stored_files if f.read_bytes() == sensitive_content]
        self.assertTrue(len(matching) >= 1, "Original sensitive file was not saved locally")

        # Step 4: Conversation prompt preserves attachment so ChatGPT reads the decoy
        step4_payload = {
            "action": "next",
            "messages": [
                {
                    "content": {"content_type": "multimodal_text", "parts": [user_prompt]},
                    "metadata": {"attachments": [{"id": file_id, "name": file_name}]},
                }
            ],
        }
        step4_body = json.dumps(step4_payload).encode("utf-8")
        step4_req = RequestMock("chatgpt.com", "/backend-api/conversation", "POST", step4_body)
        step4_flow = FlowMock(step4_req)
        addon.request(step4_flow)
        # Verify attachment is preserved
        self.assertIsNone(step4_flow.response)
        conv_data = json.loads(step4_flow.request.raw_content.decode("utf-8"))
        self.assertIn("attachments", conv_data["messages"][0]["metadata"])


if __name__ == "__main__":
    unittest.main()
