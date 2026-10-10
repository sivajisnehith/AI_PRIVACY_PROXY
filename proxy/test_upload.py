from __future__ import annotations

import json
import time
from pathlib import Path

import requests

PROJECT_DIR = Path(__file__).resolve().parent.parent
STORAGE_DIR = PROJECT_DIR / "storage"
PROXY_URL = "http://127.0.0.1:8080"
TEST_SERVER_URL = "http://127.0.0.1:5000"


def wait_for_server(url: str, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=2)
            if r.status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"Server at {url} did not become ready within {timeout}s")


def send_upload(prompt: str, file_content: bytes, file_name: str, content_type: str) -> requests.Response:
    return requests.post(
        f"{TEST_SERVER_URL}/upload",
        data={"prompt": prompt},
        files={"file": (file_name, file_content, content_type)},
        proxies={
            "http": PROXY_URL,
            "https": PROXY_URL,
        },
        timeout=20,
    )

def run_tests() -> None:
    print("Waiting for test server and proxy to be ready...")
    wait_for_server(f"{TEST_SERVER_URL}/health")

    # ---- Known file used for all happy-path checks ----
    original_bytes = b"%PDF-1.1\n"
    original_bytes += b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    original_bytes += b"2 0 obj<</Type/Pages/Count 0/Kids[]>>endobj\n"
    original_bytes += b"trailer<</Root 1 0 R>>\n%%EOF"
    original_name = "sample.pdf"
    original_ct = "application/pdf"

    prompt = "Summarize this document"

    # 1. Happy path: file + prompt through proxy
    print("\n[Test 1] Happy-path upload through proxy")
    resp = send_upload(prompt, original_bytes, original_name, original_ct)
    body = resp.json()
    print("  status:", resp.status_code)
    print("  response:", json.dumps(body, indent=2))

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    assert body.get("received_prompt") == prompt, f"Prompt mismatch: {body.get('received_prompt')!r}"
    assert body.get("files_received") == 0, f"Expected 0 files, got {body.get('files_received')}"

    # 2. Confirm saved file exists and bytes match.
    saved = [
        p for p in STORAGE_DIR.iterdir()
        if p.is_file() and p.read_bytes() == original_bytes
    ]
    print("  matching saved uploads:", [p.name for p in saved])
    assert saved, "Original upload bytes were not saved in storage/"

    # 3. Response reaches the client.
    assert "message" in body, "Response missing 'message'"

    # 4. Malformed multipart: send non-multipart body to /upload.
    print("\n[Test 2] Non-multipart POST to /upload (should be untouched by proxy)")
    resp2 = requests.post(
        f"{TEST_SERVER_URL}/upload",
        data={"prompt": "x"},
        proxies={"http": PROXY_URL, "https": PROXY_URL},
        timeout=20,
    )
    print("  status:", resp2.status_code)
    # The proxy should not touch non-multipart requests; Flask will handle them.
    assert resp2.status_code == 200, f"Expected 200, got {resp2.status_code}"

    # 5. Missing file field: multipart with prompt but no file.
    print("\n[Test 3] Multipart upload with prompt but no file field")
    from urllib3.filepost import encode_multipart_formdata

    # NOTE: the second positional arg of encode_multipart_formdata is the
    # *boundary*, not a files dict - pass files as keyword if needed.
    body_bytes, ct = encode_multipart_formdata({"prompt": "no file here"})
    resp3 = requests.post(
        f"{TEST_SERVER_URL}/upload",
        data=body_bytes,
        headers={"Content-Type": ct},
        proxies={"http": PROXY_URL, "https": PROXY_URL},
        timeout=20,
    )
    body3 = resp3.json()
    print("  status:", resp3.status_code)
    print("  response:", json.dumps(body3, indent=2))
    assert resp3.status_code == 200
    assert body3.get("received_prompt") == "no file here"
    assert body3.get("files_received") == 0

    # 6. Empty prompt with a file.
    print("\n[Test 4] Upload with empty prompt")
    resp4 = send_upload("", original_bytes, original_name, original_ct)
    body4 = resp4.json()
    print("  status:", resp4.status_code)
    print("  response:", json.dumps(body4, indent=2))
    assert resp4.status_code == 200
    assert body4.get("received_prompt") == ""
    assert body4.get("files_received") == 0

    # 7. Requests to unrelated destinations must remain untouched.
    # Uses the local /echo endpoint (not /upload) so the proxy must pass it
    # through unmodified; the echoed data must come back byte-identical.
    print("\n[Test 5] Unrelated request through proxy remains untouched")
    marker = "untouched-marker-12345"
    resp5 = requests.post(
        f"{TEST_SERVER_URL}/echo?tag={marker}",
        data=marker,
        proxies={"http": PROXY_URL, "https": PROXY_URL},
        timeout=20,
    )
    body5 = resp5.json()
    print("  status:", resp5.status_code)
    print("  response:", json.dumps(body5, indent=2))
    assert resp5.status_code == 200, f"Expected 200 from /echo, got {resp5.status_code}"
    assert body5.get("data") == marker, f"Echoed data was modified: {body5.get('data')!r}"
    assert body5.get("args", {}).get("tag") == marker, f"Echoed args were modified: {body5.get('args')!r}"

    # 8. The proxy still works for /upload after all of the above (no crash,
    #    no lingering state).
    print("\n[Test 6] Upload still works after the no-file and unrelated requests")
    resp6 = send_upload("final check", original_bytes, original_name, original_ct)
    body6 = resp6.json()
    print("  status:", resp6.status_code)
    print("  response:", json.dumps(body6, indent=2))
    assert resp6.status_code == 200
    assert body6.get("received_prompt") == "final check"
    assert body6.get("files_received") == 0

    print("\nAll tests passed.")


if __name__ == "__main__":
    run_tests()
