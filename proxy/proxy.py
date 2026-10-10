from __future__ import annotations

import hashlib
import json
import logging
import mimetypes
import os
import re
import sys
import uuid
from email import policy
from email.message import Message
from email.parser import BytesParser
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import NamedTuple
from urllib.parse import parse_qs, urlsplit

from mitmproxy import http

if getattr(sys, "frozen", False):
    _exe_dir = Path(sys.executable).resolve().parent
    PROJECT_DIR = _exe_dir.parent if _exe_dir.name.lower() == "dist" else _exe_dir
else:
    PROJECT_DIR = Path(__file__).resolve().parent.parent

STORAGE_DIR = PROJECT_DIR / "storage"
LOG_DIR = PROJECT_DIR / "logs"
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Keep addon logs separate from mitmproxy's normal flow dumper.
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.propagate = False
if not any(getattr(handler, "_ai_privacy_proxy", False) for handler in logger.handlers):
    handler = RotatingFileHandler(
        LOG_DIR / "privacy-observer.log",
        maxBytes=1_000_000,
        backupCount=3,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    handler._ai_privacy_proxy = True
    logger.addHandler(handler)

TEST_SERVER_HOST = "127.0.0.1"
TEST_SERVER_PORT = 5000
TEST_SERVER_PATH = "/upload"

# Fields that represent uploaded files and must be removed from forwarded multipart requests.
FILE_FIELDS = frozenset({"file", "document", "attachment", "files"})
OBSERVE_REQUESTS = os.environ.get("AI_PRIVACY_OBSERVE", "1").strip().lower() in {
    "1", "true", "yes", "on"
}
_OBSERVABLE_ROUTE_WORDS = frozenset({
    "api", "backend-api", "v1", "v2", "v3", "file", "files", "upload",
    "uploads", "attachment", "attachments", "message", "messages", "chat",
    "conversation", "conversations", "thread", "threads", "response",
    "responses", "completion", "completions", "turn", "turns", "content",
    "stream", "chunks", "create", "submit",
})


def get_storage_dir() -> Path:
    """Return the absolute path to the local file storage directory."""
    return STORAGE_DIR.resolve()


def list_stored_files() -> list[dict]:
    """List all stored documents with details."""
    files = []
    if not STORAGE_DIR.exists():
        return files
    for p in sorted(STORAGE_DIR.iterdir(), key=lambda x: x.stat().st_mtime if x.is_file() else 0, reverse=True):
        if p.is_file():
            stat = p.stat()
            files.append({
                "name": p.name,
                "path": str(p.resolve()),
                "size_bytes": stat.st_size,
                "modified": stat.st_mtime,
            })
    return files


class MultipartPart(NamedTuple):
    """One part of a parsed multipart/form-data body."""

    name: str | None          # value of the `name` parameter of Content-Disposition
    filename: str | None      # value of the `filename` parameter of Content-Disposition
    headers: list[tuple[str, str]]  # part headers, restricted to safe ones when re-emitting
    content: bytes            # exact part payload bytes


def _safe_filename(raw: str) -> str:
    """Return a safe storage name for an uploaded file, or "" when unusable."""
    name = (raw or "").strip()
    name = name.replace("\\", "/").split("/")[-1]
    name = name.lstrip(".")
    if not name:
        return ""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        # Sanitize unsafe characters
        name = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    return name[:128]


def _store_file(filename: str, content: bytes) -> Path | None:
    """Write an uploaded file to the storage directory.

    Returns the Path of the saved file, or None on failure.
    Uses a content-hash prefix to avoid collisions and prevent overwriting.
    """
    safe = _safe_filename(filename)
    digest = hashlib.sha256(content).hexdigest()[:16]
    if safe:
        stem = Path(safe).stem
        suffix = Path(safe).suffix
        if len(suffix) > 16:
            suffix = ""
        outfile_name = f"{digest}_{stem}{suffix}"
    else:
        outfile_name = f"{digest}_document.bin"
    dest = STORAGE_DIR / outfile_name
    try:
        with dest.open("xb") as output:
            output.write(content)
        return dest
    except FileExistsError:
        try:
            if dest.read_bytes() == content:
                return dest
        except OSError:
            return None
        unique_dest = dest.with_name(f"{dest.stem}_{uuid.uuid4().hex[:12]}{dest.suffix}")
        try:
            with unique_dest.open("xb") as output:
                output.write(content)
            return unique_dest
        except OSError:
            return None
_NOTIFICATION_CALLBACK = None


def register_notification_callback(callback):
    """Register a callback fn(filename: str, size: int) for capture notifications."""
    global _NOTIFICATION_CALLBACK
    _NOTIFICATION_CALLBACK = callback


def _notify_capture(filename: str, size: int) -> None:
    if _NOTIFICATION_CALLBACK:
        try:
            _NOTIFICATION_CALLBACK(filename, size)
        except Exception:
            pass


def _extract_boundary(content_type: str) -> str | None:
    """Extract the multipart boundary from a Content-Type header value."""
    msg = Message()
    msg["content-type"] = content_type
    boundary = msg.get_param("boundary")
    if isinstance(boundary, str) and boundary:
        return boundary
    return None


_KEPT_PART_HEADERS = ("content-disposition", "content-type")


def _parse_multipart(raw_body: bytes, content_type: str) -> list[MultipartPart] | None:
    """Parse a multipart/form-data body using stdlib MIME parser."""
    if _extract_boundary(content_type) is None:
        return None
    try:
        envelope = (
            b"Content-Type: "
            + content_type.encode("latin-1", "replace")
            + b"\r\nMIME-Version: 1.0\r\n\r\n"
            + raw_body
        )
        msg = BytesParser(policy=policy.compat32).parsebytes(envelope)
    except Exception:
        return None
    if not msg.is_multipart():
        return None
    parts: list[MultipartPart] = []
    for p in msg.get_payload():
        name = p.get_param("name", header="content-disposition")
        if isinstance(name, tuple):
            name = name[2]
        filename = p.get_filename()
        content = p.get_payload(decode=True)
        if content is None:
            return None
        headers = [
            (k, v)
            for k, v in p.items()
            if k.lower() in _KEPT_PART_HEADERS
        ]
        parts.append(MultipartPart(name, filename, headers, content))
    return parts


def _encode_multipart(boundary: str, parts: list[MultipartPart]) -> bytes:
    """Re-serialize parts as a multipart/form-data body using boundary."""
    bnd = boundary.encode("latin-1", "replace")
    chunks: list[bytes] = []
    for part in parts:
        chunks.append(b"--" + bnd + b"\r\n")
        for key, value in part.headers:
            key_b = key.encode("utf-8", "surrogateescape")
            value_b = value.encode("utf-8", "surrogateescape")
            if b"\r" in value_b or b"\n" in value_b or b":" in key_b:
                continue
            chunks.append(key_b + b": " + value_b + b"\r\n")
        chunks.append(b"\r\n")
        chunks.append(part.content)
        chunks.append(b"\r\n")
    chunks.append(b"--" + bnd + b"--\r\n")
    return b"".join(chunks)


def _observation_route(path: str) -> str:
    """Keep common route labels while omitting query strings and sensitive segments."""
    segments = urlsplit(path).path.split("/")
    safe: list[str] = []
    for segment in segments[:12]:
        if not segment:
            continue
        lowered = segment.lower()
        safe.append(lowered if lowered in _OBSERVABLE_ROUTE_WORDS else ":segment")
    return "/" + "/".join(safe)


def _safe_field_name(name: str | None) -> str:
    if name and len(name) <= 48 and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", name):
        return name
    return "[field]"


def _json_shape(value: object, prefix: str = "", depth: int = 0) -> list[str]:
    """Describe JSON structure without including values."""
    result: list[str] = []
    if depth > 4 or len(result) >= 32:
        return result
    if isinstance(value, dict):
        for key, child in list(value.items())[:32]:
            safe_key = _safe_field_name(key if isinstance(key, str) else None)
            child_path = f"{prefix}.{safe_key}" if prefix else safe_key
            if isinstance(child, (dict, list)):
                result.extend(_json_shape(child, child_path, depth + 1))
            else:
                kind = "null" if child is None else "boolean" if isinstance(child, bool) else "number" if isinstance(child, (int, float)) else "string"
                result.append(f"{child_path}:{kind}")
            if len(result) >= 32:
                break
    elif isinstance(value, list) and value:
        result.extend(_json_shape(value[0], f"{prefix}[]", depth + 1))
    elif isinstance(value, list):
        result.append(f"{prefix}:empty-list")
    else:
        kind = "null" if value is None else "boolean" if isinstance(value, bool) else "number" if isinstance(value, (int, float)) else "string"
        result.append(f"{prefix}:{kind}")
    return result[:32]


def _observe_request(flow: http.HTTPFlow) -> None:
    """Log request route and shape without leaking secrets."""
    req = flow.request
    if req.method.upper() not in {"POST", "PUT", "PATCH"}:
        return
    body = req.raw_content or b""
    if not body:
        return
    content_type = req.headers.get("content-type", "")
    header = Message()
    try:
        header["content-type"] = content_type
        media_type = str(header.get_content_type()).lower()
    except Exception:
        media_type = "unknown"

    shape = "body"
    if media_type == "multipart/form-data":
        parts = _parse_multipart(body, content_type)
        if parts is None:
            shape = "multipart-unparsed"
        else:
            shape = "multipart=" + ",".join(
                f"{_safe_field_name(part.name)}:{len(part.content)}B"
                for part in parts[:32]
            )
    elif media_type == "application/json" and len(body) <= 2 * 1024 * 1024:
        try:
            shape = "json=" + ",".join(_json_shape(json.loads(body)))
        except (ValueError, UnicodeDecodeError, RecursionError):
            shape = "json-unparsed"
    elif media_type == "application/x-www-form-urlencoded":
        try:
            from urllib.parse import parse_qsl
            names = [name for name, _ in parse_qsl(body.decode("ascii", "ignore"), keep_blank_values=True)]
            shape = "form=" + ",".join(_safe_field_name(name) for name in names[:32])
        except Exception:
            shape = "form-unparsed"

    host = re.sub(r"[^A-Za-z0-9.:-]", "?", req.pretty_host.lower())[:255]
    logger.info(
        "Observed request method=%s host=%s path=%s type=%s bytes=%d shape=%s",
        req.method.upper(), host, _observation_route(req.path), media_type,
        len(body), shape,
    )


def requestheaders(flow: http.HTTPFlow) -> None:
    """Report body-bearing request headers when mitmproxy has not buffered the body."""
    if not OBSERVE_REQUESTS:
        return
    req = flow.request
    if req.method.upper() not in {"POST", "PUT", "PATCH"} or req.raw_content is not None:
        return
    raw_length = req.headers.get("content-length", "")
    try:
        length = int(raw_length)
    except (TypeError, ValueError):
        length = -1
    if length == 0 or (length < 0 and "transfer-encoding" not in req.headers):
        return
    header = Message()
    try:
        header["content-type"] = req.headers.get("content-type", "")
        media_type = str(header.get_content_type()).lower()
    except Exception:
        media_type = "unknown"
    host = re.sub(r"[^A-Za-z0-9.:-]", "?", req.pretty_host.lower())[:255]
    logger.info(
        "Observed request headers method=%s host=%s path=%s type=%s bytes=%s shape=body-not-buffered",
        req.method.upper(), host, _observation_route(req.path), media_type,
        str(length) if length >= 0 else "unknown",
    )


def _handle_multipart_upload(flow: http.HTTPFlow) -> bool:
    """Intercept multipart/form-data upload, save file locally, and strip it from the request."""
    content_type = flow.request.headers.get("content-type", "")
    if not content_type.lower().startswith("multipart/form-data"):
        return False

    raw_body = flow.request.raw_content
    if raw_body is None:
        flow.response = http.Response.make(400, b"Empty request body")
        return True

    parts = _parse_multipart(raw_body, content_type)
    if parts is None:
        flow.response = http.Response.make(400, b"Invalid multipart upload")
        return True

    file_parts = [p for p in parts if p.name in FILE_FIELDS or bool(p.filename)]
    if not file_parts:
        return False

    saved = 0
    for part in file_parts:
        stored = _store_file(part.filename or "", part.content)
        if stored is None:
            logger.error("Failed to store upload; rejecting request")
            flow.response = http.Response.make(500, b"Failed to store upload")
            return True
        saved += 1
        _notify_capture(stored.name, len(part.content))
        print(f"\n[AI-PRIVACY-PROXY] Captured file: {stored.name} ({len(part.content)} bytes)")
        print(f"[AI-PRIVACY-PROXY] Saved to: {stored.resolve()}")

    boundary = _extract_boundary(content_type)
    if boundary is None:
        flow.response = http.Response.make(400, b"Missing multipart boundary")
        return True

    kept = [p for p in parts if p not in file_parts]
    try:
        new_body = _encode_multipart(boundary, kept)
    except Exception:
        flow.response = http.Response.make(502, b"Failed to rebuild request")
        return True

    flow.request.raw_content = new_body
    flow.request.headers["content-length"] = str(len(new_body))
    logger.info("Intercepted upload: saved %d file(s)", saved)
    return True


_last_registered_filename: str = ""


def _remember_filename(name: str) -> None:
    global _last_registered_filename
    if name and isinstance(name, str):
        _last_registered_filename = name.strip()


def _get_remembered_filename() -> str:
    global _last_registered_filename
    return _last_registered_filename


def _handle_chatgpt_file_upload(flow: http.HTTPFlow) -> bool:
    """Intercept file uploads targeting ChatGPT cloud storage.

    Allows metadata registration through to OpenAI so the UI receives valid tokens,
    then intercepts and stores the actual file PUT payload locally.
    """
    req = flow.request
    method = req.method.upper()
    path = req.path
    host = req.pretty_host.lower()

    if method == "OPTIONS":
        flow.response = http.Response.make(
            200,
            b"",
            {
                "Access-Control-Allow-Origin": req.headers.get("origin", "*"),
                "Access-Control-Allow-Methods": "GET, PUT, POST, OPTIONS, HEAD",
                "Access-Control-Allow-Headers": req.headers.get("access-control-request-headers", "*"),
                "Access-Control-Allow-Credentials": "true",
            },
        )
        return True

    # 1. Metadata registration: POST /backend-api/files
    # Record the filename/size and let this request pass to OpenAI untouched.
    if method == "POST" and path == "/backend-api/files":
        try:
            if req.raw_content:
                data = json.loads(req.raw_content.decode("utf-8"))
                if "file_name" in data:
                    _remember_filename(data["file_name"])
        except Exception:
            pass
        return False

    # 2. Upload finalization & readiness signals:
    # Matches POST /backend-api/files/{file_id} (with index_for_retrieval or file_id),
    # or POST /backend-api/files/{file_id}/uploaded, or GET /backend-api/files/{file_id}
    if "/backend-api/files/" in path:
        is_finalization = False
        file_id = path.split("/backend-api/files/")[1].split("/")[0].split("?")[0]
        file_name = _get_remembered_filename() or "document.pdf"
        use_case = "my_files"
        mime_type = "application/pdf"
        file_size = 0

        if method == "POST":
            raw_str = (req.raw_content or b"").decode("utf-8", errors="ignore")
            if path.endswith("/uploaded") or "index_for_retrieval" in raw_str or "file_id" in raw_str:
                is_finalization = True
                try:
                    data = json.loads(raw_str)
                    if isinstance(data, dict):
                        file_id = data.get("file_id") or file_id
                        file_name = data.get("file_name") or file_name
                        use_case = data.get("use_case", use_case)
                        mime_type = data.get("mime_type", mime_type)
                        file_size = data.get("file_size", file_size)
                except Exception:
                    pass
        elif method == "GET":
            is_finalization = True

        if is_finalization:
            resp_data = {
                "id": file_id,
                "file_name": file_name,
                "status": "success",
                "ready": True,
                "use_case": use_case,
                "mime_type": mime_type,
                "size_bytes": file_size,
                "download_url": f"https://sdmntprcentralindia.oaiusercontent.com/files/{file_id}",
            }
            resp_json = json.dumps(resp_data).encode("utf-8")
            flow.response = http.Response.make(
                200,
                resp_json,
                {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": req.headers.get("origin", "*"),
                    "Access-Control-Allow-Credentials": "true",
                },
            )
            logger.info("Marked ChatGPT file ready locally: %s (%s)", file_name, file_id)
            print(f"\n[AI-PRIVACY-PROXY] Document finalized & marked ready for ChatGPT: {file_name} ({file_id})")
            return True

    # 3. Actual file payload upload: PUT (or multipart POST)
    if method not in {"PUT", "POST"}:
        return False

    body = req.raw_content or b""
    if not body:
        return False

    # If it's a small JSON API call on chatgpt.com (like telemetry or settings), do not treat as a file
    ct = req.headers.get("content-type", "").lower()
    if ct.startswith("application/json") and len(body) < 10000 and "backend-api" in path:
        return False

    filename = ""
    path_name = Path(urlsplit(req.path).path).name
    if path_name and "." in path_name and not path_name.startswith("file-"):
        filename = path_name

    if not filename:
        filename = _get_remembered_filename()

    if not filename and "content-disposition" in req.headers:
        msg = Message()
        msg["content-disposition"] = req.headers["content-disposition"]
        filename = msg.get_filename() or ""

    if not filename:
        parsed = urlsplit(req.path)
        qs = parse_qs(parsed.query)
        if "filename" in qs and qs["filename"]:
            filename = qs["filename"][0]

    if not filename:
        mime_clean = ct.split(";")[0].strip().lower()
        ext = mimetypes.guess_extension(mime_clean) or ".bin"
        if ext == ".jpe":
            ext = ".jpg"
        filename = f"chatgpt_upload{ext}"

    stored = _store_file(filename, body)
    if stored is None:
        logger.error("Failed to store ChatGPT upload (%s)", filename)
        flow.response = http.Response.make(500, b"Failed to store upload locally")
        return True

    logger.info("Intercepted ChatGPT upload: saved to %s (%d bytes)", stored.name, len(body))
    _notify_capture(stored.name, len(body))
    print(f"\n[AI-PRIVACY-PROXY] Captured confidential document: {stored.name} ({len(body)} bytes)")
    print(f"[AI-PRIVACY-PROXY] Stored safely at: {stored.resolve()}")
    print(f"[AI-PRIVACY-PROXY] Intercepted cloud upload: Returning instant 200 OK without sending bytes to cloud.")

    origin = req.headers.get("origin", "*")
    flow.response = http.Response.make(
        200,
        b"",
        {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Methods": "GET, PUT, POST, OPTIONS, HEAD",
            "Access-Control-Allow-Headers": req.headers.get("access-control-request-headers", "*"),
            "Access-Control-Allow-Credentials": "true",
            "ETag": f'"{uuid.uuid4().hex}"',
            "Content-Length": "0",
        },
    )
    return True


def _handle_chatgpt_conversation(flow: http.HTTPFlow) -> bool:
    """Intercept ChatGPT conversation requests.

    Strips attachments and file IDs from the JSON payload, keeping only the user's prompt text.
    """
    req = flow.request
    if req.method.upper() != "POST":
        return False

    ct = req.headers.get("content-type", "").lower()
    if not ct.startswith("application/json"):
        return False

    raw = req.raw_content
    if not raw:
        return False

    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        return False

    modified = False

    if "attachment_mime_types" in data and data["attachment_mime_types"]:
        data["attachment_mime_types"] = []
        modified = True

    messages = data.get("messages")
    if isinstance(messages, list):
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            meta = msg.get("metadata")
            if isinstance(meta, dict):
                to_delete = [k for k in meta if any(term in k.lower() for term in ("attach", "file", "upload"))]
                for k in to_delete:
                    del meta[k]
                    modified = True
            content = msg.get("content")
            if isinstance(content, dict):
                if content.get("content_type") == "multimodal_text":
                    content["content_type"] = "text"
                    parts = content.get("parts", [])
                    content["parts"] = [p for p in parts if isinstance(p, str)]
                    modified = True
                to_delete = [k for k in content if any(term in k.lower() for term in ("attach", "file", "upload"))]
                for k in to_delete:
                    del content[k]
                    modified = True

    pq = data.get("partial_query")
    if isinstance(pq, dict):
        if "attachments" in pq:
            del pq["attachments"]
            modified = True
        content = pq.get("content")
        if isinstance(content, dict) and content.get("content_type") == "multimodal_text":
            content["content_type"] = "text"
            parts = content.get("parts", [])
            content["parts"] = [p for p in parts if isinstance(p, str)]
            modified = True

    if modified:
        new_body = json.dumps(data, separators=(",", ":")).encode("utf-8")
        req.raw_content = new_body
        req.headers["content-length"] = str(len(new_body))
        logger.info("Sanitized ChatGPT conversation: stripped attachment references, retained prompt.")
        print("\n[AI-PRIVACY-PROXY] Stripped document attachment from ChatGPT prompt request.")

    return modified


def request(flow: http.HTTPFlow) -> None:
    if OBSERVE_REQUESTS:
        _observe_request(flow)

    host = flow.request.pretty_host.lower()
    path = flow.request.path

    # 1. Local test server (for integration tests)
    if host in {"127.0.0.1", "localhost"} and flow.request.port == TEST_SERVER_PORT:
        if path == TEST_SERVER_PATH:
            _handle_multipart_upload(flow)
        return

    # 2. ChatGPT file uploads and file metadata
    if "oaiusercontent.com" in host or ("chatgpt.com" in host and ("/backend-api/files" in path or flow.request.method.upper() == "PUT")):
        if _handle_chatgpt_file_upload(flow):
            return

    # 3. ChatGPT conversation submissions
    if "chatgpt.com" in host and "/conversation" in path:
        if _handle_chatgpt_conversation(flow):
            return

    # 4. Standard AI API multipart file uploads (e.g. api.openai.com/v1/files or /upload endpoints)
    if "api.openai.com" in host or path in {"/v1/files", "/upload"}:
        content_type = flow.request.headers.get("content-type", "").lower()
        if content_type.startswith("multipart/form-data"):
            _handle_multipart_upload(flow)


class PrivacyProxyAddon:
    """Mitmproxy addon wrapper for AI Privacy Proxy."""

    def request(self, flow: http.HTTPFlow) -> None:
        request(flow)

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        requestheaders(flow)

