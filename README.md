# AI Privacy Proxy (DLP Gateway) - Version 1

An on-device Data Loss Prevention (DLP) and Privacy Proxy designed to protect confidential files, proprietary documents, and Personally Identifiable Information (PII) from leaking to cloud AI services (such as ChatGPT).

---

## 🎯 How It Works

When using AI web interfaces like ChatGPT, users frequently attach sensitive documents (PDFs, spreadsheets, code, private notes). **AI Privacy Proxy** acts as a local security gateway between your browser and the cloud:

```
[Browser / ChatGPT Web]
         │
         ▼  (1) Upload Document (PUT *.oaiusercontent.com)
[AI Privacy Proxy - 127.0.0.1:8080]
   ├───► Saves document strictly to local disk (./storage/)
   └───► Returns instant HTTP 200 OK directly to browser (0 bytes sent to OpenAI)
         │
         ▼  (2) Check File Readiness (POST /backend-api/files/{id})
[AI Privacy Proxy]
   └───► Mocks {"status": "success", "ready": true}
         │
         ▼  (3) Submit Prompt (POST /backend-api/.../conversation)
[AI Privacy Proxy]
   └───► Scrubs attachment pointers & multimodal objects
         │
         ▼  (4) Clean Prompt Text Only
[OpenAI / ChatGPT Cloud] ───► Responds based strictly on text prompt
```

### Key Security Safeguards
1. **Zero Cloud Leakage**: Document binaries never reach OpenAI, Azure, or external servers.
2. **Local Storage Vault**: Intercepted documents are saved safely on your local disk in `storage/`.
3. **Seamless UX**: ChatGPT's web UI does not crash or display upload errors. It shows the document ready and answers your text prompt.
4. **Failsafe Restoration**: Exiting the proxy (`exit` command or `Ctrl+C`) automatically resets Windows Internet Settings (`ProxyEnable = 0`) and refreshes WinINet.

---

## 🚀 Quick Start

### 1. Requirements
- Windows 10 / 11
- Python 3.10+
- Google Chrome, Microsoft Edge, Brave, or Firefox

### 2. Installation
Clone the repository and install dependencies:
```bash
git clone https://github.com/<your-username>/AI-Privacy-Proxy.git
cd AI-Privacy-Proxy

# Create virtual environment and activate
python -m venv .venv
.\.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Launching Protection
Run via the provided batch script:
```cmd
.\run.bat
```
or run directly with Python:
```bash
python main.py
```

### 4. Interactive Console Commands
While running, `main.py` provides an interactive shell:
| Command | Action |
|---|---|
| `open` / `o` | Opens the local `storage/` folder in Windows File Explorer |
| `list` / `l` | Displays all intercepted documents with timestamps and sizes |
| `status` / `s` | Shows proxy running state, port, and storage metrics |
| `exit` / `quit` | Stops the proxy and cleanly restores Windows internet settings |

---

## 🧪 Testing & Verification

Run the automated test suite verifying ChatGPT flow interception, multipart scrubbing, and end-to-end integration:

```bash
# Run all tests
python -m unittest test_chatgpt_flow.py test_e2e.py proxy/test_proxy.py
```

---

## 📁 Project Structure

```
AI-Privacy-Proxy/
├── proxy/
│   ├── proxy.py          # Core mitmproxy DLP addon (upload interception & redaction)
│   ├── win_proxy.py      # Windows WinINet proxy configuration & Root CA manager
│   ├── test_proxy.py     # Unit tests for multipart parsing & sanitization
│   ├── test_server.py    # Local mock AI server for integration tests
│   └── test_upload.py    # Upload verification test suite
├── storage/              # Local encrypted/hashed vault for intercepted documents
├── logs/                 # Privacy observer logs
├── main.py               # Main CLI gateway application
├── run.bat               # Windows quick-launch script
├── test_chatgpt_flow.py  # Full ChatGPT upload & conversation simulation test
├── test_e2e.py           # End-to-end proxy integration tests
├── requirements.txt      # Project dependencies
└── README.md             # Documentation
```

---

## 🛡️ License
MIT License. Created for local data privacy and AI security research.
