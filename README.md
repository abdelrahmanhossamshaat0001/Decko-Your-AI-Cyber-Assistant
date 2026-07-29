# 🦊 Decko — AI Cyber Assistant  v2.0


---

## What Is Decko?

Decko is an **AI-powered cybersecurity copilot** designed for defensive security workflows,
ethical hacking teams, students, and SOC analysts.  
It is **not just a chatbot** — it is a full desktop security workstation with:

- Dual AI brain (Gemini cloud + Ollama offline)
- Animated fox avatar with lip-sync
- Network scanner, web fuzzer, crypto workbench
- File forensics + YARA signature engine
- ML anomaly detection (IsolationForest)
- YAML playbook engine for incident response
- MITRE ATT&CK educational simulator (with consent gate)
- Live CVE feed from NVD API 2.0
- Full SQLite audit trail + CSV export
- Voice output (TTS) and voice input (STT) support

---

## Project Structure

```
decko_v2/
├── decko.py              # Main PyQt6 application (complete rewrite v2.0)
├── tools.py              # All security tool functions
├── requirements.txt      # Python dependencies
├── playbooks/
│   ├── malware_response.yaml
│   └── ransomware_containment.yaml
├── fox_idle.gif          # Avatar animations
├── fox_talk.gif
├── fox_think.gif
├── fox.gif
└── decko_memory.db       # SQLite audit log (auto-created)
```

---

## Setup (Windows — Recommended)

```powershell
cd "C:\Users\YourName\Desktop\Decko_Project"

# 1. Create virtual environment
python -m venv venv

# 2. Activate it
venv\Scripts\activate

# 3. Install all dependencies
pip install -r requirements.txt

# 4. Set your Gemini API key (get one free at aistudio.google.com)
$env:GEMINI_API_KEY = "YOUR_KEY_HERE"

# 5. Run Decko
python decko.py
```

---

## Setup (Linux / macOS)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export GEMINI_API_KEY="YOUR_KEY_HERE"
python decko.py
```

---

## Offline Mode (Ollama — Zero Internet Required)

```bash
# 1. Install Ollama from https://ollama.com
# 2. Pull a model
ollama pull llama3

# 3. Start Ollama server
ollama serve

# 4. In Decko → Settings tab → Ollama section
#    Host:  http://localhost:11434
#    Model: llama3
#    Click: Apply Ollama Brain
```

---

## Feature Checklist

| Module              | Status | Notes |
|---------------------|--------|-------|
| PyQt6 Desktop UI    | ✅ Done | Frameless, transparent, always-on-top |
| Fox Avatar + GIFs   | ✅ Done | Idle / Think / Talk — lip-sync on AI reply |
| Gemini AI Chat      | ✅ Done | google-genai SDK (new + legacy fallback) |
| Ollama Offline LLM  | ✅ Done | llama3, phi3, any Ollama model |
| File Forensics      | ✅ Done | MD5, SHA256, size, DB log |
| YARA Scanner        | ✅ Done | yara-python + built-in string fallback |
| Port Scanner        | ✅ Done | 25 common ports, risk flagging |
| Web Directory Fuzz  | ✅ Done | 23 sensitive paths + security headers |
| Crypto Workbench    | ✅ Done | SHA256, MD5, Base64, password gen |
| Hash Dictionary     | ✅ Done | Crack MD5 against wordlist |
| Static Code Audit   | ✅ Done | 16 risk patterns, multi-severity |
| ML Anomaly Detect   | ✅ Done | IsolationForest, auto-collection |
| Playbook Engine     | ✅ Done | YAML, 2 sample playbooks included |
| MITRE Simulator     | ✅ Done | 8 techniques, consent gate |
| CVE Live Feed       | ✅ Done | NVD API 2.0, keyword filter |
| Voice Output (TTS)  | ✅ Done | pyttsx3 toggle in Settings |
| Voice Input (STT)   | ✅ Done | SpeechRecognition + microphone |
| HTML Report Gen     | ✅ Done | Full styled report, opens in browser |
| SQLite Audit Log    | ✅ Done | All ops, forensics, playbooks, sims |
| Log CSV Export      | ✅ Done | Export to file |
| System Monitor      | ✅ Done | Live CPU + RAM in status bar |

---

## Security & Ethics

Decko is designed **exclusively for authorized defensive security work**.

- No malware generation
- No unauthorized exploitation
- No credential brute-force or stealth features
- Consent gate required before any simulation
- All operations immutably logged with timestamps
- Works fully offline (Ollama mode) — zero data leakage

---

## Graduation Demo Flow

1. **Dashboard** — Click "Run Demo" to load all scenarios
2. **Terminal** — Chat with Decko AI
3. **Forensics** — Load a file → hash → YARA scan
4. **Arsenal → Network** — Scan 127.0.0.1
5. **Arsenal → Web** — Fuzz http://localhost
6. **Arsenal → Crypto** — Hash + Base64 operations
7. **Coding** — Click "Analyze Code Risks" on pre-loaded risky sample
8. **Anomaly** — Watch ML collect baseline (8 samples) → Run Analysis
9. **Playbook** — Select malware_response.yaml → Execute
10. **Simulator** — Choose T1059.001 → Consent → Run
11. **Intel** — Fetch CVEs (keyword: Apache or Windows)
12. **Dashboard** — Click "Generate Report" → opens HTML in browser

---

## Dependencies

| Package | Purpose |
|---------|---------|
| PyQt6 | Desktop GUI |
| google-genai | Gemini AI brain |
| psutil | System metrics |
| requests | HTTP tools + CVE feed |
| PyYAML | Playbook engine |
| scikit-learn | ML anomaly detection |
| numpy | Numerical data for ML |
| pyttsx3 | Offline text-to-speech |
| SpeechRecognition | Voice input |

---

## Built by
AbdElrahman Hossam

*TKBW — Think, Know, Build, Work Smart.*
