# 🦊 Decko — AI Cyber Assistant v3

Decko is a Windows-first desktop cybersecurity assistant for authorized defensive work, security labs, students, and SOC workflows. It combines an AI assistant with local analysis tools, file forensics, playbooks, anomaly detection, CVE intelligence, and an audit trail.

> Use Decko only on systems and targets you own or have explicit permission to test.

## Features

- Gemini cloud AI and Ollama offline mode
- PyQt6 desktop interface with animated fox avatar
- Network scanning with Nmap support and a built-in fallback
- Web checks with SQLmap, Nikto, Nuclei, Gobuster support, and built-in checks
- File hashing, YARA scanning, and signature-based fallback
- John the Ripper integration for authorized password-audit exercises
- ML anomaly detection using Isolation Forest
- YAML incident-response playbooks
- MITRE ATT&CK educational simulator with a consent gate
- NVD CVE feed, HTML reports, SQLite audit logs, and CSV export
- Optional text-to-speech and speech recognition

## Download options

The repository contains the maintainable source code. The GitHub **Releases** page contains the Windows bundle with the `DeckoTools` directory because the third-party binaries are too large for a normal source repository.

- Source users: download or clone the repository.
- Windows demo users: download `Decko-v3-Windows-with-tools.zip` from Releases.

Do not download GitHub's automatically generated “Source code” archive if you need the bundled external tools.

## Quick start on Windows

1. Install 64-bit Python 3.11 or 3.12 from [python.org](https://www.python.org/downloads/windows/) and enable **Add Python to PATH**.
2. Extract the complete release ZIP to a normal writable directory.
3. Double-click `setup_windows.bat`.
4. Set `GEMINI_API_KEY` for Gemini, or configure Ollama in Decko for offline use.

Manual setup:

```powershell
py -3 -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python verify_installation.py --test-tools
$env:GEMINI_API_KEY = "YOUR_KEY_HERE"
python decko.py
```

Never commit a real API key. A local `.env` file is ignored by Git.

## Linux and macOS

The Python application can run on Linux and macOS, but the bundled external executables are Windows builds. Install native versions of the tools on `PATH` if required.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python verify_installation.py --test-tools
export GEMINI_API_KEY="YOUR_KEY_HERE"
python decko.py
```

## Offline mode with Ollama

Install [Ollama](https://ollama.com/), then:

```bash
ollama pull llama3
ollama serve
```

In Decko, open Settings and use host `http://localhost:11434`, model `llama3`, then select **Apply Ollama Brain**.

## External tool status

Decko discovers tools on the system `PATH` and recursively under `DeckoTools/`. Supported ZIP bundles are extracted automatically on first use.

| Tool | Included in Windows release | Notes |
|---|---:|---|
| Nmap | Yes | Some scan types need Npcap, the Microsoft Visual C++ runtime, and administrator rights. |
| SQLmap | Yes | Runs with the active Python interpreter. |
| John the Ripper | Yes | Windows Security may quarantine password-auditing binaries. Restore only if downloaded from the official release and you intend authorized use. |
| Nikto | Yes | Requires Strawberry Perl on `PATH` plus `JSON` and `XML::Writer` (`cpan JSON XML::Writer`). |
| Nuclei | Yes, compressed | Extracts on first use; templates can require an Internet connection. |
| Gobuster | Yes, compressed | Official Windows x64 build; extracts automatically on first use. |
| YARA CLI | Yes | `yara.exe` is included; `yara-python` remains an optional alternative. |

Run this any time to check the current machine:

```powershell
python verify_installation.py --test-tools
```

An optional tool being unavailable does not prevent the main application from starting; Decko falls back where supported and reports the limitation.

For a strict external-tool check, use `python verify_installation.py --test-tools --strict-tools`. This may fail when an optional runtime or antivirus exception is missing even though the main Decko interface can run.

## Project layout

```text
Decko/
├── decko.py
├── tools.py
├── verify_installation.py
├── setup_windows.bat
├── requirements.txt
├── playbooks/
├── yara_rules/
├── fox.gif / fox_idle.gif / fox_talk.gif / fox_think.gif
└── DeckoTools/                 # Release bundle only; ignored by Git
```

`decko_memory.db` is created locally at runtime and is ignored by Git.

## Security and limitations

- No malware generation or unauthorized exploitation is intended.
- Simulations require user consent and operations are logged.
- Tool output is not proof that a target is safe; validate important findings manually.
- Third-party tools keep their own licenses and are not authored by the Decko project.
- A clean static check cannot guarantee every Windows machine, antivirus policy, driver, network, or API configuration. Use `verify_installation.py` after extraction.

## Built by

**Decko Team** · Graduation Project  
*TKBW — Think, Know, Build, Work Smart.*
