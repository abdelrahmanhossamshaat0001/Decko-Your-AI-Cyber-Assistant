"""
tools.py  -  Decko Security Tools Module  v3.0
All defensive analysis tools used by the Decko AI Cyber Assistant.
Every function has graceful fallbacks when optional libs are missing.
"""

import os
import re
import json
import socket
import hashlib
import struct
import base64
import string
import random
import threading
import subprocess
import shutil
import zipfile
import tempfile
from datetime import datetime
from pathlib import Path

import requests
import psutil

# ── Optional library imports with fallbacks ─────────────────────────────────
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    import pyttsx3
    TTS_AVAILABLE = True
except ImportError:
    TTS_AVAILABLE = False

try:
    import speech_recognition as sr
    STT_AVAILABLE = True
except ImportError:
    STT_AVAILABLE = False


# ════════════════════════════════════════════════════════════════════════════
#  EXTERNAL TOOL DISCOVERY  —  auto-detects real tools under DeckoTools/,
#  no manual PATH setup needed. Falls back gracefully if a tool is missing.
# ════════════════════════════════════════════════════════════════════════════

PROJECT_DIR     = Path(__file__).resolve().parent
DECKO_TOOLS_DIR = Path(os.getenv("DECKO_TOOLS_DIR", str(PROJECT_DIR / "DeckoTools")))
YARA_RULES_DIR  = PROJECT_DIR / "yara_rules"

_tool_path_cache: dict = {}


def _extract_zip_if_needed(zip_stem: str) -> None:
    """Auto-unzip DeckoTools/<zip_stem>.zip the first time it's needed."""
    zip_path = DECKO_TOOLS_DIR / f"{zip_stem}.zip"
    marker   = DECKO_TOOLS_DIR / f".{zip_stem}_extracted"
    if not zip_path.exists() or marker.exists():
        return
    try:
        with zipfile.ZipFile(zip_path) as zf:
            destination = (DECKO_TOOLS_DIR / zip_stem).resolve()
            for member in zf.infolist():
                member_path = (destination / member.filename).resolve()
                if destination not in member_path.parents and member_path != destination:
                    raise ValueError(f"Unsafe path in archive: {member.filename}")
            zf.extractall(destination)
        marker.touch()
    except Exception:
        pass


def find_tool(key: str, filenames: list, zip_stem: str = None) -> str:
    """
    Locate a real external tool's executable/script.
    Search order: cache -> system PATH -> recursive search under DeckoTools/
    -> auto-extract a matching .zip under DeckoTools/ and search again.
    Returns the full path as a string, or "" if the tool isn't found anywhere.
    """
    if key in _tool_path_cache:
        return _tool_path_cache[key]

    for name in filenames:
        found = shutil.which(name)
        if found:
            _tool_path_cache[key] = found
            return found

    if DECKO_TOOLS_DIR.exists():
        for name in filenames:
            for match in DECKO_TOOLS_DIR.rglob(name):
                if match.is_file():
                    _tool_path_cache[key] = str(match)
                    return str(match)

    if zip_stem:
        _extract_zip_if_needed(zip_stem)
        if DECKO_TOOLS_DIR.exists():
            for name in filenames:
                for match in DECKO_TOOLS_DIR.rglob(name):
                    if match.is_file():
                        _tool_path_cache[key] = str(match)
                        return str(match)

    _tool_path_cache[key] = ""
    return ""


def get_tools_status() -> dict:
    """Report which real external tools were actually found on this machine."""
    checks = {
        "nmap":     (["nmap.exe", "nmap"], None),
        "sqlmap":   (["sqlmap.py"], None),
        "john":     (["john.exe", "john"], "john-1.9.0-jumbo-1-win64"),
        "yara":     (["yara64.exe", "yara.exe", "yara"], None),
        "nikto":    (["nikto.pl"], None),
        "gobuster": (["gobuster.exe", "gobuster"], "gobuster_Windows_x86_64"),
        "nuclei":   (["nuclei.exe", "nuclei"], "nuclei_3.11.0_windows_amd64"),
    }
    status = {}
    for key, (names, zstem) in checks.items():
        path = find_tool(key, names, zstem)
        status[key] = path or None
    return status


def print_tools_banner() -> None:
    status = get_tools_status()
    found   = [k for k, v in status.items() if v]
    missing = [k for k, v in status.items() if not v]
    print(f"[DECKO TOOLS] Detected  : {found or 'none'}")
    print(f"[DECKO TOOLS] Not found : {missing or 'none'}")
    if missing:
        print(f"[DECKO TOOLS] Looked under: {DECKO_TOOLS_DIR}")


print_tools_banner()


# ════════════════════════════════════════════════════════════════════════════
#  NETWORK TOOLS
# ════════════════════════════════════════════════════════════════════════════

COMMON_PORTS = {
    21: "FTP",       22: "SSH",       23: "Telnet",    25: "SMTP",
    53: "DNS",       80: "HTTP",      110: "POP3",     135: "RPC",
    139: "NetBIOS",  143: "IMAP",     443: "HTTPS",    445: "SMB",
    993: "IMAPS",    995: "POP3S",    1433: "MSSQL",   1521: "Oracle",
    3306: "MySQL",   3389: "RDP",     5432: "Postgres", 5900: "VNC",
    6379: "Redis",   8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}
RISKY_PORTS = {21, 23, 135, 139, 445, 3389, 5900, 6379, 27017}


def _nmap_scan(target: str) -> str:
    """Run a real Nmap scan if the binary was found; empty string if not."""
    nmap_exe = find_tool("nmap", ["nmap.exe", "nmap"])
    if not nmap_exe:
        return ""
    try:
        proc = subprocess.run(
            [nmap_exe, "-T4", "-sV", "-Pn", "--top-ports", "100", target],
            capture_output=True, text=True, timeout=180,
        )
        out = (proc.stdout or proc.stderr or "").strip()
        return out
    except Exception as e:
        return f"[nmap error] {e}"


def scan_ports(target: str, timeout: float = 0.6) -> str:
    """Real Nmap scan when nmap is available on this machine, otherwise
    a built-in TCP connect scan of common service ports."""
    nmap_out = _nmap_scan(target)
    if nmap_out:
        return (
            f"┌─[ NMAP SCAN — {target} ]────────────────────────\n"
            f"│ Engine : real nmap ({find_tool('nmap', ['nmap.exe','nmap'])})\n"
            f"└─────────────────────────────────────────────────\n\n"
            f"{nmap_out}"
        )
    return _scan_ports_builtin(target, timeout)


def _scan_ports_builtin(target: str, timeout: float = 0.6) -> str:
    """TCP connect scan of common service ports on an authorized target."""
    lines = [
        f"┌─[ DECKO NETWORK SCAN ]──────────────────────────",
        f"│ Target : {target}",
        f"│ Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"└─────────────────────────────────────────────────",
        "",
    ]
    open_ports = []
    for port, service in sorted(COMMON_PORTS.items()):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((target, port)) == 0:
                risk = "  ⚠ HIGH RISK" if port in RISKY_PORTS else ""
                lines.append(f"  [OPEN]  {port:5d}/tcp  {service}{risk}")
                open_ports.append(port)
            s.close()
        except OSError:
            pass

    if not open_ports:
        lines.append("  [-] No common ports open (host unreachable or all filtered)")
    lines += [
        "",
        f"  Summary: {len(open_ports)} open port(s) found",
    ]
    risky = RISKY_PORTS & set(open_ports)
    if risky:
        lines.append(f"  WARNING: High-risk ports detected → {sorted(risky)}")
        lines.append("  Recommendation: Review firewall rules immediately.")
    return "\n".join(lines)


_DEFAULT_WORDLIST = [
    "admin", "login", "backup", "config", "test", "api", "dev", "staging",
    "uploads", "images", "assets", "old", "tmp", "db", "data", "private",
    "wp-admin", "phpmyadmin", "console", "dashboard", "panel", "secret",
]


def _gobuster_scan(url: str) -> str:
    """Run real Gobuster directory brute-force if the binary was found."""
    gobuster_exe = find_tool("gobuster", ["gobuster.exe", "gobuster"],
                              zip_stem="gobuster_Windows_x86_64")
    if not gobuster_exe:
        return ""
    wordlist_path = ""
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("\n".join(_DEFAULT_WORDLIST))
            wordlist_path = f.name
        proc = subprocess.run(
            [gobuster_exe, "dir", "-u", url, "-w", wordlist_path,
             "-t", "20", "-q", "--timeout", "5s"],
            capture_output=True, text=True, timeout=90,
        )
        return (proc.stdout or proc.stderr or "").strip()
    except Exception as e:
        return f"[gobuster error] {e}"
    finally:
        try:
            os.unlink(wordlist_path)
        except Exception:
            pass


def sqlmap_scan(url: str, extra_args: list = None) -> str:
    """Run real sqlmap against a URL (authorized testing only)."""
    sqlmap_py = find_tool("sqlmap", ["sqlmap.py"])
    if not sqlmap_py:
        return "[!] sqlmap.py not found under DeckoTools/ — check sqlmap-master was extracted"
    import sys as _sys
    cmd = [_sys.executable, sqlmap_py, "-u", url, "--batch", "--level=1", "--risk=1"]
    if extra_args:
        cmd += extra_args
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        return (proc.stdout or proc.stderr or "").strip()
    except Exception as e:
        return f"[sqlmap error] {e}"


def nikto_scan(url: str) -> str:
    """Run real Nikto against a URL (requires Perl on PATH)."""
    nikto_pl = find_tool("nikto", ["nikto.pl"])
    if not nikto_pl:
        return "[!] nikto.pl not found under DeckoTools/ — check nikto-main folder"
    perl = shutil.which("perl")
    if not perl:
        return "[!] Perl not found on PATH — install Strawberry Perl to run Nikto on Windows"
    try:
        proc = subprocess.run([perl, nikto_pl, "-h", url],
                               capture_output=True, text=True, timeout=180)
        return (proc.stdout or proc.stderr or "").strip()
    except Exception as e:
        return f"[nikto error] {e}"


def nuclei_scan(target: str) -> str:
    """Run real Nuclei against a target (authorized testing only)."""
    nuclei_exe = find_tool("nuclei", ["nuclei.exe", "nuclei"],
                            zip_stem="nuclei_3.11.0_windows_amd64")
    if not nuclei_exe:
        return "[!] nuclei not found under DeckoTools/ — check the zip was extracted"
    try:
        proc = subprocess.run([nuclei_exe, "-u", target, "-silent"],
                               capture_output=True, text=True, timeout=180)
        return (proc.stdout or proc.stderr or "").strip() or "[+] No findings"
    except Exception as e:
        return f"[nuclei error] {e}"


def web_directory_fuzzer(url: str, timeout: int = 4) -> str:
    """Check web surface exposure — real Gobuster run (if available) plus
    a built-in check of common sensitive paths and security headers."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    gobuster_out = _gobuster_scan(url)
    builtin_out  = _web_directory_fuzzer_builtin(url, timeout)

    if gobuster_out:
        return (
            f"┌─[ GOBUSTER (real) ]─────────────────────────────\n"
            f"{gobuster_out}\n\n"
            f"{builtin_out}"
        )
    return builtin_out


def _web_directory_fuzzer_builtin(url: str, timeout: int = 4) -> str:
    sensitive_paths = [
        "/admin", "/login", "/wp-admin", "/phpmyadmin", "/dashboard",
        "/.env", "/.git/config", "/config", "/backup", "/backup.zip",
        "/api", "/api/v1", "/api/v2", "/swagger", "/swagger-ui.html",
        "/robots.txt", "/sitemap.xml", "/.htaccess", "/server-status",
        "/actuator", "/actuator/env", "/graphql", "/console", "/trace",
        "/.DS_Store", "/web.config", "/xmlrpc.php",
    ]
    security_headers = [
        "Strict-Transport-Security", "Content-Security-Policy",
        "X-Frame-Options", "X-Content-Type-Options",
        "X-XSS-Protection", "Referrer-Policy", "Permissions-Policy",
    ]

    lines = [
        f"┌─[ WEB EXPOSURE CHECK ]──────────────────────────",
        f"│ Target : {url}",
        f"│ Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"└─────────────────────────────────────────────────",
        "",
        "[ Path Enumeration ]",
    ]
    found = []
    headers_ua = {"User-Agent": "Decko-Security-Scanner/3.0"}
    for path in sensitive_paths:
        try:
            r = requests.get(url + path, timeout=timeout,
                             allow_redirects=False, headers=headers_ua)
            if r.status_code in (200, 201, 301, 302, 403, 500):
                tag = {200: "EXPOSED", 201: "EXPOSED", 403: "FORBIDDEN",
                       301: "REDIRECT", 302: "REDIRECT", 500: "ERROR"}.get(r.status_code, str(r.status_code))
                lines.append(f"  [!] {path:<30} → {tag} ({r.status_code})")
                found.append(path)
        except Exception:
            pass

    if not found:
        lines.append("  [+] No sensitive paths exposed")

    lines += ["", "[ Security Headers ]"]
    try:
        r = requests.get(url, timeout=timeout, headers=headers_ua)
        for h in security_headers:
            if h.lower() in {k.lower() for k in r.headers}:
                lines.append(f"  [+] {h}: Present")
            else:
                lines.append(f"  [-] {h}: MISSING")
    except Exception as e:
        lines.append(f"  [!] Header check failed: {e}")

    lines += ["", f"  Summary: {len(found)} exposed path(s) found"]
    return "\n".join(lines)


# ════════════════════════════════════════════════════════════════════════════
#  HASH & CRYPTO
# ════════════════════════════════════════════════════════════════════════════

_JOHN_FORMAT = {32: "raw-md5", 40: "raw-sha1", 64: "raw-sha256"}


def _john_crack(hash_value: str, wordlist: list) -> str:
    """Run real John the Ripper against the hash. Returns '' if unavailable
    or if John itself couldn't be run (not the same as 'not cracked')."""
    john_exe = find_tool(
        "john",
        ["john.exe", "john"],
        zip_stem="john-1.9.0-jumbo-1-win64",
    )
    if not john_exe:
        return ""
    h = hash_value.strip().lower()
    fmt = _JOHN_FORMAT.get(len(h))
    if not fmt:
        return ""  # John's raw formats here only cover MD5/SHA1/SHA256

    tmp_dir = Path(tempfile.mkdtemp(prefix="decko_john_"))
    hash_file = tmp_dir / "hash.txt"
    wl_file   = tmp_dir / "wordlist.txt"
    pot_file  = tmp_dir / "john.pot"
    try:
        hash_file.write_text(h + "\n")
        wl_file.write_text("\n".join(wordlist))
        subprocess.run(
            [john_exe, f"--format={fmt}", f"--pot={pot_file}",
             f"--wordlist={wl_file}", str(hash_file)],
            capture_output=True, text=True, timeout=120,
        )
        show = subprocess.run(
            [john_exe, f"--format={fmt}", f"--pot={pot_file}",
             "--show", str(hash_file)],
            capture_output=True, text=True, timeout=30,
        )
        out = show.stdout.strip()
        if ":" in out and not out.lower().startswith("0 password"):
            cracked_pw = out.split(":", 1)[1].split("\n")[0].strip()
            return (f"[ HASH LAB — real John the Ripper, format={fmt} ]\n"
                    f"  [CRACKED] Plain text: '{cracked_pw}'")
        return (f"[ HASH LAB — real John the Ripper, format={fmt} ]\n"
                f"  [-] Not found in provided wordlist")
    except Exception as e:
        return f"[john error] {e}"
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def crack_hash(hash_value: str, wordlist: list) -> str:
    """Real John the Ripper when available (MD5/SHA1/SHA256), otherwise a
    pure-Python dictionary check."""
    john_out = _john_crack(hash_value, wordlist)
    if john_out:
        return john_out
    return _crack_hash_builtin(hash_value, wordlist)


def _crack_hash_builtin(hash_value: str, wordlist: list) -> str:
    """Dictionary-based hash cracking for authorized lab use."""
    h = hash_value.strip().lower()
    type_map = {32: "MD5", 40: "SHA-1", 56: "SHA-224", 64: "SHA-256",
                96: "SHA-384", 128: "SHA-512"}
    h_type = type_map.get(len(h), f"Unknown ({len(h)} chars)")

    lines = [
        f"[ HASH LAB — {h_type} ]",
        f"  Input : {h[:32]}{'...' if len(h) > 32 else ''}",
        "",
    ]
    cracked = False
    for word in wordlist:
        for name, fn in [("MD5", hashlib.md5), ("SHA1", hashlib.sha1),
                         ("SHA256", hashlib.sha256)]:
            if fn(word.encode()).hexdigest().lower() == h:
                lines.append(f"  [CRACKED] Plain text: '{word}'  (algorithm: {name})")
                cracked = True
                break
        if cracked:
            break
    if not cracked:
        lines.append("  [-] Not found in provided wordlist")
        lines.append("  Tip: Use a larger dictionary (e.g., rockyou.txt) for real-world checks")
    return "\n".join(lines)


# ════════════════════════════════════════════════════════════════════════════
#  STATIC CODE AUDIT
# ════════════════════════════════════════════════════════════════════════════

RISK_PATTERNS = [
    (r"\beval\s*\(",               "CRITICAL", "eval() — arbitrary code execution"),
    (r"\bexec\s*\(",               "CRITICAL", "exec() — code injection vector"),
    (r"os\.system\s*\(",           "HIGH",     "os.system() — shell injection possible"),
    (r"subprocess.*shell\s*=\s*True", "HIGH",  "subprocess with shell=True — injection risk"),
    (r"pickle\.loads?\s*\(",       "HIGH",     "pickle deserialization — RCE risk"),
    (r"__import__\s*\(",           "HIGH",     "Dynamic import — code injection vector"),
    (r"(password|passwd|secret|api_key|token|private_key)\s*=\s*['\"][^'\"]{4,}['\"]",
                                   "HIGH",     "Hardcoded credential detected"),
    (r"verify\s*=\s*False",        "HIGH",     "SSL verification disabled — MITM risk"),
    (r"md5\s*\(",                  "MEDIUM",   "MD5 usage — weak, collision-vulnerable"),
    (r"\bsha1\s*\(",               "MEDIUM",   "SHA-1 usage — deprecated for security"),
    (r"http://",                   "MEDIUM",   "Plaintext HTTP — upgrade to HTTPS"),
    (r"0\.0\.0\.0",               "MEDIUM",   "Binding to all interfaces — restrict scope"),
    (r"debug\s*=\s*True",          "MEDIUM",   "Debug mode on — disable in production"),
    (r"random\.(random|randint|choice)\s*\(",
                                   "LOW",      "Non-cryptographic random — use secrets module"),
    (r"print\s*\(.*password",      "LOW",      "Potential password printed to stdout"),
    (r"\bTODO\b|\bFIXME\b|\bHACK\b|\bNOTSECURE\b",
                                   "INFO",     "Technical debt marker"),
]


def audit_source_code(source_code: str) -> str:
    """Multi-severity static analysis for common security vulnerabilities."""
    lines = source_code.split("\n")
    findings: dict[str, list] = {k: [] for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for pattern, severity, description in RISK_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings[severity].append((i, description, stripped[:90]))

    total = sum(len(v) for v in findings.values())
    out = [
        f"┌─[ CODE SECURITY AUDIT ]─────────────────────────",
        f"│ Lines : {len(lines)}   Findings : {total}",
        f"│ Time  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"└─────────────────────────────────────────────────",
        "",
    ]

    if total == 0:
        out.append("  [+] No common security issues detected — clean pass")
    else:
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if findings[sev]:
                out.append(f"  [{sev}]  ({len(findings[sev])} finding(s))")
                for lineno, desc, snippet in findings[sev]:
                    out.append(f"    Line {lineno:4d}: {desc}")
                    out.append(f"             → {snippet}")
                out.append("")

    out.append("  Recommendation: Review each finding in its full context.")
    return "\n".join(out)


# ════════════════════════════════════════════════════════════════════════════
#  YARA SCANNER
# ════════════════════════════════════════════════════════════════════════════

# Built-in rules (plain strings, no YARA lib required for basic scan)
SUSPICIOUS_SIGS = [
    (b"cmd.exe",              "HIGH",   "Windows command interpreter reference"),
    (b"powershell -enc",      "HIGH",   "Encoded PowerShell command"),
    (b"powershell -nop",      "HIGH",   "PowerShell NoProfile flag"),
    (b"CreateRemoteThread",   "CRIT",   "Thread injection API"),
    (b"VirtualAllocEx",       "CRIT",   "Remote memory allocation API"),
    (b"WriteProcessMemory",   "CRIT",   "Process memory write API"),
    (b"WScript.Shell",        "CRIT",   "Windows Script Host shell"),
    (b"Base64,",              "MEDIUM", "Inline Base64 data"),
    (b"EICAR-STANDARD",       "CRIT",   "EICAR test signature"),
    (b"MZ",                   "INFO",   "Windows PE executable header"),
    (b"This program cannot",  "INFO",   "Windows PE stub message"),
    (b"eval(base64_decode",   "HIGH",   "PHP webshell pattern"),
    (b"<?php system(",        "HIGH",   "PHP command execution"),
    (b"nc -e /bin/sh",        "CRIT",   "Netcat reverse shell"),
    (b"/bin/sh",              "MEDIUM", "Unix shell reference"),
]

BUILTIN_YARA_SOURCE = """
rule SuspiciousWindowsStrings {
    meta:
        description = "Detects common Windows malware indicators"
        severity = "HIGH"
    strings:
        $s1 = "cmd.exe" nocase
        $s2 = "powershell -enc" nocase
        $s3 = "WScript.Shell" nocase
        $s4 = "CreateRemoteThread"
        $s5 = "VirtualAllocEx"
    condition:
        any of them
}
rule PHPWebshell {
    meta:
        description = "Detects PHP webshell patterns"
        severity = "CRITICAL"
    strings:
        $p1 = "<?php system(" nocase
        $p2 = "eval(base64_decode" nocase
        $p3 = "passthru($_" nocase
    condition:
        any of them
}
rule EicarTest {
    meta:
        description = "EICAR antivirus test file"
        severity = "INFO"
    strings:
        $e = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $e
}
"""


def yara_scan_file(file_path: str) -> str:
    """Scan a file with YARA rules (or string-based fallback)."""
    fname = os.path.basename(file_path)
    lines = [
        f"┌─[ YARA / SIGNATURE SCAN ]───────────────────────",
        f"│ File : {fname}",
        f"│ Time : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"└─────────────────────────────────────────────────",
        "",
    ]

    # Read file bytes
    try:
        with open(file_path, "rb") as f:
            content = f.read()
        size_kb = len(content) / 1024
        lines.append(f"  Size: {size_kb:.1f} KB  |  "
                     f"MD5: {hashlib.md5(content).hexdigest()}")
        lines.append("")
    except Exception as e:
        lines.append(f"  [!] Cannot read file: {e}")
        return "\n".join(lines)

    # Try yara-python first
    if YARA_AVAILABLE:
        try:
            rules = yara.compile(source=BUILTIN_YARA_SOURCE)
            matches = rules.match(data=content)
            if matches:
                lines.append(f"  [!] {len(matches)} YARA rule(s) triggered:")
                for m in matches:
                    sev = m.meta.get("severity", "UNKNOWN")
                    desc = m.meta.get("description", "")
                    lines.append(f"    [{sev}] {m.rule} — {desc}")
            else:
                lines.append("  [+] No YARA matches — file appears clean")
            lines.append(f"\n  Engine: yara-python {yara.__version__}")
            return "\n".join(lines)
        except Exception as e:
            lines.append(f"  [!] YARA engine error: {e}")

    # Try the real YARA CLI against the project's rule files.
    yara_exe = find_tool("yara", ["yara64.exe", "yara.exe", "yara"])
    if yara_exe and YARA_RULES_DIR.exists():
        try:
            rule_files = sorted(
                str(path) for pattern in ("*.yar", "*.yara")
                for path in YARA_RULES_DIR.glob(pattern)
                if path.is_file()
            )
            if not rule_files:
                raise FileNotFoundError(f"No .yar or .yara rules found in {YARA_RULES_DIR}")
            proc = subprocess.run(
                [yara_exe, *rule_files, file_path],
                capture_output=True, text=True, timeout=30,
            )
            out = (proc.stdout or "").strip()
            if proc.returncode not in (0, 1):
                raise RuntimeError((proc.stderr or out or f"exit code {proc.returncode}").strip())
            lines.append(f"  Engine: real yara ({yara_exe})")
            lines.append("")
            if out:
                lines.append("  [!] Rule(s) triggered:")
                for row in out.splitlines():
                    lines.append(f"    {row}")
            else:
                lines.append("  [+] No YARA matches — file appears clean")
            return "\n".join(lines)
        except Exception as e:
            lines.append(f"  [!] yara binary error: {e}")

    # Fallback: byte-string signatures
    lines.append("  Engine: Built-in string signatures (yara-python not installed)")
    lines.append("")
    found = []
    for sig, severity, desc in SUSPICIOUS_SIGS:
        if sig.lower() in content.lower():
            found.append((severity, desc, sig.decode("utf-8", errors="replace")))

    if found:
        lines.append(f"  [!] {len(found)} signature(s) matched:")
        for sev, desc, sig in found:
            lines.append(f"    [{sev}] {desc}  ('{sig}')")
    else:
        lines.append("  [+] No suspicious signatures detected")

    # Extract printable strings (quick)
    printable = re.findall(rb"[ -~]{6,}", content)
    if printable:
        lines += ["", f"  Extracted strings (first 10):"]
        for s in printable[:10]:
            lines.append(f"    {s.decode('ascii', errors='replace')[:80]}")

    return "\n".join(lines)


# ════════════════════════════════════════════════════════════════════════════
#  ML ANOMALY DETECTION
# ════════════════════════════════════════════════════════════════════════════

def collect_system_snapshot() -> dict:
    """Collect a real-time system metrics snapshot."""
    snap: dict = {"ts": datetime.now().strftime("%H:%M:%S")}
    try:
        snap["cpu"]  = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        snap["ram"]  = mem.percent
        net = psutil.net_io_counters()
        snap["net_sent_mb"] = round(net.bytes_sent / 1e6, 2)
        snap["net_recv_mb"] = round(net.bytes_recv / 1e6, 2)
        try:
            conns = psutil.net_connections()
            snap["connections"] = len(conns)
        except Exception:
            snap["connections"] = 0
        procs = list(psutil.process_iter(["pid", "name", "cpu_percent"]))
        snap["processes"] = len(procs)
        top = max(procs, key=lambda p: p.info.get("cpu_percent") or 0, default=None)
        snap["top_proc"]  = top.info["name"] if top else "N/A"
        snap["top_cpu"]   = top.info.get("cpu_percent", 0) if top else 0
    except Exception as e:
        snap["error"] = str(e)
    return snap


def run_anomaly_detection(history: list) -> str:
    """Run IsolationForest on collected metric history."""
    lines = [
        f"┌─[ ML ANOMALY DETECTION ]────────────────────────",
        f"│ Samples : {len(history)}",
        f"│ Time    : {datetime.now().strftime('%H:%M:%S')}",
        f"└─────────────────────────────────────────────────",
        "",
    ]

    if not SKLEARN_AVAILABLE:
        lines += [
            "  scikit-learn not installed.",
            "  Install: pip install scikit-learn numpy",
        ]
        return "\n".join(lines)

    MIN_SAMPLES = 8
    if len(history) < MIN_SAMPLES:
        lines.append(f"  Collecting baseline... ({len(history)}/{MIN_SAMPLES} samples)")
        return "\n".join(lines)

    try:
        X = np.array([[
            d.get("cpu", 0),
            d.get("ram", 0),
            d.get("connections", 0),
            d.get("processes", 0),
        ] for d in history], dtype=float)

        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(X)
        preds  = model.predict(X)
        scores = model.score_samples(X)

        anomalies = [i for i, p in enumerate(preds) if p == -1]
        if anomalies:
            lines.append(f"  [!] {len(anomalies)} anomalous sample(s) detected!")
            for idx in anomalies[-5:]:
                d = history[idx]
                lines.append(
                    f"    #{idx} at {d.get('ts','?')}  "
                    f"CPU={d.get('cpu',0):.1f}%  RAM={d.get('ram',0):.1f}%  "
                    f"Conns={d.get('connections',0)}  Score={scores[idx]:.3f}"
                )
        else:
            lines.append("  [+] All samples within normal range — no anomalies")

        latest = history[-1]
        lines += [
            "",
            "  [ Latest Snapshot ]",
            f"    CPU        : {latest.get('cpu', 0):.1f}%",
            f"    RAM        : {latest.get('ram', 0):.1f}%",
            f"    Connections: {latest.get('connections', 0)}",
            f"    Processes  : {latest.get('processes', 0)}",
            f"    Top process: {latest.get('top_proc', 'N/A')} "
            f"({latest.get('top_cpu', 0):.1f}% CPU)",
        ]

    except Exception as e:
        lines.append(f"  [!] Analysis error: {e}")

    return "\n".join(lines)


# ════════════════════════════════════════════════════════════════════════════
#  PLAYBOOK ENGINE
# ════════════════════════════════════════════════════════════════════════════

PLAYBOOKS_DIR = Path(__file__).parent / "playbooks"


def list_playbooks() -> list:
    """Return all YAML playbook paths."""
    if not PLAYBOOKS_DIR.exists():
        return []
    return sorted(PLAYBOOKS_DIR.glob("*.yaml")) + sorted(PLAYBOOKS_DIR.glob("*.yml"))


def load_playbook(path) -> tuple:
    """Load a YAML playbook. Returns (data, error_msg)."""
    if not YAML_AVAILABLE:
        return None, "PyYAML not installed — run: pip install pyyaml"
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f), None
    except Exception as e:
        return None, str(e)


def execute_playbook(playbook_data: dict, log_cb=None) -> str:
    """Execute a playbook dict and return a detailed log."""
    name  = playbook_data.get("name", "Unnamed Playbook")
    steps = playbook_data.get("steps", [])
    lines = [
        f"┌─[ PLAYBOOK: {name} ]",
        f"│ Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"│ Steps   : {len(steps)}",
        f"└─────────────────────────────────────────────────",
        "",
    ]

    for i, step in enumerate(steps, 1):
        sname = step.get("name", f"Step {i}")
        stype = step.get("type", "log")
        desc  = step.get("description", "")

        lines.append(f"  ► Step {i}/{len(steps)}: {sname}")
        if desc:
            lines.append(f"    Info: {desc}")

        if stype == "log":
            lines.append(f"    [LOG] {step.get('message', '')}")

        elif stype == "hash_file":
            fp = step.get("file", "")
            if fp and os.path.exists(fp):
                with open(fp, "rb") as fh:
                    d = fh.read()
                lines.append(f"    [HASH] MD5    : {hashlib.md5(d).hexdigest()}")
                lines.append(f"    [HASH] SHA256 : {hashlib.sha256(d).hexdigest()}")
            else:
                lines.append(f"    [SKIP] File not found: {fp}")

        elif stype == "check_port":
            host = step.get("host", "localhost")
            port = int(step.get("port", 80))
            try:
                s = socket.socket()
                s.settimeout(1)
                status = "OPEN" if s.connect_ex((host, port)) == 0 else "CLOSED"
                s.close()
                lines.append(f"    [PORT] {host}:{port} → {status}")
            except Exception as e:
                lines.append(f"    [PORT] Error: {e}")

        elif stype == "alert":
            lvl = step.get("level", "INFO").upper()
            lines.append(f"    [ALERT/{lvl}] {step.get('message', '')}")

        elif stype == "quarantine":
            lines.append(f"    [QUARANTINE] Simulated isolation: {step.get('file', 'unknown')}")
            lines.append(f"    [QUARANTINE] Entry added to audit log")

        elif stype == "scan_ports":
            target = step.get("host", "127.0.0.1")
            lines.append(f"    [SCAN] Running port scan on {target}...")
            result = scan_ports(target, timeout=0.3)
            for l in result.split("\n")[:8]:
                lines.append(f"      {l}")

        elif stype == "generate_report":
            lines.append(f"    [REPORT] Report generated at {datetime.now().isoformat()}")

        else:
            lines.append(f"    [SKIP] Unknown step type: {stype}")

        lines.append(f"    [OK]")
        if log_cb:
            log_cb(f"Playbook step {i}/{len(steps)}: {sname} — done")

    lines += [
        "",
        f"  Playbook completed: {len(steps)} step(s)",
        f"  Finished : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    ]
    return "\n".join(lines)


# ════════════════════════════════════════════════════════════════════════════
#  MITRE ATT&CK SIMULATOR  (safe, educational, no real execution)
# ════════════════════════════════════════════════════════════════════════════

MITRE_TECHNIQUES = {
    "T1059.001": {
        "name": "PowerShell Execution",
        "tactic": "Execution",
        "description": "Adversaries abuse PowerShell to execute malicious scripts.",
        "indicators": ["powershell.exe spawned by Office app",
                       "Encoded -enc argument",
                       "DownloadString or IEX patterns"],
        "detection": "Monitor: powershell.exe process creation, Script Block Logging (Event 4104)",
        "mitigation": "Constrained Language Mode, PowerShell v5+ logging, AMSI",
        "demo": 'powershell.exe -NoP -NonI -Enc <base64_payload>',
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion / Privilege Escalation",
        "description": "Injecting code into legitimate processes to evade AV and gain privileges.",
        "indicators": ["VirtualAllocEx in unexpected process",
                       "CreateRemoteThread across process boundaries",
                       "WriteProcessMemory calls"],
        "detection": "Monitor: OpenProcess + VirtualAllocEx + CreateRemoteThread sequence",
        "mitigation": "EDR with memory scanning, Process Guard, Credential Guard",
        "demo": "OpenProcess(lsass.exe) → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread",
    },
    "T1083": {
        "name": "File & Directory Discovery",
        "tactic": "Discovery",
        "description": "Enumerating files, dirs, and drives to understand environment.",
        "indicators": ["Excessive dir/ls commands", "Access to C:\\Users\\*",
                       "Reading %APPDATA% paths"],
        "detection": "Monitor: file system access patterns, Event 4663 (Object Access)",
        "mitigation": "Least-privilege file permissions, honeypot files with alerts",
        "demo": "dir C:\\Users\\* /b /s | findstr /i password",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Exploiting vulnerabilities in internet-facing services.",
        "indicators": ["Unusual HTTP error spikes (500s)", "SQLi/XSS patterns in logs",
                       "Unexpected outbound connections from web server"],
        "detection": "WAF logs, IDS/IPS alerts, web server error rate anomalies",
        "mitigation": "Patch management, WAF, input validation, network segmentation",
        "demo": "GET /index.php?id=1' OR '1'='1  → SQL injection probe",
    },
    "T1486": {
        "name": "Data Encrypted for Impact (Ransomware)",
        "tactic": "Impact",
        "description": "Encrypting data to deny access and extort ransom payments.",
        "indicators": ["High-volume file renames (.locked, .encrypted)",
                       "Shadow copy deletion (vssadmin delete shadows)",
                       "Ransom note creation"],
        "detection": "Honeypot files, file activity monitoring, vssadmin deletion alert",
        "mitigation": "Offline backups (3-2-1 rule), immutable storage, EDR behavior detection",
        "demo": "vssadmin delete shadows /all /quiet  →  Encrypt files  →  DROP README.txt",
    },
    "T1566.001": {
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "Targeted phishing emails with malicious attachments (macros, exploits).",
        "indicators": ["Macro-enabled Office docs from external email",
                       "Office spawning powershell/cmd child process",
                       "Unusual attachment file types"],
        "detection": "Email gateway filtering, DMARC/DKIM/SPF, Office macro policies",
        "mitigation": "Phishing-resistant MFA, disable macros by default, security awareness",
        "demo": "Email with .docm → Enable Content → macro drops & executes payload",
    },
    "T1071": {
        "name": "Application Layer Protocol (C2)",
        "tactic": "Command & Control",
        "description": "Using standard protocols (HTTP/S, DNS) for C2 to blend with legit traffic.",
        "indicators": ["Beaconing at regular intervals", "DNS queries for DGA domains",
                       "Encrypted traffic to uncommon destinations"],
        "detection": "NetFlow analysis, DNS monitoring, JA3 TLS fingerprinting",
        "mitigation": "DNS filtering, egress firewall rules, network segmentation",
        "demo": "Beacon every 60s → POST /jquery-3.1.1.min.js → encoded C2 response",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Persistence / Defense Evasion",
        "description": "Using stolen or compromised credentials to maintain access.",
        "indicators": ["Login from unusual geo or time", "Service account interactive login",
                       "Multiple failed then successful auth"],
        "detection": "UEBA / behavioral analytics, impossible travel detection, Event 4624/4625",
        "mitigation": "MFA everywhere, privileged access workstations, credential tiering",
        "demo": "Stolen credentials used at 3AM from TOR exit node → successful login",
    },
}


def run_mitre_simulation(technique_id: str) -> str:
    """Return a detailed educational simulation for a MITRE ATT&CK technique."""
    tech = MITRE_TECHNIQUES.get(technique_id)
    if not tech:
        return f"Technique {technique_id} not in the demo library."

    lines = [
        f"┌─[ MITRE ATT&CK — {technique_id} ]─────────────────",
        f"│ SAFE EDUCATIONAL DEMO  •  NO REAL EXECUTION",
        f"└─────────────────────────────────────────────────",
        "",
        f"  Name   : {tech['name']}",
        f"  Tactic : {tech['tactic']}",
        "",
        "  [ Description ]",
        f"  {tech['description']}",
        "",
        "  [ Indicators of Compromise ]",
    ]
    for ioc in tech["indicators"]:
        lines.append(f"    • {ioc}")

    lines += [
        "",
        "  [ Simulated Attack Command (Educational Only) ]",
        f"    $ {tech['demo']}",
        "",
        "  [ Detection Guidance ]",
        f"    {tech['detection']}",
        "",
        "  [ Mitigation ]",
        f"    {tech['mitigation']}",
        "",
        f"  Simulation logged: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    ]
    return "\n".join(lines)


# ════════════════════════════════════════════════════════════════════════════
#  CVE FEED
# ════════════════════════════════════════════════════════════════════════════

def fetch_recent_cves(keyword: str = "", limit: int = 8) -> str:
    """Fetch recent CVEs from NVD API 2.0."""
    lines = [
        f"┌─[ CVE FEED ]────────────────────────────────────",
        f"│ Source : NVD API 2.0",
        f"│ Filter : {keyword or 'None'}",
        f"└─────────────────────────────────────────────────",
        "",
    ]
    params: dict = {"resultsPerPage": limit, "startIndex": 0}
    if keyword:
        params["keywordSearch"] = keyword

    try:
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params, timeout=10,
            headers={"User-Agent": "Decko-SecurityAssistant/3.0"}
        )
        if r.status_code != 200:
            lines.append(f"  [!] NVD API returned HTTP {r.status_code}")
            return "\n".join(lines)

        data = r.json()
        vulns = data.get("vulnerabilities", [])
        total = data.get("totalResults", 0)
        lines.append(f"  Total results: {total}  |  Showing: {len(vulns)}")
        lines.append("")

        for item in vulns:
            cve   = item.get("cve", {})
            cid   = cve.get("id", "N/A")
            descs = cve.get("descriptions", [])
            desc  = next((d["value"] for d in descs if d["lang"] == "en"), "No description")
            desc  = desc[:110] + "…" if len(desc) > 110 else desc
            pub   = cve.get("published", "")[:10]

            # CVSS
            metrics = cve.get("metrics", {})
            score, sev = "N/A", "UNKNOWN"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cv = metrics[key][0].get("cvssData", {})
                    score = cv.get("baseScore", "N/A")
                    sev   = cv.get("baseSeverity", "UNKNOWN")
                    break

            sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠",
                        "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
            lines.append(f"  {sev_icon} [{cid}]  Score: {score} ({sev})  Published: {pub}")
            lines.append(f"     {desc}")
            lines.append("")

    except requests.Timeout:
        lines.append("  [!] NVD API timeout — check internet connection")
    except Exception as e:
        lines.append(f"  [!] Feed error: {e}")

    return "\n".join(lines)


# ════════════════════════════════════════════════════════════════════════════
#  OLLAMA CLIENT
# ════════════════════════════════════════════════════════════════════════════

def check_ollama(host: str = "http://localhost:11434") -> tuple:
    """Returns (is_available: bool, models: list)."""
    try:
        r = requests.get(f"{host}/api/tags", timeout=2)
        models = [m["name"] for m in r.json().get("models", [])]
        return r.status_code == 200, models
    except Exception:
        return False, []


def ollama_chat(prompt: str, model: str = "llama3",
                host: str = "http://localhost:11434",
                system_prompt: str = "") -> str:
    """Send a message to local Ollama and return the reply."""
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})
    try:
        r = requests.post(
            f"{host}/api/chat",
            json={"model": model, "messages": messages, "stream": False},
            timeout=120,
        )
        if r.status_code == 200:
            return r.json().get("message", {}).get("content", "No response from Ollama")
        return f"Ollama error: HTTP {r.status_code}"
    except requests.ConnectionError:
        return ("Ollama is not running.\n"
                "Start it with:  ollama serve\n"
                "Then pull a model:  ollama pull llama3")
    except Exception as e:
        return f"Ollama error: {e}"


# ════════════════════════════════════════════════════════════════════════════
#  TTS / VOICE OUTPUT
# ════════════════════════════════════════════════════════════════════════════

_tts_lock   = threading.Lock()
_tts_engine = None


def _get_tts():
    global _tts_engine
    if _tts_engine is None and TTS_AVAILABLE:
        try:
            _tts_engine = pyttsx3.init()
            _tts_engine.setProperty("rate", 155)
            _tts_engine.setProperty("volume", 0.9)
        except Exception:
            pass
    return _tts_engine


def speak_async(text: str) -> bool:
    """Speak text in a daemon thread (non-blocking)."""
    if not TTS_AVAILABLE:
        return False

    def _run():
        with _tts_lock:
            engine = _get_tts()
            if not engine:
                return
            try:
                clean = re.sub(r"[*#\[\]<>→►•]", " ", text)[:400]
                engine.say(clean)
                engine.runAndWait()
            except Exception:
                pass

    threading.Thread(target=_run, daemon=True).start()
    return True


# ════════════════════════════════════════════════════════════════════════════
#  VOICE INPUT  (STT)
# ════════════════════════════════════════════════════════════════════════════

def listen_once(timeout: int = 5) -> str:
    """Listen for one utterance and return recognized text, or error string."""
    if not STT_AVAILABLE:
        return "ERROR: SpeechRecognition not installed (pip install SpeechRecognition pyaudio)"
    try:
        recognizer = sr.Recognizer()
        with sr.Microphone() as source:
            recognizer.adjust_for_ambient_noise(source, duration=0.5)
            audio = recognizer.listen(source, timeout=timeout, phrase_time_limit=15)
        return recognizer.recognize_google(audio)
    except sr.WaitTimeoutError:
        return "ERROR: No speech detected within timeout"
    except sr.UnknownValueError:
        return "ERROR: Speech not recognized"
    except sr.RequestError as e:
        return f"ERROR: Recognition service error: {e}"
    except Exception as e:
        return f"ERROR: {e}"
import socket

def network_scanner(ip_address: str) -> str:
    """
    Scans a given IP address for common open ports (e.g., 80, 443, 135, 445).
    Call this tool IMMEDIATELY whenever the user asks to scan an IP address or check open ports on a specific IP.
    """
    print(f"[SYSTEM] Gemini called network_scanner for IP: {ip_address}...") # عشان تتابع في التيرمنال
    
    open_ports = []
    # حطينا بورتات مشهورة كمثال سريع
    common_ports = [80, 443, 135, 445, 3306] 
    
    for port in common_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5) # وقت قليل عشان مينامش
            if s.connect_ex((ip_address, port)) == 0:
                open_ports.append(str(port))
                
    if open_ports:
        return f"Scan complete for {ip_address}. Open ports found: {', '.join(open_ports)}"
    return f"Scan complete for {ip_address}. No common open ports found."
