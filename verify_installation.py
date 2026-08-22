"""Preflight checks for a Decko installation.

This script does not run scans. It verifies the Python environment and locates
the optional external tools shipped in the Windows release package.
"""

from __future__ import annotations

import importlib.util
import argparse
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent
TOOLS_DIR = PROJECT_DIR / "DeckoTools"

REQUIRED_MODULES = {
    "PyQt6": "PyQt6",
    "dotenv": "python-dotenv",
    "google.genai": "google-genai",
    "psutil": "psutil",
    "requests": "requests",
    "yaml": "PyYAML",
}

OPTIONAL_MODULES = {
    "sklearn": "scikit-learn",
    "numpy": "numpy",
    "pyttsx3": "pyttsx3",
    "speech_recognition": "SpeechRecognition",
    "yara": "yara-python",
}

TOOL_NAMES = {
    "Nmap": ("nmap.exe", "nmap"),
    "SQLmap": ("sqlmap.py",),
    "John the Ripper": ("john.exe", "john"),
    "Nikto": ("nikto.pl",),
    "Gobuster": ("gobuster.exe", "gobuster"),
    "YARA CLI": ("yara64.exe", "yara.exe", "yara"),
    "Nuclei": ("nuclei.exe", "nuclei"),
}

TOOL_ARCHIVES = {
    "Nuclei": "nuclei_3.11.0_windows_amd64.zip",
    "Gobuster": "gobuster_Windows_x86_64.zip",
}


def module_exists(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ModuleNotFoundError, AttributeError):
        return False


def locate(names: tuple[str, ...]) -> str | None:
    for name in names:
        system_path = shutil.which(name)
        if system_path:
            return system_path
        if TOOLS_DIR.exists():
            match = next((p for p in TOOLS_DIR.rglob(name) if p.is_file()), None)
            if match:
                return str(match)
    return None


def extract_archive(label: str) -> bool:
    """Safely extract a known bundled tool archive."""
    archive_name = TOOL_ARCHIVES.get(label)
    if not archive_name:
        return False
    archive = TOOLS_DIR / archive_name
    destination = (TOOLS_DIR / archive.stem).resolve()
    if not archive.is_file():
        return False
    try:
        with zipfile.ZipFile(archive) as bundle:
            for member in bundle.infolist():
                member_path = (destination / member.filename).resolve()
                if destination not in member_path.parents and member_path != destination:
                    raise ValueError(f"Unsafe path in {archive.name}: {member.filename}")
            bundle.extractall(destination)
        return True
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"  ERROR    {label} archive could not be extracted: {exc}")
        return False


def version_command(label: str, path: str) -> list[str] | None:
    """Return a harmless version command for an external tool."""
    commands = {
        "Nmap": [path, "--version"],
        "SQLmap": [sys.executable, path, "--version"],
        "John the Ripper": [path, "--list=build-info"],
        "Gobuster": [path, "version"],
        "YARA CLI": [path, "--version"],
        "Nuclei": [path, "-version"],
    }
    if label == "Nikto":
        perl = shutil.which("perl")
        return [perl, path, "-Version"] if perl else None
    return commands.get(label)


def test_tool(label: str, path: str) -> tuple[bool, str]:
    command = version_command(label, path)
    if not command:
        return False, "required runtime is missing"
    if os.name != "nt" and path.lower().endswith(".exe"):
        return True, "Windows executable detected; execution test skipped on this OS"
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        output = (result.stdout or result.stderr or "").strip().splitlines()
        detail = output[0][:160] if output else f"exit code {result.returncode}"
        return result.returncode == 0, detail
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a Decko installation")
    parser.add_argument("--test-tools", action="store_true", help="extract bundled archives and run harmless version checks")
    parser.add_argument("--strict-tools", action="store_true", help="return a failure code when an optional external tool test fails")
    args = parser.parse_args()

    print("Decko installation check")
    print(f"Python: {sys.version.split()[0]}")
    print(f"Project: {PROJECT_DIR}")

    missing_required = []
    print("\nRequired Python packages:")
    for module, package in REQUIRED_MODULES.items():
        ok = module_exists(module)
        print(f"  {'OK' if ok else 'MISSING':7} {package}")
        if not ok:
            missing_required.append(package)

    print("\nOptional Python packages:")
    for module, package in OPTIONAL_MODULES.items():
        print(f"  {'OK' if module_exists(module) else 'OPTIONAL':8} {package}")

    print("\nExternal tools:")
    detected_tools: dict[str, str] = {}
    for label, names in TOOL_NAMES.items():
        path = locate(names)
        archive = TOOLS_DIR / TOOL_ARCHIVES.get(label, "") if label in TOOL_ARCHIVES else None
        if not path and args.test_tools and archive and archive.is_file() and extract_archive(label):
            path = locate(names)
        if path:
            detected_tools[label] = path
            print(f"  {'FOUND':8} {label} -> {path}")
        elif archive and archive.is_file():
            print(f"  {'ARCHIVED':8} {label} -> extracts automatically on first use")
        else:
            print(f"  {'OPTIONAL':8} {label}")

    perl = shutil.which("perl")
    print(f"\nNikto runtime: {'Perl found at ' + perl if perl else 'Perl not found (Nikto will be unavailable)'}")

    tool_failures = []
    if args.test_tools:
        print("\nHarmless external-tool version checks:")
        for label, path in detected_tools.items():
            ok, detail = test_tool(label, path)
            print(f"  {'PASS' if ok else 'WARNING':8} {label} -> {detail}")
            if not ok:
                tool_failures.append(label)

    if missing_required:
        print("\nInstall missing requirements with:")
        print(f'  "{sys.executable}" -m pip install -r requirements.txt')
        return 1

    if args.strict_tools and tool_failures:
        print("\nStrict tool verification failed: " + ", ".join(tool_failures))
        return 2

    print("\nPASS: Decko's required Python environment is ready.")
    print("Optional tools may still require Windows, administrator rights, Npcap, templates, or Internet access.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
