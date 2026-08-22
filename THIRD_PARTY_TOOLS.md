# Third-party tools in the Windows release

The `DeckoTools` directory in the Windows release contains or supports software maintained by independent projects. Decko does not claim authorship of those tools. Their original license files are kept inside their directories or archives.

| Tool | Bundled version/build | Official project |
|---|---|---|
| Gobuster | 3.8.2, Windows x86-64 | https://github.com/OJ/gobuster |
| John the Ripper | 1.9.0-jumbo-1, Windows x64 | https://www.openwall.com/john/ |
| Nikto | 2.6.0 source | https://github.com/sullo/nikto |
| Nmap | 7.95, Windows x64 files | https://nmap.org/ |
| Nuclei | 3.11.0, Windows amd64 | https://github.com/projectdiscovery/nuclei |
| SQLmap | bundled development snapshot | https://github.com/sqlmapproject/sqlmap |
| YARA | 4.5.8 source and Windows x64 CLI | https://github.com/VirusTotal/yara |

## Checksums of redistributed archives and added executables

```text
677abe8e56c5455804225ad2264dc6e9981e99673ef3ccd6a2fa2af8a2e92aba  gobuster_Windows_x86_64.zip
87173bd0dc1ccda2101e102e7a6e2f01e29010259b4ec3f84d65108bca94d663  nuclei_3.11.0_windows_amd64.zip
1c45eb279d820aba81fd41c22384428ebe44037cf5793be4b52a9d3b3df62b33  yara.exe
5b6705b9a8dabf496bccf163a65887574290c97f8b999c8cb73df5417b04bbd7  yarac64.exe
```

Users should review each upstream license before redistribution or commercial use. Security tools can trigger antivirus or endpoint-protection alerts; do not disable protection globally.
