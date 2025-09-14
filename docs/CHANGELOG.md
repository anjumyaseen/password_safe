# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2025-09-13

- Encryption at rest (AES‑GCM) and plaintext → encrypted migration on unlock
- Multi‑vault tabs; drag‑and‑drop move entries
- Persist empty custom folders; protect default folders from deletion/rename
- Clipboard auto‑clear with countdown; Preferences for TTL and copy safety
- Idle auto‑lock (default 300s); Lock Now; menubar disabled while locked
- Export Encrypted (.vaultenc) with passphrase; guarded plaintext export (YES confirm)
- First‑run Terms modal; Help → Legal & Privacy dialog
- Readme: Terms, Privacy, Disclaimer; Verify Downloads instructions
- Tools: `tools/make_ico.py` to generate ICO from PNG
- Build: PyInstaller recipe documented (assets/app.ico + icon-safe.png)
- Tests: storage encryption + migration

