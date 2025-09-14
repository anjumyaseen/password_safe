---

# 📦 Password Safe (v1.0.0)

A simple **local password manager** built with **Python + PyQt5**.
It securely stores your credentials (usernames, emails, URLs, notes) in an encrypted vault file, with search, password generation, and folder organization.

---

## 📂 Project Structure

```
password_safe/
│
├── main.py               # Entry point
├── main_window.py        # Main window wrapper
├── login_dialog.py       # Login / unlock dialog
├── dashboard.py          # Password vault dashboard (UI)
├── storage.py            # Vault storage and encryption logic (AES‑GCM at rest)
├── requirements.txt      # Python dependencies
├── tests/                # Unit tests
├── .gitignore            # Git ignore rules
└── Readme.md             # Project documentation
```

---

## 🚀 Features

* 🔑 Master password to unlock the vault
* 📂 Organize entries into folders (Personal, Work, Finance, Shopping, Other, custom)
* 🔍 Search entries in real time
* 🔒 Strong password generator with adjustable length
* 🧮 Password strength meter
* ✏️ Add / edit / delete / copy credentials
* 🌐 Open stored URLs directly in browser
* 📝 Notes & tags per entry
* 📦 Encryption at rest (AES‑GCM via `cryptography`), vault stored at `~/.simple_vault/vault.json`
* 🔁 Automatic migration of older plaintext vaults on first unlock
* 🗂️ Custom folders and nested subfolders (use paths like `Entertainment/Netflix`)
* ⬆️ Export Encrypted by default; plaintext export only under Advanced with strong warnings
* 🧷 Multi‑vault tabs: open multiple vaults side‑by‑side (New/Open/Close)
* 🔒 Idle auto‑lock and Lock Now menu for quick security

---

## 🛠️ Installation (Development)

1. Clone this repo:

   ```bash
   git clone https://github.com/yourname/password-safe.git
   cd password-safe
   ```

2. Create a virtual environment:

   ```bash
   python -m venv .venv
   .venv\Scripts\activate   # Windows
   source .venv/bin/activate # Linux/Mac
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Run app:

   ```bash
   python main.py
   ```

---

## 📦 Build `.exe` (Windows)

Using [PyInstaller](https://pyinstaller.org/):

```bash
# 1) Generate the .ico (Windows requires ICO for the EXE)
pip install pillow
python tools/make_ico.py  # creates icon-safe.ico next to icon-safe.png

# 2) Place final icon
mkdir -p assets
copy icon-safe.ico assets\app.ico   # Windows

# 3) Build the EXE (option A: CLI)
pyinstaller --onefile --windowed --name PasswordSafe --icon=assets/app.ico --add-data "icon-safe.png;." main.py

#    Build the EXE (option B: spec file)
#    The spec keeps flags consistent across builds.
pyinstaller --onefile PasswordSafe.spec
```

- Window/taskbar icon at runtime uses the app icon set in code (`icon-safe.png`).
- Pinned/EXE icon uses the `.ico` embedded via the `--icon` flag above.
- Remove older icons (e.g., `new-cir-logo.ico`) to avoid confusion; use `icon-safe.png`/`assets/app.ico` consistently.

* Output binary: `dist/PasswordSafe.exe`
* Ship this `.exe` to end users.
* (Optional) wrap into an installer with [Inno Setup](https://jrsoftware.org/isinfo.php).

---

## 🧑‍💻 Contributing

* Fork and create a feature branch (`git checkout -b feat-xyz`).
* Submit PRs with clear descriptions.
* Follow semantic versioning (`1.0.1` for fixes, `1.1.0` for features).

---

## 📜 License

MIT License – feel free to use and modify.

---

## 🔒 Security Notes

- Encryption: Entries are encrypted at rest using AES‑GCM with a key derived from your master password (PBKDF2‑HMAC‑SHA256).
- Migration: If a legacy plaintext vault is detected, it is encrypted automatically after the first successful unlock.
- Export: The Export to JSON feature writes unencrypted data for portability. Treat exported files as sensitive and remove them when no longer needed.
  - Recommended: Use "Export Encrypted…" (default) for sharing or backup. A passphrase is required and an encrypted `.vaultenc` file is created.
  - Plaintext export is located under File → Export → Advanced and requires typing `YES`. Optionally auto-deletes after 10 minutes (best effort).

---

## ✅ Verify Downloads

Until code-signing is available, verify your binaries after download.

- Windows PowerShell:

  ```powershell
  Get-FileHash .\dist\PasswordSafe.exe -Algorithm SHA256
  ```

- macOS/Linux:

  ```bash
  shasum -a 256 dist/PasswordSafe.exe   # or: sha256sum dist/PasswordSafe.exe
  ```

Compare the output to the SHA256 published on the GitHub Release page.
Optionally, check the VirusTotal scan link provided in the release notes.

---

## Project Governance

- License: MIT (see `LICENSE`)
- Security policy: see `SECURITY.md`
- Contributing guidelines: see `CONTRIBUTING.md`
- Code of Conduct: see `CODE_OF_CONDUCT.md`

---

## ⚙️ Preferences

Open via Edit → Preferences…

- Clipboard auto-clear: Number of seconds before the clipboard is cleared after a Copy (default 30s). A live countdown appears in the main window status bar at the bottom (e.g., “Password copied. Clears in 29s”). The app clears the clipboard only if it still contains the same copied value, so it won’t erase newer clipboard content.
- Require “Show” before copying password: Optional UX guardrail. When enabled, the password must be visible (Show checked) before it can be copied. This reduces accidental copies but can increase shoulder‑surfing risk; leave off unless you value the extra step. Default: off.
- Plaintext export auto-delete (seconds): Best‑effort timer to delete a plaintext export created via Advanced → Export Plaintext. Works only while the app remains open and is not a secure wipe (no disk overwrite).
- Auto‑lock: Option to enable idle auto‑lock and choose the timeout (seconds). When locked, use Help → Unlock Current Vault… (or simply perform an action) to re‑enter your master password and unlock.
  - Default: 5 minutes (300 s). Change under Edit → Preferences…

---

## ⬆️ Export / ⬇️ Import

- Export Encrypted…: File → Export → Export Encrypted… (recommended). Prompts for a passphrase, produces a `.vaultenc` file using AES‑GCM with PBKDF2‑SHA256 (200k iterations).
- Import Encrypted…: File → Import Encrypted… Select a `.vaultenc`, enter the passphrase, and the entries are imported with new IDs.
- Export Plaintext (Not Recommended): File → Export → Advanced → Export Plaintext… Requires typing `YES` in a confirmation dialog. Optionally schedule auto‑delete (see Preferences). Treat the resulting `.json` as highly sensitive.

---

## 🗂️ Multi‑Vault Tabs

- File → New Vault…: choose a filename (e.g., `personal.psf`), set a master password, opens as a new tab.
- File → Open Vault…: pick an existing vault and unlock; opens as a new tab. Duplicate opens activate the existing tab.
- Tabs are closable and rearrangeable (drag to move left/right). Title shows the active vault name.

---

## 🔒 Locking

- Lock Now: File → Lock Now (Ctrl+L) immediately locks the app (for all tabs).
- Auto‑lock: enabled by default at 5 minutes (300 s); change or disable in Preferences (in seconds). Any user activity resets the timer.
- Unlock: Help → Unlock Current Vault… prompts for the master password and re‑enables the active tab.

---

## 📄 Terms of Use

This software (“Password Safe”) is provided free of charge for personal use. By using it, you agree to the following:

- You are solely responsible for safeguarding your master password and vault file(s).
- The developers are not liable for any data loss, unauthorized access, or damages arising from your use of the software.
- You may use and distribute the software under the terms of the MIT License (see LICENSE file).
- These terms may be updated in future versions. Continued use indicates acceptance of any updates.

---

## 🔒 Privacy Statement

- This application is fully local-first: it does not collect, transmit, or store your personal data.
- All vault data remains encrypted and stored on your device, under your control.
- No telemetry, analytics, or remote logging is built into the software.
- If you choose to use external storage (e.g., backups to cloud drives), that usage is entirely under your control and outside the scope of this app.

---

## ⚠️ Disclaimer

- This software is provided “as-is”, without warranty of any kind, express or implied.
- While modern encryption methods are used, no system is 100% secure.
- The developers disclaim any responsibility for security incidents, data breaches, or damages that may occur from use or misuse of this software.
- Always use strong master passwords, maintain offline backups, and practice good security hygiene.
