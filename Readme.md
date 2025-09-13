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
   python -m venv .venv
   source .venv/bin/activate   # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   python main.py
   ```

---

## 📦 Build `.exe` (Windows)

Using [PyInstaller](https://pyinstaller.org/):

```bash
pyinstaller --onefile --noconsole --name PasswordSafe --icon=assets/app.ico password_safe/main.py
```

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
