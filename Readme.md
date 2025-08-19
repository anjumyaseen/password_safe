---

# 📦 Password Safe (v1.0.0)

A simple **local password manager** built with **Python + PyQt5**.
It securely stores your credentials (usernames, emails, URLs, notes) in an encrypted vault file, with search, password generation, and folder organization.

---

## 📂 Project Structure

```
password-safe/
│
├── password_safe/              # Main application package
│   ├── __init__.py             # Version, package info
│   ├── main.py                 # Entry point
│   ├── dashboard.py            # Password vault dashboard (UI)
│   ├── main_window.py          # Main window wrapper
│   ├── login_dialog.py         # Login / unlock dialog
│   ├── storage.py              # Vault storage and encryption logic
│   └── __pycache__/            # Python cache files (ignored)
│
├── assets/                     # Icons, images (e.g., app.ico)
│   └── new-cir-logo.png
│
├── tests/                      # (optional) Unit tests
│
├── .gitignore                  # Git ignore rules
├── pyproject.toml              # Project metadata & dependencies
├── requirements.txt            # Python dependencies
├── README.md                   # Project documentation
├── CHANGELOG.md                 # Version history
└── LICENSE                      # License (MIT recommended)
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
* 📦 Encrypted JSON vault stored locally in `~/.simple_vault/vault.json`

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
   python -m password_safe
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

