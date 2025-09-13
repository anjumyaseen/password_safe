import os
import sys
import json
import base64
import hashlib
from datetime import datetime, timezone
from PyQt5.QtWidgets import (
    QMainWindow, QAction, QFileDialog, QMessageBox, QApplication, QDialog, QInputDialog, QLineEdit, QCheckBox,
    QWidget, QFormLayout, QVBoxLayout, QPushButton, QHBoxLayout
)
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import QTimer
from PyQt5 import QtCore
from __init__ import __version__
from storage import VaultStorage
from login_dialog import LoginDialog
from dashboard import VaultDashboard
from settings import load_settings, save_settings

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    AESGCM = None

class MainWindow(QMainWindow):
    def __init__(self, storage: VaultStorage):
        super().__init__()
        self.storage = storage
        self.setWindowTitle("Password Safe")
        self.resize(1000, 620)
        # App/window icon
        try:
            self.setWindowIcon(QIcon("icon-safe.png"))
        except Exception:
            pass
        self.settings = load_settings()

        self._build_ui()
        self._build_menu()
        # Ensure a status bar exists for non-blocking notifications
        self.statusBar()
        try:
            self._refresh_title_and_status()
        except Exception:
            pass

    def _build_ui(self):
        self.dashboard = VaultDashboard(self.storage)
        try:
            self.dashboard.apply_settings(self.settings)
        except Exception:
            pass
        self.setCentralWidget(self.dashboard)
        try:
            self.dashboard.entries_changed.connect(self._refresh_title_and_status)
        except Exception:
            pass

    def _build_menu(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu("&File")

        # Export submenu
        export_menu = file_menu.addMenu("Export")
        export_enc_action = QAction("Export Encrypted...", self)
        export_enc_action.triggered.connect(self._export_encrypted)
        export_menu.addAction(export_enc_action)

        advanced_menu = export_menu.addMenu("Advanced")
        export_plain_action = QAction("Export Plaintext (Not Recommended)...", self)
        export_plain_action.triggered.connect(self._export_json)
        advanced_menu.addAction(export_plain_action)

        # Import
        import_enc_action = QAction("Import Encrypted...", self)
        import_enc_action.triggered.connect(self._import_encrypted)
        file_menu.addAction(import_enc_action)

        file_menu.addSeparator()
        change_master_action = QAction("Change Master Password...", self)
        change_master_action.triggered.connect(self._change_master_password)
        file_menu.addAction(change_master_action)

        quit_action = QAction("Quit", self)
        quit_action.setShortcut("Ctrl+Q")
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        edit_menu = menubar.addMenu("&Edit")
        prefs_action = QAction("Preferences...", self)
        prefs_action.triggered.connect(self._preferences)
        edit_menu.addAction(prefs_action)

        help_menu = menubar.addMenu("&Help")
        about_action = QAction("About", self)
        about_action.triggered.connect(self._about)
        help_menu.addAction(about_action)

    def _about(self):
        vault_path = getattr(self.storage, 'path', '(unknown)')
        base = os.path.basename(vault_path)
        master = getattr(self.storage, '_data', {}).get('master') if hasattr(self.storage, '_data') else None
        iterations = master.get('iterations', 200_000) if isinstance(master, dict) else 200_000
        try:
            import cryptography
            crypto_ver = cryptography.__version__
        except Exception:
            crypto_ver = 'n/a'
        pyqt_ver = getattr(QtCore, 'PYQT_VERSION_STR', 'n/a')
        html = f"""
        <h3>Password Safe <small>v{__version__}</small></h3>
        <p><b>Vault:</b> {base}<br><span style='color:#666'>{vault_path}</span></p>
        <p><b>Crypto:</b> AES-256-GCM<br>
        <b>KDF:</b> PBKDF2-HMAC-SHA256 ({iterations} iterations)</p>
        <p><b>Environment:</b> PyQt5 {pyqt_ver} | cryptography {crypto_ver}</p>
        <p><b>Tips:</b> Use <i>Export Encrypted…</i> for backups. Plaintext export is under <i>Export → Advanced</i> with safeguards.</p>
        <p><b>License:</b> MIT</p>
        """
        QMessageBox.about(self, "About", html)

    def _refresh_title_and_status(self):
        vault_path = getattr(self.storage, 'path', '')
        base = os.path.basename(vault_path) if vault_path else 'Vault'
        try:
            entries = len(self.storage.list_entries())
        except Exception:
            entries = 0
        self.setWindowTitle(f"Password Safe — {base} (Unlocked)")
        try:
            self.statusBar().showMessage(f"Vault: {base} | Entries: {entries}", 3000)
        except Exception:
            pass

    def _preferences(self):
        dlg = PreferencesDialog(getattr(self, 'settings', {}), self)
        if dlg.exec_() == QDialog.Accepted:
            self.settings = dlg.values()
            save_settings(self.settings)
            try:
                self.dashboard.apply_settings(self.settings)
            except Exception:
                pass

    def _export_json(self):
        # Strong warning and typed confirmation
        QMessageBox.critical(
            self,
            "Dangerous: Plaintext Export",
            "\u26a0\ufe0f This will create a file containing ALL your passwords in PLAIN TEXT.\n\n"
            "Anyone who gets this file can read all your secrets. Use only for migration or special cases.",
        )

        text, ok = QInputDialog.getText(
            self,
            "Confirm Plaintext Export",
            "Type YES to proceed:",
            QLineEdit.Normal,
        )
        if not ok or (text or "").strip().upper() != "YES":
            return

        path, _ = QFileDialog.getSaveFileName(self, "Export vault as JSON (PLAINTEXT)", "", "JSON Files (*.json)")
        if not path:
            return
        data = {
            "version": 1,
            "entries": self.storage.list_entries()
        }
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            # Optional safeguard: offer auto-delete after X minutes
            minutes = int(getattr(self, 'settings', {}).get("plaintext_export_autodelete_min", 10) or 10)
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Warning)
            box.setWindowTitle("Plaintext Export Created")
            box.setText(
                f"Plaintext file saved to:\n{path}\n\nConsider deleting it soon."
            )
            cb = QCheckBox(f"Auto-delete after {minutes} minutes")
            box.setCheckBox(cb)
            box.addButton("OK", QMessageBox.AcceptRole)
            box.exec_()
            if cb.isChecked():
                QTimer.singleShot(minutes * 60 * 1000, lambda: self._try_delete_file(path))
            QMessageBox.information(self, "Exported", "Vault exported successfully (PLAINTEXT).")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export: {e}")

    def _export_encrypted(self):
        if AESGCM is None:
            QMessageBox.critical(self, "Missing dependency", "'cryptography' package is required for encrypted export.")
            return

        # Ask for passphrase twice
        pw1, ok1 = QInputDialog.getText(self, "Export Encrypted", "Set passphrase:", QLineEdit.Password)
        if not ok1:
            return
        pw2, ok2 = QInputDialog.getText(self, "Export Encrypted", "Confirm passphrase:", QLineEdit.Password)
        if not ok2:
            return
        if not pw1 or pw1 != pw2:
            QMessageBox.warning(self, "Mismatch", "Passphrases do not match or are empty.")
            return
        if len(pw1) < 8:
            QMessageBox.warning(self, "Weak passphrase", "Use at least 8 characters.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Encrypted Vault",
            "",
            "Encrypted Vault (*.vaultenc);;All Files (*)",
        )
        if not path:
            return

        try:
            plaintext = {
                "version": 1,
                "exported_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "entries": self.storage.list_entries(),
            }
            pt = json.dumps(plaintext, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            salt = os.urandom(16)
            iterations = 200_000
            key = hashlib.pbkdf2_hmac("sha256", pw1.encode("utf-8"), salt, iterations)
            nonce = os.urandom(12)
            aad = b"password_safe:export:v1"
            aes = AESGCM(key)
            ct = aes.encrypt(nonce, pt, aad)

            doc = {
                "format": "password_safe_export",
                "version": 1,
                "kdf": {
                    "algo": "pbkdf2-sha256",
                    "iterations": iterations,
                    "salt": base64.b64encode(salt).decode("ascii"),
                },
                "cipher": "aes-256-gcm",
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "ciphertext": base64.b64encode(ct).decode("ascii"),
            }

            with open(path, "w", encoding="utf-8") as f:
                json.dump(doc, f, indent=2)
            QMessageBox.information(self, "Exported", "Encrypted vault exported successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export encrypted vault: {e}")

    def _try_delete_file(self, path):
        try:
            if os.path.exists(path):
                os.remove(path)
                # Notify via status bar if available
                try:
                    self.statusBar().showMessage("Plaintext export auto-deleted.", 3000)
                except Exception:
                    pass
        except Exception:
            # Best effort only; ignore failures
            pass

    def _import_encrypted(self):
        if AESGCM is None:
            QMessageBox.critical(self, "Missing dependency", "'cryptography' package is required for encrypted import.")
            return

        path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Encrypted Vault",
            "",
            "Encrypted Vault (*.vaultenc);;All Files (*)",
        )
        if not path:
            return

        try:
            with open(path, "r", encoding="utf-8") as f:
                doc = json.load(f)
            if not isinstance(doc, dict) or doc.get("cipher") != "aes-256-gcm":
                QMessageBox.critical(self, "Invalid file", "Selected file does not look like a valid encrypted export.")
                return

            # Ask for passphrase
            pw, ok = QInputDialog.getText(self, "Import Encrypted", "Enter passphrase:", QLineEdit.Password)
            if not ok:
                return
            salt = base64.b64decode(doc["kdf"]["salt"])
            iterations = int(doc["kdf"].get("iterations", 200_000))
            key = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, iterations)
            nonce = base64.b64decode(doc["nonce"])
            ct = base64.b64decode(doc["ciphertext"])
            aad = b"password_safe:export:v1"
            pt = AESGCM(key).decrypt(nonce, ct, aad)
            payload = json.loads(pt.decode("utf-8"))
            entries = payload.get("entries", [])

            if not entries:
                QMessageBox.information(self, "Nothing to import", "The encrypted export contains no entries.")
                return

            reply = QMessageBox.question(
                self,
                "Confirm Import",
                f"Import {len(entries)} entries into this vault? New IDs will be assigned.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if reply != QMessageBox.Yes:
                return

            imported = 0
            for e in entries:
                # Avoid id collisions; let storage assign a new ID and timestamps
                e = dict(e)
                e.pop("id", None)
                e.pop("created_at", None)
                e.pop("updated_at", None)
                self.storage.add_entry(e)
                imported += 1

            QMessageBox.information(self, "Imported", f"Imported {imported} entries.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to import encrypted vault: {e}")

    # --- Change master password ---
    def _change_master_password(self):
        dlg = ChangeMasterDialog(self)
        if dlg.exec_() != QDialog.Accepted:
            return
        old_pw, new_pw = dlg.values()
        try:
            ok = self.storage.change_master_password(old_pw, new_pw)
        except RuntimeError as ex:
            QMessageBox.critical(self, "Unavailable", str(ex))
            return
        if not ok:
            QMessageBox.critical(self, "Invalid password", "Current master password is incorrect.")
            return
        QMessageBox.information(self, "Success", "Master password changed and vault re-encrypted.")


class ChangeMasterDialog(QDialog):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Change Master Password")
        self.setModal(True)
        self.setMinimumWidth(360)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        form = QFormLayout()

        self.current = QLineEdit()
        self.current.setEchoMode(QLineEdit.Password)
        self.new = QLineEdit()
        self.new.setEchoMode(QLineEdit.Password)
        self.confirm = QLineEdit()
        self.confirm.setEchoMode(QLineEdit.Password)

        form.addRow("Current password:", self.current)
        form.addRow("New password:", self.new)
        form.addRow("Confirm new:", self.confirm)

        btns = QHBoxLayout()
        ok = QPushButton("Change")
        cancel = QPushButton("Cancel")
        ok.clicked.connect(self._on_accept)
        cancel.clicked.connect(self.reject)
        btns.addWidget(ok)
        btns.addWidget(cancel)
        btns.addStretch()

        layout.addLayout(form)
        layout.addLayout(btns)

    def _on_accept(self):
        cur = self.current.text()
        new = self.new.text()
        con = self.confirm.text()
        if not cur or not new or not con:
            QMessageBox.warning(self, "Required", "Please fill all fields.")
            return
        if new != con:
            QMessageBox.warning(self, "Mismatch", "New passwords do not match.")
            return
        if len(new) < 8:
            QMessageBox.warning(self, "Weak password", "Use at least 8 characters.")
            return
        self.accept()

    def values(self):
        return self.current.text(), self.new.text()


class PreferencesDialog(QDialog):
    def __init__(self, values: dict, parent=None):
        super().__init__(parent)
        self._values = dict(values or {})
        self.setWindowTitle("Preferences")
        self.setModal(True)
        self.setMinimumWidth(380)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        form = QFormLayout()

        from PyQt5.QtWidgets import QSpinBox
        self.clip_ttl = QSpinBox()
        self.clip_ttl.setRange(10, 120)
        self.clip_ttl.setSuffix(" s")
        self.clip_ttl.setValue(int(self._values.get("clipboard_ttl_sec", 30) or 30))

        self.require_show = QCheckBox("Require 'Show' before copying password")
        self.require_show.setChecked(bool(self._values.get("require_show_to_copy", False)))

        self.plain_autodel = QSpinBox()
        self.plain_autodel.setRange(1, 120)
        self.plain_autodel.setSuffix(" min")
        self.plain_autodel.setValue(int(self._values.get("plaintext_export_autodelete_min", 10) or 10))

        form.addRow("Clipboard auto-clear:", self.clip_ttl)
        form.addRow("Password copy safety:", self.require_show)
        form.addRow("Plaintext export auto-delete:", self.plain_autodel)

        btns = QHBoxLayout()
        ok = QPushButton("Save")
        cancel = QPushButton("Cancel")
        ok.clicked.connect(self._on_accept)
        cancel.clicked.connect(self.reject)
        btns.addWidget(ok)
        btns.addWidget(cancel)
        btns.addStretch()

        layout.addLayout(form)
        layout.addLayout(btns)

    def _on_accept(self):
        self._values["clipboard_ttl_sec"] = int(self.clip_ttl.value())
        self._values["require_show_to_copy"] = bool(self.require_show.isChecked())
        self._values["plaintext_export_autodelete_min"] = int(self.plain_autodel.value())
        self.accept()

    def values(self) -> dict:
        return dict(self._values)


def main():
    app = QApplication([])
    storage = VaultStorage(default_vault_path())
    login = LoginDialog(storage)
    if login.exec_() != QDialog.Accepted:
        sys.exit(0)
    win = MainWindow(storage)
    win.show()
    app.exec_()


if __name__ == "__main__":
    main()
