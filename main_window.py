import os
import sys
import json
import base64
import hashlib
from datetime import datetime, timezone
from PyQt5.QtWidgets import (
    QMainWindow, QAction, QFileDialog, QMessageBox, QApplication, QDialog, QInputDialog, QLineEdit, QCheckBox,
    QWidget, QFormLayout, QVBoxLayout, QPushButton, QHBoxLayout, QTabWidget
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

class LockedView(QWidget):
    def __init__(self, storage: VaultStorage, on_unlock, title: str = "Vault Locked"):
        super().__init__()
        self.storage = storage
        self.on_unlock = on_unlock
        self.original = None  # set by caller
        lay = QVBoxLayout(self)
        lay.setContentsMargins(40, 40, 40, 40)
        lbl = QLabel(f"<h2>{title}</h2><p>This vault is locked. Click Unlock to continue.</p>")
        btn = QPushButton("Unlock…")
        btn.clicked.connect(lambda: self.on_unlock())
        lay.addWidget(lbl)
        lay.addStretch(1)
        lay.addWidget(btn, alignment=QtCore.Qt.AlignLeft)
        lay.addStretch(3)

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
        self.locked = False
        self._last_activity_ms = 0
        self._idle_timer = QTimer(self)
        self._idle_timer.setInterval(10_000)
        self._idle_timer.timeout.connect(self._check_idle_lock)

        self._build_ui()
        self._build_menu()
        # Ensure a status bar exists for non-blocking notifications
        self.statusBar()
        try:
            self._refresh_title_and_status()
        except Exception:
            pass
        # Idle lock handling
        self._reset_activity_timer()
        self._idle_timer.start()
        self.installEventFilter(self)

    def _build_ui(self):
        # Tabbed multi-vault container
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.tabCloseRequested.connect(self._close_tab_index)
        self.tabs.currentChanged.connect(lambda _: self._refresh_title_and_status())
        self.setCentralWidget(self.tabs)

        # Initial tab with provided storage
        self._add_tab_for_storage(self.storage)

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

        # New/Open/Close vault tabs
        new_vault_action = QAction("New Vault...", self)
        new_vault_action.setShortcut("Ctrl+N")
        new_vault_action.triggered.connect(self._new_vault)
        file_menu.addAction(new_vault_action)

        open_vault_action = QAction("Open Vault...", self)
        open_vault_action.setShortcut("Ctrl+O")
        open_vault_action.triggered.connect(self._open_vault)
        file_menu.addAction(open_vault_action)

        close_tab_action = QAction("Close Vault", self)
        close_tab_action.setShortcut("Ctrl+W")
        close_tab_action.triggered.connect(lambda: self._close_tab_index(self.tabs.currentIndex()))
        file_menu.addAction(close_tab_action)

        file_menu.addSeparator()
        lock_action = QAction("Lock Now", self)
        lock_action.setShortcut("Ctrl+L")
        lock_action.triggered.connect(self._lock_all)
        file_menu.addAction(lock_action)

        unlock_action_file = QAction("Unlock Current Vault...", self)
        unlock_action_file.setShortcut("Ctrl+U")
        unlock_action_file.triggered.connect(self._unlock_current)
        file_menu.addAction(unlock_action_file)

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

        view_menu = menubar.addMenu("&View")
        expand_action = QAction("Expand All Folders", self)
        expand_action.setShortcut("Ctrl+Shift+E")
        expand_action.triggered.connect(lambda: self._current_dashboard() and self._current_dashboard().expand_all())
        view_menu.addAction(expand_action)

        collapse_action = QAction("Collapse All Folders", self)
        collapse_action.setShortcut("Ctrl+Shift+C")
        collapse_action.triggered.connect(lambda: self._current_dashboard() and self._current_dashboard().collapse_all())
        view_menu.addAction(collapse_action)

        focus_search_action = QAction("Focus Search", self)
        focus_search_action.setShortcut("Ctrl+F")
        focus_search_action.triggered.connect(lambda: self._current_dashboard() and self._current_dashboard().focus_search())
        view_menu.addAction(focus_search_action)

        help_menu = menubar.addMenu("&Help")
        about_action = QAction("About", self)
        about_action.triggered.connect(self._about)
        help_menu.addAction(about_action)
        faq_action = QAction("FAQ", self)
        faq_action.triggered.connect(self._faq)
        help_menu.addAction(faq_action)
        unlock_action = QAction("Unlock Current Vault...", self)
        unlock_action.setShortcut("Ctrl+U")
        unlock_action.triggered.connect(self._unlock_current)
        help_menu.addAction(unlock_action)

    def _about(self):
        cs = self._current_storage() or self.storage
        vault_path = getattr(cs, 'path', '(unknown)')
        base = os.path.basename(vault_path)
        master = getattr(cs, '_data', {}).get('master') if hasattr(cs, '_data') else None
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

    def _faq(self):
        cs = self._current_storage() or self.storage
        vault_path = getattr(cs, 'path', '(unknown)')
        html = f"""
        <h3>Frequently Asked Questions</h3>
        <p><b>Where is my vault stored?</b><br>
        {vault_path}</p>
        <p><b>Is the vault encrypted?</b><br>
        Yes. Entries are encrypted at rest with AES‑GCM. The key is derived from your master password using PBKDF2‑SHA256 (200k iterations).</p>
        <p><b>How do I back up or move my data?</b><br>
        Use <i>File → Export → Export Encrypted…</i> to create a passphrase‑protected export. Restore via <i>File → Import Encrypted…</i>.</p>
        <p><b>Can I export plaintext?</b><br>
        It’s under <i>Export → Advanced</i> with strong warnings and an optional auto‑delete timer. Use only for migration.</p>
        <p><b>Clipboard auto‑clear?</b><br>
        Copies clear automatically after the configured TTL (Edit → Preferences). A countdown appears in the status bar.</p>
        <p><b>Change master password?</b><br>
        Use <i>File → Change Master Password…</i>. The vault is re‑encrypted with the new key.</p>
        """
        QMessageBox.about(self, "FAQ", html)

    def _refresh_title_and_status(self):
        cs = self._current_storage() or self.storage
        vault_path = getattr(cs, 'path', '')
        base = os.path.basename(vault_path) if vault_path else 'Vault'
        try:
            entries = len(cs.list_entries())
        except Exception:
            entries = 0
        state = "Locked" if self.locked else "Unlocked"
        self.setWindowTitle(f"Password Safe — {base} ({state})")
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
                for i in range(self.tabs.count()):
                    w = self.tabs.widget(i)
                    if hasattr(w, 'apply_settings'):
                        w.apply_settings(self.settings)
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
        cs = self._current_storage() or self.storage
        data = {"version": 1, "entries": cs.list_entries() if cs else []}
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
            cs = self._current_storage() or self.storage
            plaintext = {
                "version": 1,
                "exported_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "entries": cs.list_entries() if cs else [],
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

    # --- Lock/Unlock & Idle handling ---
    def eventFilter(self, obj, event):
        et = getattr(event, 'type', lambda: None)()
        if et in (2, 5, 6, 50, 51):  # mouse/keyboard events
            self._reset_activity_timer()
        return super().eventFilter(obj, event)

    def _reset_activity_timer(self):
        try:
            self._last_activity_ms = int(QtCore.QDateTime.currentMSecsSinceEpoch())
        except Exception:
            self._last_activity_ms = 0

    def _check_idle_lock(self):
        try:
            if not self.settings.get('auto_lock_enabled', True):
                return
            minutes = int(self.settings.get('auto_lock_minutes', 5) or 5)
            if minutes <= 0:
                return
            now_ms = int(QtCore.QDateTime.currentMSecsSinceEpoch())
            if self._last_activity_ms and (now_ms - self._last_activity_ms) >= minutes * 60 * 1000:
                self._lock_all()
        except Exception:
            pass

    def _lock_all(self):
        if self.locked:
            return
        self.locked = True
        # Replace each dashboard with a LockedView placeholder
        for i in range(self.tabs.count() - 1, -1, -1):
            w = self.tabs.widget(i)
            st = getattr(w, 'storage', None)
            if st is None or isinstance(w, LockedView):
                continue
            try:
                st.lock()
                locked = LockedView(st, on_unlock=lambda idx=i: self._unlock_tab(idx))
                locked.original = w
                label = self.tabs.tabText(i)
                tip = self.tabs.tabToolTip(i)
                self.tabs.removeTab(i)
                self.tabs.insertTab(i, locked, label)
                self.tabs.setTabToolTip(i, tip)
            except Exception:
                pass
        self._refresh_title_and_status()

    def _unlock_current(self):
        idx = self.tabs.currentIndex()
        self._unlock_tab(idx)

    def _unlock_tab(self, index: int):
        if index < 0 or index >= self.tabs.count():
            return
        w = self.tabs.widget(index)
        if not isinstance(w, LockedView):
            return
        st = getattr(w, 'storage', None)
        if not st:
            return
        dlg = LoginDialog(st)
        if dlg.exec_() != QDialog.Accepted:
            return
        try:
            original = w.original
            label = self.tabs.tabText(index)
            tip = self.tabs.tabToolTip(index)
            self.tabs.removeTab(index)
            self.tabs.insertTab(index, original, label)
            self.tabs.setTabToolTip(index, tip)
            self.tabs.setCurrentIndex(index)
        except Exception:
            pass
        # Clear locked flag if no LockedView remains
        self.locked = any(isinstance(self.tabs.widget(i), LockedView) for i in range(self.tabs.count()))
        self._refresh_title_and_status()

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
                cs = self._current_storage() or self.storage
                if cs is None:
                    break
                cs.add_entry(e)
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
            cs = self._current_storage() or self.storage
            ok = cs.change_master_password(old_pw, new_pw)
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

        self.auto_lock_enable = QCheckBox("Enable auto-lock when idle")
        self.auto_lock_enable.setChecked(bool(self._values.get("auto_lock_enabled", True)))
        self.auto_lock_min = QSpinBox()
        self.auto_lock_min.setRange(1, 120)
        self.auto_lock_min.setSuffix(" min")
        self.auto_lock_min.setValue(int(self._values.get("auto_lock_minutes", 5) or 5))

        form.addRow("Clipboard auto-clear:", self.clip_ttl)
        form.addRow("Password copy safety:", self.require_show)
        form.addRow("Plaintext export auto-delete:", self.plain_autodel)
        form.addRow("Auto-lock:", self.auto_lock_enable)
        form.addRow("Lock after:", self.auto_lock_min)

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
        self._values["auto_lock_enabled"] = bool(self.auto_lock_enable.isChecked())
        self._values["auto_lock_minutes"] = int(self.auto_lock_min.value())
        self.accept()

    def values(self) -> dict:
        return dict(self._values)

    # --- Tabs / multi-vault helpers ---
    
    
def _norm(path: str) -> str:
    try:
        return os.path.abspath(path)
    except Exception:
        return path or ""


def _base_dir() -> str:
    return os.path.join(os.path.expanduser("~"), ".simple_vault")


def _basename(path: str) -> str:
    try:
        return os.path.basename(path)
    except Exception:
        return path


def _ensure_dir(path: str):
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)


# Attach helper methods to MainWindow via dynamic definition below
def _mw_add_tab_for_storage(self, storage: VaultStorage):
    dash = VaultDashboard(storage)
    try:
        dash.apply_settings(self.settings)
    except Exception:
        pass
    try:
        dash.entries_changed.connect(self._refresh_title_and_status)
    except Exception:
        pass
    label = _basename(getattr(storage, 'path', 'Vault')) or 'Vault'
    idx = self.tabs.addTab(dash, label)
    self.tabs.setTabToolTip(idx, getattr(storage, 'path', label))
    self.tabs.setCurrentIndex(idx)
    self._refresh_title_and_status()


def _mw_find_tab_by_path(self, path: str) -> int:
    target = _norm(path)
    for i in range(self.tabs.count()):
        w = self.tabs.widget(i)
        spath = getattr(getattr(w, 'storage', None), 'path', None)
        if spath and _norm(spath) == target:
            return i
    return -1


def _mw_current_dashboard(self):
    return self.tabs.currentWidget() if hasattr(self, 'tabs') else None


def _mw_current_storage(self):
    w = _mw_current_dashboard(self)
    return getattr(w, 'storage', None) if w else None


def _mw_close_tab_index(self, index: int):
    if index < 0 or index >= self.tabs.count():
        return
    self.tabs.removeTab(index)
    self._refresh_title_and_status()


def _mw_new_vault(self):
    base = _base_dir()
    os.makedirs(base, exist_ok=True)
    path, _ = QFileDialog.getSaveFileName(
        self,
        "Create New Vault",
        os.path.join(base, "new_vault.psf"),
        "Vault Files (*.psf);;All Files (*)",
    )
    if not path:
        return
    if _mw_find_tab_by_path(self, path) >= 0:
        self.tabs.setCurrentIndex(_mw_find_tab_by_path(self, path))
        return
    _ensure_dir(path)
    storage = VaultStorage(path)
    dlg = LoginDialog(storage)
    if dlg.exec_() != QDialog.Accepted:
        return
    _mw_add_tab_for_storage(self, storage)


def _mw_open_vault(self):
    base = _base_dir()
    os.makedirs(base, exist_ok=True)
    path, _ = QFileDialog.getOpenFileName(
        self,
        "Open Vault",
        base,
        "Vault Files (*.psf *.json);;All Files (*)",
    )
    if not path:
        return
    existing = _mw_find_tab_by_path(self, path)
    if existing >= 0:
        self.tabs.setCurrentIndex(existing)
        return
    storage = VaultStorage(path)
    dlg = LoginDialog(storage)
    if dlg.exec_() != QDialog.Accepted:
        return
    _mw_add_tab_for_storage(self, storage)


# Bind helpers to MainWindow
MainWindow._add_tab_for_storage = _mw_add_tab_for_storage
MainWindow._find_tab_by_path = _mw_find_tab_by_path
MainWindow._current_dashboard = _mw_current_dashboard
MainWindow._current_storage = _mw_current_storage
MainWindow._close_tab_index = _mw_close_tab_index
MainWindow._new_vault = _mw_new_vault
MainWindow._open_vault = _mw_open_vault


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
