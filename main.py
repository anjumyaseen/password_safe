import sys
import os
from PyQt5.QtWidgets import QApplication, QDialog, QMessageBox
from storage import VaultStorage
from login_dialog import LoginDialog
from main_window import MainWindow
from settings import load_settings, save_settings

def default_vault_path():
    base = os.path.join(os.path.expanduser("~"), ".simple_vault")
    return os.path.join(base, "vault.json")

def main():
    app = QApplication(sys.argv)
    # First-run terms acceptance
    settings = load_settings()
    if not settings.get("terms_accepted", False):
        text = (
            "<b>Password Safe is a local-only, offline password manager.</b><br><br>"
            "\u26A0\uFE0F Important:<br>"
            "- You are solely responsible for your master password and vault file.<br>"
            "- If you forget your master password, your data cannot be recovered.<br>"
            "- This software is provided \"as-is\" without warranties or guarantees.<br>"
            "- No personal data is collected or transmitted; all vault data stays on your device.<br><br>"
            "By clicking <b>I Understand</b>, you acknowledge and accept these terms."
        )
        box = QMessageBox()
        box.setWindowTitle("Password Safe – Terms")
        box.setIcon(QMessageBox.Warning)
        box.setTextFormat(Qt.RichText if 'Qt' in globals() else 1)
        box.setText(text)
        ok = box.addButton("I Understand", QMessageBox.AcceptRole)
        cancel = box.addButton("Exit", QMessageBox.RejectRole)
        box.exec_()
        if box.clickedButton() is not ok:
            sys.exit(0)
        settings["terms_accepted"] = True
        try:
            from datetime import datetime, timezone
            settings["terms_accepted_at"] = datetime.now(timezone.utc).isoformat()
        except Exception:
            settings["terms_accepted_at"] = None
        save_settings(settings)
    storage = VaultStorage(default_vault_path())
    login = LoginDialog(storage)
    if login.exec_() != QDialog.Accepted:
        sys.exit(0)
    win = MainWindow(storage)
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
