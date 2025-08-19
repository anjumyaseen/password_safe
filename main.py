import sys
import os
from PyQt5.QtWidgets import QApplication, QDialog
from storage import VaultStorage
from login_dialog import LoginDialog
from main_window import MainWindow

def default_vault_path():
    base = os.path.join(os.path.expanduser("~"), ".simple_vault")
    return os.path.join(base, "vault.json")

def main():
    app = QApplication(sys.argv)
    storage = VaultStorage(default_vault_path())
    login = LoginDialog(storage)
    if login.exec_() != QDialog.Accepted:
        sys.exit(0)
    win = MainWindow(storage)
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
