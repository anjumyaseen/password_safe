import os
import sys
import json
from PyQt5.QtWidgets import (
    QMainWindow, QAction, QFileDialog, QMessageBox, QApplication, QDialog
)
from PyQt5.QtGui import QIcon
from storage import VaultStorage
from login_dialog import LoginDialog
from dashboard import VaultDashboard

class MainWindow(QMainWindow):
    def __init__(self, storage: VaultStorage):
        super().__init__()
        self.storage = storage
        self.setWindowTitle("Vault")
        self.resize(1000, 620)

        self._build_ui()
        self._build_menu()

    def _build_ui(self):
        self.dashboard = VaultDashboard(self.storage)
        self.setCentralWidget(self.dashboard)

    def _build_menu(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu("&File")

        export_action = QAction("Export to JSON...", self)
        export_action.triggered.connect(self._export_json)
        file_menu.addAction(export_action)

        quit_action = QAction("Quit", self)
        quit_action.setShortcut("Ctrl+Q")
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        help_menu = menubar.addMenu("&Help")
        about_action = QAction("About", self)
        about_action.triggered.connect(self._about)
        help_menu.addAction(about_action)

    def _export_json(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export vault as JSON", "", "JSON Files (*.json)")
        if not path:
            return
        data = {
            "version": 1,
            "entries": self.storage.list_entries()
        }
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            QMessageBox.information(self, "Exported", "Vault exported successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export: {e}")

    def _about(self):
        QMessageBox.information(self, "About", "Simple Vault\n\n- Master password for unlocking\n- Add/Edit/Delete entries\n- Password generator & strength meter\n- Clipboard copy buttons\n- JSON persistence")


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