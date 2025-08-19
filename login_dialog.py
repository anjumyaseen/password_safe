from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QLineEdit, 
    QPushButton, QCheckBox, QFormLayout, QMessageBox
)

class LoginDialog(QDialog):
    def __init__(self, storage, parent=None):
        super().__init__(parent)
        self.storage = storage
        self.setWindowTitle("Unlock Vault")
        self.setModal(True)
        self.setMinimumWidth(360)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout()

        if self.storage.is_initialized():
            title = QLabel("<b>Enter master password</b>")
            self.password = QLineEdit()
            self.password.setEchoMode(QLineEdit.Password)
            show = QCheckBox("Show password")
            show.toggled.connect(lambda c: self.password.setEchoMode(QLineEdit.Normal if c else QLineEdit.Password))
            btn = QPushButton("Unlock")
            btn.clicked.connect(self._unlock)
            layout.addWidget(title)
            layout.addWidget(self.password)
            layout.addWidget(show)
            layout.addWidget(btn)
        else:
            title = QLabel("<b>Set a master password</b>")
            desc = QLabel("This protects your vault. You'll need it to unlock later.")
            self.password = QLineEdit()
            self.password.setEchoMode(QLineEdit.Password)
            self.confirm = QLineEdit()
            self.confirm.setEchoMode(QLineEdit.Password)
            show = QCheckBox("Show passwords")
            show.toggled.connect(lambda c: [
                self.password.setEchoMode(QLineEdit.Normal if c else QLineEdit.Password),
                self.confirm.setEchoMode(QLineEdit.Normal if c else QLineEdit.Password)
            ])
            btn = QPushButton("Create Vault")
            btn.clicked.connect(self._create)
            form = QFormLayout()
            form.addRow("Master password:", self.password)
            form.addRow("Confirm password:", self.confirm)
            layout.addWidget(title)
            layout.addWidget(desc)
            layout.addLayout(form)
            layout.addWidget(show)
            layout.addWidget(btn)

        self.setLayout(layout)

    def _unlock(self):
        pw = self.password.text()
        if not pw:
            QMessageBox.warning(self, "Required", "Please enter the master password.")
            return
        if self.storage.verify_master_password(pw):
            self.accept()
        else:
            QMessageBox.critical(self, "Invalid", "Incorrect master password.")

    def _create(self):
        pw = self.password.text()
        cf = self.confirm.text()
        if not pw or not cf:
            QMessageBox.warning(self, "Required", "Please fill both password fields.")
            return
        if pw != cf:
            QMessageBox.warning(self, "Mismatch", "Passwords do not match.")
            return
        if len(pw) < 8:
            QMessageBox.warning(self, "Weak password", "Use at least 8 characters.")
            return
        self.storage.set_master_password(pw)
        QMessageBox.information(self, "Vault created", "Master password set. Use it to unlock next time.")
        self.accept()