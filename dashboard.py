from __future__ import annotations
import math
import secrets
import string
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from storage import VaultStorage

from PyQt5.QtCore import Qt, QUrl, QStringListModel, QTimer, pyqtSignal
from PyQt5.QtGui import QDesktopServices
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLabel, QLineEdit, QTextEdit, QPushButton, QTreeWidget, QTreeWidgetItem,
    QComboBox, QMessageBox, QSplitter, QCheckBox, QToolButton, 
    QProgressBar, QMenu, QAction, QInputDialog, QCompleter,
    QApplication
)
from PyQt5.QtWidgets import QAbstractItemView

class EntryTree(QTreeWidget):
    def __init__(self, owner: 'VaultDashboard'):
        super().__init__()
        self.owner = owner
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setDropIndicatorShown(True)
        self.setDragDropMode(QAbstractItemView.InternalMove)

    def dropEvent(self, event):
        try:
            target = self.itemAt(event.pos())
            # If dropping on an entry, use its parent folder
            if target and target.data(0, Qt.UserRole) is not None:
                target = target.parent()
            dest_folder = self.owner._item_path(target) if target else "Other"
            for it in self.selectedItems() or []:
                eid = it.data(0, Qt.UserRole)
                if eid:
                    self.owner.storage.update_entry(eid, {"folder": dest_folder})
        except Exception:
            pass
        super().dropEvent(event)
        # Reload to reflect canonical structure
        self.owner._load_entries()


class VaultDashboard(QWidget):
    entries_changed = pyqtSignal()
    def __init__(self, storage: 'VaultStorage'):
        super().__init__()
        self.storage = storage
        self.current_id = None
        self.gen_length = 16
        self.clipboard_ttl_ms = 30_000  # auto-clear clipboard TTL
        self.require_show_to_copy = False
        # Clipboard countdown state
        self._clip_timer = None
        self._clip_expected = None
        self._clip_label = None
        self._clip_countdown = 0
        self._build_ui()
        self._load_entries()

    def _build_ui(self):
        self.setContentsMargins(8, 8, 8, 8)
        splitter = QSplitter(Qt.Horizontal)

        # Left pane
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search entries...")
        self.search.textChanged.connect(self._filter_tree)

        self.entry_tree = EntryTree(self)
        self.entry_tree.setHeaderHidden(True)
        self.entry_tree.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.entry_tree.itemSelectionChanged.connect(self._on_select_tree)
        self.entry_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.entry_tree.customContextMenuRequested.connect(self._show_tree_context_menu)

        self.new_btn = QPushButton("New")
        self.delete_btn = QPushButton("Delete")
        self.delete_btn.setEnabled(False)
        self.new_btn.clicked.connect(self._new_entry)
        self.delete_btn.clicked.connect(self._delete_entry)

        list_buttons = QHBoxLayout()
        list_buttons.addWidget(self.new_btn)
        list_buttons.addWidget(self.delete_btn)
        list_buttons.addStretch()

        left_layout.addWidget(self.search)
        left_layout.addWidget(self.entry_tree, stretch=1)
        left_layout.addLayout(list_buttons)

        # Right pane
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(12, 0, 0, 0)
        form = QFormLayout()

        self.nameField = QLineEdit()
        self.usernameField = QLineEdit()
        self.emailField = QLineEdit()
        self.urlField = QLineEdit()
        self.urlField.setPlaceholderText("https://")

        self.openUrlBtn = QToolButton()
        self.openUrlBtn.setText("Open")
        self.openUrlBtn.clicked.connect(self._open_url)
        self.copyUrlBtn = QToolButton()
        self.copyUrlBtn.setText("Copy")
        self.copyUrlBtn.clicked.connect(lambda: self._copy_text(self.urlField.text(), "URL"))
        url_row = QHBoxLayout()
        url_row.addWidget(self.urlField, 1)
        url_row.addWidget(self.openUrlBtn)
        url_row.addWidget(self.copyUrlBtn)

        self.copyUserBtn = QToolButton()
        self.copyUserBtn.setText("Copy")
        self.copyUserBtn.clicked.connect(lambda: self._copy_text(self.usernameField.text(), "Username"))
        user_row = QHBoxLayout()
        user_row.addWidget(self.usernameField, 1)
        user_row.addWidget(self.copyUserBtn)

        self.copyEmailBtn = QToolButton()
        self.copyEmailBtn.setText("Copy")
        self.copyEmailBtn.clicked.connect(lambda: self._copy_text(self.emailField.text(), "Email"))
        email_row = QHBoxLayout()
        email_row.addWidget(self.emailField, 1)
        email_row.addWidget(self.copyEmailBtn)

        self.passwordField = QLineEdit()
        self.passwordField.setEchoMode(QLineEdit.Password)
        self.passwordField.textChanged.connect(self._update_strength)

        self.showPass = QCheckBox("Show")
        self.showPass.toggled.connect(lambda c: self.passwordField.setEchoMode(QLineEdit.Normal if c else QLineEdit.Password))

        self.genPassBtn = QToolButton()
        self.genPassBtn.setText("Generate")
        self.genPassBtn.clicked.connect(self._generate_password)
        gen_menu = QMenu(self.genPassBtn)
        for L in (12, 16, 20, 24, 32):
            act = gen_menu.addAction(f"Length {L}")
            act.triggered.connect(lambda _, l=L: self._set_gen_length(l))
        self.genPassBtn.setMenu(gen_menu)
        self.genPassBtn.setPopupMode(QToolButton.MenuButtonPopup)

        self.copyPassBtn = QToolButton()
        self.copyPassBtn.setText("Copy")
        self.copyPassBtn.clicked.connect(lambda: self._copy_text(self.passwordField.text(), "Password"))

        pass_row = QHBoxLayout()
        pass_row.addWidget(self.passwordField, 1)
        pass_row.addWidget(self.showPass)
        pass_row.addWidget(self.genPassBtn)
        pass_row.addWidget(self.copyPassBtn)

        self.strengthBar = QProgressBar()
        self.strengthBar.setRange(0, 100)
        self.strengthBar.setTextVisible(False)
        self.strengthLabel = QLabel("Strength: —")
        strength_row = QHBoxLayout()
        strength_row.addWidget(self.strengthBar, 1)
        strength_row.addWidget(self.strengthLabel)

        self.notesField = QTextEdit()
        self.folderField = QComboBox()
        self.folderField.setEditable(True)
        self.folderField.addItems(["Personal", "Work", "Finance", "Shopping", "Other"])
        self.folderField.setInsertPolicy(QComboBox.NoInsert)
        # Autocomplete for existing folder paths without filling the dropdown
        self.folderModel = QStringListModel([])
        self.folderCompleter = QCompleter(self.folderModel, self)
        self.folderCompleter.setCaseSensitivity(Qt.CaseInsensitive)
        try:
            # Qt >= 5.10
            self.folderCompleter.setFilterMode(Qt.MatchContains)
        except Exception:
            pass
        self.folderCompleter.setCompletionMode(QCompleter.PopupCompletion)
        self.folderField.setCompleter(self.folderCompleter)
        self.tagsField = QLineEdit()
        self.tagsField.setPlaceholderText("Comma-separated (e.g., banking, 2fa)")

        form.addRow("Entry name*", self.nameField)
        form.addRow("Username", QWidget())
        form.itemAt(form.rowCount()-1, QFormLayout.FieldRole).widget().setLayout(user_row)
        form.addRow("Email", QWidget())
        form.itemAt(form.rowCount()-1, QFormLayout.FieldRole).widget().setLayout(email_row)
        form.addRow("URL", QWidget())
        form.itemAt(form.rowCount()-1, QFormLayout.FieldRole).widget().setLayout(url_row)
        form.addRow("Password*", QWidget())
        form.itemAt(form.rowCount()-1, QFormLayout.FieldRole).widget().setLayout(pass_row)
        form.addRow("", QWidget())
        form.itemAt(form.rowCount()-1, QFormLayout.FieldRole).widget().setLayout(strength_row)
        form.addRow("Notes", self.notesField)
        form.addRow("Folder", self.folderField)
        form.addRow("Tags", self.tagsField)

        btn_row = QHBoxLayout()
        self.save_btn = QPushButton("Save")
        self.save_btn.clicked.connect(self._save_entry)
        self.clear_btn = QPushButton("Reset")
        self.clear_btn.clicked.connect(self._clear_form)
        btn_row.addWidget(self.save_btn)
        btn_row.addWidget(self.clear_btn)
        btn_row.addStretch()

        right_layout.addLayout(form)
        right_layout.addLayout(btn_row)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)

        layout = QVBoxLayout(self)
        layout.addWidget(splitter)

    # --- View helpers for menu actions ---
    def expand_all(self):
        try:
            self.entry_tree.expandAll()
        except Exception:
            pass

    def collapse_all(self):
        try:
            self.entry_tree.collapseAll()
        except Exception:
            pass

    def focus_search(self):
        try:
            self.search.setFocus()
            self.search.selectAll()
        except Exception:
            pass

    def _show_tree_context_menu(self, position):
        menu = QMenu()
        item = self.entry_tree.itemAt(position)

        if item is None:
            # Empty space: only New Folder
            new_folder_action = QAction("New Folder", self)
            new_folder_action.triggered.connect(self._create_top_level_folder)
            menu.addAction(new_folder_action)
            menu.exec_(self.entry_tree.viewport().mapToGlobal(position))
            return

        is_entry = item.data(0, Qt.UserRole) is not None
        if not is_entry:
            # Folder (any depth)
            protected = (item.parent() is None and item.text(0) in ["Personal", "Work", "Finance", "Shopping", "Other"])
            add_folder_action = QAction("Create Subfolder", self)
            add_folder_action.triggered.connect(lambda: self._create_subfolder(item))
            menu.addAction(add_folder_action)

            new_entry_action = QAction("New Entry Here", self)
            new_entry_action.triggered.connect(lambda: self._new_entry_in_folder(item))
            menu.addAction(new_entry_action)

            if not protected:
                rename_action = QAction("Rename Folder", self)
                rename_action.triggered.connect(lambda: self._rename_folder(item))
                menu.addAction(rename_action)

                delete_action = QAction("Delete Folder", self)
                delete_action.triggered.connect(lambda: self._delete_folder(item))
                menu.addAction(delete_action)
        else:
            # Entry item
            copy_action = QAction("Copy Entry", self)
            copy_action.triggered.connect(lambda: self._copy_entry(item))
            menu.addAction(copy_action)

            move_action = QAction("Move Entry", self)
            move_action.triggered.connect(lambda: self._move_entry(item))
            menu.addAction(move_action)

            del_action = QAction("Delete Entry", self)
            del_action.triggered.connect(lambda: self._delete_entry_item(item))
            menu.addAction(del_action)

        menu.exec_(self.entry_tree.viewport().mapToGlobal(position))

    def _create_top_level_folder(self):
        name, ok = QInputDialog.getText(self, "New Folder", "Folder name:")
        if ok and name:
            folder = QTreeWidgetItem([name])
            self.entry_tree.addTopLevelItem(folder)
            # Update suggestions
            self._ensure_folder_in_combo(name)
            try:
                self.storage.add_folder(name)
            except Exception:
                pass

    def _create_subfolder(self, parent_item):
        name, ok = QInputDialog.getText(self, "New Subfolder", "Subfolder name:")
        if ok and name:
            subfolder = QTreeWidgetItem([name])
            parent_item.addChild(subfolder)
            parent_item.setExpanded(True)
            # Update suggestions with full path
            self._ensure_folder_in_combo(self._item_path(subfolder))
            try:
                self.storage.add_folder(self._item_path(subfolder))
            except Exception:
                pass

    def _new_entry_in_folder(self, folder_item):
        try:
            self.folderField.setCurrentText(self._item_path(folder_item))
        except Exception:
            pass
        self._clear_form()

    def _rename_folder(self, item):
        old_path = self._item_path(item)
        new_name, ok = QInputDialog.getText(self, "Rename Folder", "New name:", text=item.text(0))
        if ok and new_name:
            item.setText(0, new_name)
            # Keep folder suggestions roughly in sync
            self._refresh_combo_from_tree()
            # Compute new path
            new_path = self._item_path(item)
            try:
                self.storage.rename_folder(old_path, new_path)
            except Exception:
                pass

    def _delete_folder(self, item):
        # Prevent deleting default top-level folders
        if item.parent() is None and item.text(0) in ["Personal", "Work", "Finance", "Shopping", "Other"]:
            QMessageBox.information(self, "Not allowed", "Default folders cannot be deleted.")
            return
        # Determine folder path we are deleting (and its subtree)
        folder_path = self._item_path(item)

        # Find all entries under this folder path (including subfolders)
        affected_ids = []
        for e in self.storage.list_entries():
            f = (e.get("folder") or "Other")
            if f == folder_path or f.startswith(folder_path + "/"):
                affected_ids.append(e.get("id"))

        # Warn and confirm deletion of entries, no move
        if affected_ids:
            reply = QMessageBox.question(
                self,
                "Delete Folder",
                f"This will permanently delete {len(affected_ids)} entrie(s) contained in '{folder_path}'.\n\nProceed?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if reply != QMessageBox.Yes:
                return
            for eid in affected_ids:
                try:
                    self.storage.delete_entry(eid)
                except Exception:
                    pass

        # Remove the folder node from the tree
        parent = item.parent()
        if parent is None:
            idx = self.entry_tree.indexOfTopLevelItem(item)
            if idx >= 0:
                self.entry_tree.takeTopLevelItem(idx)
        else:
            parent.removeChild(item)

        # Refresh view
        self._load_entries()
        self._refresh_combo_from_tree()

    def _copy_entry(self, item):
        entry_id = item.data(0, Qt.UserRole)
        entry = next((e for e in self.storage.list_entries() if e["id"] == entry_id), None)
        if entry:
            # Create a copy with new ID
            new_entry = entry.copy()
            new_entry["name"] = f"{entry['name']} (Copy)"
            new_entry = self.storage.add_entry(new_entry)
            self._load_entries()
            QMessageBox.information(self, "Copied", "Entry copied successfully.")

    def _move_entry(self, item):
        entry_id = item.data(0, Qt.UserRole)
        folders = self._collect_folder_paths()
        
        folder_name, ok = QInputDialog.getItem(
            self, "Move Entry", "Select destination folder:",
            folders, 0, False
        )
        
        if ok and folder_name:
            # Update the entry's folder in storage
            entry = next((e for e in self.storage.list_entries() if e["id"] == entry_id), None)
            if entry:
                self.storage.update_entry(entry_id, {"folder": folder_name})
                self._load_entries()

    def _load_entries(self):
        self.entry_tree.clear()
        # Always ensure default top-level folders exist
        defaults = ["Personal", "Work", "Finance", "Shopping", "Other"]
        for d in defaults:
            self._get_or_create_folder_item(d)

        # Also ensure any custom folders (even empty) are shown
        try:
            for path in self.storage.list_folders():
                self._get_or_create_folder_item(path)
        except Exception:
            pass

        # Load entries into possibly nested folder paths
        for e in self.storage.list_entries():
            folder_path = e.get("folder") or "Other"
            folder_item = self._get_or_create_folder_item(folder_path)
            item = QTreeWidgetItem([e.get("name", "(no name)")])
            item.setData(0, Qt.UserRole, e["id"])
            folder_item.addChild(item)

        self.delete_btn.setEnabled(False)
        # Refresh folder suggestions with current folders
        self._refresh_combo_from_tree()
        try:
            self.entries_changed.emit()
        except Exception:
            pass

    def _filter_tree(self, term):
        term = (term or "").strip().lower()
        self._first_search_match = None

        def entry_matches(item):
            if not term:
                return True
            # Name match
            if term in (item.text(0) or "").lower():
                return True
            # Field match
            try:
                entry_id = item.data(0, Qt.UserRole)
                if not entry_id:
                    return False
                e = next((x for x in self.storage.list_entries() if x["id"] == entry_id), None)
                if not e:
                    return False
                haystack = " ".join([
                    (e.get("name", "") or ""),
                    (e.get("username", "") or ""),
                    (e.get("email", "") or ""),
                    (e.get("url", "") or ""),
                    " ".join(e.get("tags", []) or []),
                ]).lower()
                return term in haystack
            except Exception:
                return False

        def walk(item):
            # Determine if this is an entry (has id) or a folder
            is_entry = item.data(0, Qt.UserRole) is not None
            if is_entry:
                visible = entry_matches(item)
                item.setHidden(not visible)
                if visible and self._first_search_match is None:
                    self._first_search_match = item
                return visible
            # Folder: recurse into children
            any_visible = False
            for i in range(item.childCount()):
                if walk(item.child(i)):
                    any_visible = True
            # When no term, keep folders visible; otherwise only those with visible descendants
            item.setHidden(False if not term else not any_visible)
            item.setExpanded(bool(term) and any_visible)
            return any_visible or not term

        for i in range(self.entry_tree.topLevelItemCount()):
            walk(self.entry_tree.topLevelItem(i))

        if self._first_search_match is not None:
            self.entry_tree.setCurrentItem(self._first_search_match)
            self._on_select_tree()
        else:
            # Clear selection if nothing matches
            self.entry_tree.clearSelection()
            self.delete_btn.setEnabled(False)

    def _on_select_tree(self):
        items = self.entry_tree.selectedItems()
        if not items:
            self.delete_btn.setEnabled(False)
            return
        item = items[0]
        entry_id = item.data(0, Qt.UserRole)
        # If a folder is selected (no entry id), prefill folder field with its path
        if entry_id is None:
            self.folderField.setCurrentText(self._item_path(item))
            self.delete_btn.setEnabled(False)
            return
        data = next((e for e in self.storage.list_entries() if e["id"] == entry_id), None)
        if data:
            self.current_id = entry_id
            self._set_form_entry(data)
            self.delete_btn.setEnabled(True)

    def _new_entry(self):
        self._clear_form()
        # Default folder to currently selected folder if a folder is selected
        items = self.entry_tree.selectedItems()
        if items:
            it = items[0]
            if it and it.data(0, Qt.UserRole) is None:
                self.folderField.setCurrentText(self._item_path(it))
        self.nameField.setFocus()

    def _clear_form(self):
        self.current_id = None
        self.nameField.clear()
        self.usernameField.clear()
        self.emailField.clear()
        self.urlField.clear()
        self.passwordField.clear()
        self.notesField.clear()
        self.tagsField.clear()
        # Keep current folder selection text, otherwise default to Personal
        if not self.folderField.currentText().strip():
            self.folderField.setCurrentText("Personal")
        self.entry_tree.clearSelection()
        self.delete_btn.setEnabled(False)
        self._update_strength()

    def _delete_entry(self):
        items = self.entry_tree.selectedItems()
        if not items or not items[0].parent():
            return
        item = items[0]
        entry_id = item.data(0, Qt.UserRole)
        reply = QMessageBox.question(
            self, "Delete entry", "Are you sure you want to delete this entry?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            if self.storage.delete_entry(entry_id):
                parent = item.parent()
                parent.removeChild(item)
                self._clear_form()
                QMessageBox.information(self, "Deleted", "Entry removed.")
                try:
                    self.entries_changed.emit()
                except Exception:
                    pass
            else:
                QMessageBox.warning(self, "Not found", "Could not delete the selected entry.")

    def _delete_entry_item(self, item):
        # Delete the specific tree item (used from context menu)
        try:
            if item is None or item.parent() is None:
                return
            entry_id = item.data(0, Qt.UserRole)
            if not entry_id:
                return
            reply = QMessageBox.question(
                self, "Delete entry", "Are you sure you want to delete this entry?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if reply != QMessageBox.Yes:
                return
            if self.storage.delete_entry(entry_id):
                parent = item.parent()
                parent.removeChild(item)
                self._clear_form()
                QMessageBox.information(self, "Deleted", "Entry removed.")
                try:
                    self.entries_changed.emit()
                except Exception:
                    pass
        except Exception:
            pass

    def _get_form_entry(self):
        name = self.nameField.text().strip()
        password = self.passwordField.text()
        if not name or not password:
            return None, "Entry name and password are required."
        entry = {
            "name": name,
            "username": self.usernameField.text().strip(),
            "email": self.emailField.text().strip(),
            "url": self.urlField.text().strip(),
            "password": password,
            "notes": self.notesField.toPlainText().strip(),
            "tags": [t.strip() for t in self.tagsField.text().split(",") if t.strip()],
            "folder": self.folderField.currentText()
        }
        return entry, None

    def _set_form_entry(self, e):
        self.nameField.setText(e.get("name", ""))
        self.usernameField.setText(e.get("username", ""))
        self.emailField.setText(e.get("email", ""))
        self.urlField.setText(e.get("url", ""))
        self.passwordField.setText(e.get("password", ""))
        self.notesField.setPlainText(e.get("notes", ""))
        self.tagsField.setText(", ".join(e.get("tags", [])))
        folder = e.get("folder") or "Other"
        # Ensure folder path appears in suggestions and set the text
        self._ensure_folder_in_combo(folder)
        self.folderField.setCurrentText(folder)
        self._update_strength()

    def _save_entry(self):
        entry, err = self._get_form_entry()
        if err:
            QMessageBox.warning(self, "Missing required fields", err)
            return

        if self.current_id:
            # We have an entry selected; ask user if they want to update or save as new
            existing = next((e for e in self.storage.list_entries() if e["id"] == self.current_id), None)
            if existing is not None and self._entries_equivalent(existing, entry):
                # No change; nothing to do
                QMessageBox.information(self, "No changes", "Nothing changed to save.")
                return

            box = QMessageBox(self)
            box.setIcon(QMessageBox.Question)
            box.setWindowTitle("Update or Save as New?")
            box.setText("You are editing an existing entry. Do you want to update it or save as a new entry?")
            update_btn = box.addButton("Update Existing", QMessageBox.AcceptRole)
            new_btn = box.addButton("Save as New", QMessageBox.ActionRole)
            cancel_btn = box.addButton(QMessageBox.Cancel)
            box.setDefaultButton(new_btn)
            box.exec_()

            clicked = box.clickedButton()
            if clicked is cancel_btn:
                return
            elif clicked is new_btn:
                created = self.storage.add_entry(entry)
                self._load_entries()
                self.current_id = created["id"]
                QMessageBox.information(self, "Saved", f"New entry '{entry['name']}' added.")
            else:
                updated = entry.copy()
                self.storage.update_entry(self.current_id, updated)
                self._load_entries()
                QMessageBox.information(self, "Saved", "Entry updated.")
                try:
                    self.entries_changed.emit()
                except Exception:
                    pass
        else:
            created = self.storage.add_entry(entry)
            self._load_entries()
            self.current_id = created["id"]
            QMessageBox.information(self, "Success", f"Entry '{entry['name']}' added.")
            try:
                self.entries_changed.emit()
            except Exception:
                pass
            try:
                self.entries_changed.emit()
            except Exception:
                pass

    def _copy_text(self, text, label="Text"):
        if not text:
            self._notify(f"No {label.lower()} to copy.")
            return
        # Respect preference: require 'Show' for password copies
        if label == "Password" and self.require_show_to_copy and self.passwordField.echoMode() != QLineEdit.Normal:
            self._notify("Password is hidden. Click 'Show' first or disable the setting in Preferences.")
            return
        cb = QApplication.clipboard()
        cb.setText(text)
        # Setup countdown
        self._clip_expected = text
        self._clip_label = label
        self._clip_countdown = max(1, int(self.clipboard_ttl_ms / 1000))
        self._start_clipboard_timer()
        self._notify(f"{label} copied. Clears in {self._clip_countdown}s.", 1100)

    def _clear_clipboard_if_unchanged(self, expected_text: str):
        cb = QApplication.clipboard()
        try:
            current = cb.text() or ""
        except Exception:
            current = ""
        if current == (expected_text or ""):
            cb.setText("")
            self._notify("Clipboard cleared.", 1500)
        # Reset state
        self._clip_expected = None
        self._clip_label = None
        self._clip_countdown = 0

    def _start_clipboard_timer(self):
        # Stop any existing timer
        if self._clip_timer is not None:
            try:
                self._clip_timer.stop()
                self._clip_timer.deleteLater()
            except Exception:
                pass
            self._clip_timer = None

        self._clip_timer = QTimer(self)
        self._clip_timer.setInterval(1000)
        self._clip_timer.timeout.connect(self._tick_clipboard)
        self._clip_timer.start()

    def _tick_clipboard(self):
        # If clipboard changed, stop countdown
        cb = QApplication.clipboard()
        try:
            current = cb.text() or ""
        except Exception:
            current = ""
        if self._clip_expected is None or current != (self._clip_expected or ""):
            # Someone copied something else; stop timer silently
            if self._clip_timer is not None:
                self._clip_timer.stop()
                self._clip_timer.deleteLater()
                self._clip_timer = None
            self._clip_expected = None
            self._clip_label = None
            self._clip_countdown = 0
            return

        # Countdown and update status
        self._clip_countdown = max(0, self._clip_countdown - 1)
        if self._clip_countdown > 0:
            if self._clip_label:
                self._notify(f"{self._clip_label} copied. Clears in {self._clip_countdown}s.", 1100)
            return

        # Time to clear
        if self._clip_timer is not None:
            self._clip_timer.stop()
            self._clip_timer.deleteLater()
            self._clip_timer = None
        self._clear_clipboard_if_unchanged(self._clip_expected or "")

    def apply_settings(self, settings: dict):
        try:
            sec = int(settings.get("clipboard_ttl_sec", 30) or 30)
            self.clipboard_ttl_ms = max(1, sec) * 1000
        except Exception:
            pass
        try:
            self.require_show_to_copy = bool(settings.get("require_show_to_copy", False))
        except Exception:
            pass

    # Lock/unlock UI helpers
    def lock_ui(self):
        try:
            self.setEnabled(False)
            # Clear sensitive fields
            self.passwordField.clear()
            self._clear_form()
        except Exception:
            pass

    def unlock_ui(self):
        try:
            self.setEnabled(True)
            self._load_entries()
        except Exception:
            pass

    def _open_url(self):
        url = self.urlField.text().strip()
        if not url:
            return
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "https://" + url
        QDesktopServices.openUrl(QUrl(url))

    def _set_gen_length(self, L):
        self.gen_length = int(L)
        if not self.passwordField.text():
            self._generate_password()

    def _generate_password(self):
        L = max(8, int(self.gen_length))
        lowers = string.ascii_lowercase
        uppers = string.ascii_uppercase
        digits = string.digits
        punct = "!@#$%^&*()-_=+[]{};:,.?/|~"
        pools = [lowers, uppers, digits, punct]
        pwd_chars = [
            secrets.choice(lowers),
            secrets.choice(uppers),
            secrets.choice(digits),
            secrets.choice(punct),
        ]
        all_chars = "".join(pools)
        while len(pwd_chars) < L:
            pwd_chars.append(secrets.choice(all_chars))
        secrets.SystemRandom().shuffle(pwd_chars)
        password = "".join(pwd_chars)
        self.passwordField.setText(password)
        self.showPass.setChecked(True)
        self._update_strength()

    def _update_strength(self):
        pwd = self.passwordField.text()
        score, label, color = self._password_strength(pwd)
        self.strengthBar.setValue(score)
        self._set_bar_color(self.strengthBar, color)
        self.strengthLabel.setText(f"Strength: {label}")

    def _set_bar_color(self, bar: QProgressBar, color: str):
        bar.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid #aaa; border-radius: 4px; background: #eee; height: 10px;
            }}
            QProgressBar::chunk {{
                background-color: {color};
            }}
        """)

    def _password_strength(self, pwd: str):
        if not pwd:
            return 0, "—", "red"
        length = len(pwd)
        sets = 0
        size = 0
        has_lower = any(c.islower() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        has_punct = any(c in string.punctuation for c in pwd)
        if has_lower: sets += 1; size += 26
        if has_upper: sets += 1; size += 26
        if has_digit: sets += 1; size += 10
        if has_punct: sets += 1; size += 32
        unique_chars = len(set(pwd))
        repeat_penalty = max(0, (length - unique_chars)) * 1.5
        entropy = max(0.0, length * math.log2(size) - repeat_penalty) if size > 0 else 0.0
        score = int(max(0, min(100, (entropy / 80.0) * 100)))
        if length < 8 or sets <= 1: score = min(score, 30)
        elif length < 12: score = min(score, 60)
        if score < 25: return score, "Very weak", "red"
        elif score < 50: return score, "Weak", "orange"
        elif score < 75: return score, "Good", "gold"
        else: return score, "Strong", "green"    

    # --- Folder helpers ---
    def _notify(self, message: str, ms: int = 2000):
        # Prefer main window status bar if available, fallback to no-op
        app = QApplication.instance()
        win = app.activeWindow() if app else None
        try:
            sb = getattr(win, 'statusBar', None)
            if callable(sb):
                sb().showMessage(message, ms)
                return
        except Exception:
            pass
        # As a very last resort, ignore to avoid modal popups
        return
    def _entries_equivalent(self, a, b):
        keys = ["name", "username", "email", "url", "password", "notes", "folder"]
        for k in keys:
            if (a.get(k) or "").strip() != (b.get(k) or "").strip():
                return False
        # Compare tags ignoring order/whitespace
        at = sorted([t.strip() for t in a.get("tags", []) if t.strip()])
        bt = sorted([t.strip() for t in b.get("tags", []) if t.strip()])
        return at == bt
    def _item_path(self, item):
        parts = []
        it = item
        while it is not None and it.text(0):
            parts.append(it.text(0))
            it = it.parent()
        return "/".join(reversed(parts))

    def _get_or_create_folder_item(self, path: str):
        # Accept nested paths like "Entertainment/Netflix"
        parts = [p for p in (path or "Other").split("/") if p]
        if not parts:
            parts = ["Other"]
        # Find or create the top-level item
        parent = None
        # Search for existing top-level with the given name
        def _find_child(parent_item, name):
            if parent_item is None:
                # search top-level
                for i in range(self.entry_tree.topLevelItemCount()):
                    it = self.entry_tree.topLevelItem(i)
                    if it.text(0) == name:
                        return it
                return None
            else:
                for j in range(parent_item.childCount()):
                    ch = parent_item.child(j)
                    if ch.text(0) == name:
                        return ch
                return None

        current = None
        for idx, name in enumerate(parts):
            found = _find_child(current, name)
            if not found:
                node = QTreeWidgetItem([name])
                if current is None:
                    self.entry_tree.addTopLevelItem(node)
                else:
                    current.addChild(node)
                current = node
            else:
                current = found
        return current

    def _collect_folder_paths(self):
        paths = []
        def _walk(item, base=None):
            name = item.text(0)
            path = name if not base else f"{base}/{name}"
            paths.append(path)
            for i in range(item.childCount()):
                _walk(item.child(i), path)
        for i in range(self.entry_tree.topLevelItemCount()):
            _walk(self.entry_tree.topLevelItem(i), None)
        return paths

    def _ensure_folder_in_combo(self, path: str):
        # Ensure the completer model contains this path without bloating the dropdown
        if not path:
            return
        paths = set(self.folderModel.stringList())
        if path not in paths:
            paths.add(path)
            self.folderModel.setStringList(sorted(paths))

    def _refresh_combo_from_tree(self):
        # Keep dropdown compact with defaults only; update completer with full set
        defaults = ["Personal", "Work", "Finance", "Shopping", "Other"]
        cur = self.folderField.currentText()
        self.folderField.clear()
        self.folderField.setEditable(True)
        self.folderField.addItems(defaults)
        # Update completer suggestions with existing folders (including defaults)
        paths = sorted(set(self._collect_folder_paths()) | set(defaults))
        self.folderModel.setStringList(paths)
        if cur:
            self.folderField.setCurrentText(cur)
