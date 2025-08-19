import os
import json
import uuid
import base64
import hashlib
import hmac
from datetime import datetime

class VaultStorage:
    def __init__(self, path):
        self.path = path
        self._data = None
        self._load()

    def _default_data(self):
        return {"version": 1, "master": None, "entries": []}

    def _load(self):
        if not os.path.exists(self.path):
            self._data = self._default_data()
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self._data = json.load(f)
            if "entries" not in self._data:
                self._data["entries"] = []
        except Exception:
            self._data = self._default_data()

    def save(self):
        directory = os.path.dirname(self.path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2)
        os.replace(tmp, self.path)

    def is_initialized(self):
        return self._data.get("master") is not None

    def set_master_password(self, password, iterations=200_000):
        salt = os.urandom(16)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        self._data["master"] = {
            "salt": base64.b64encode(salt).decode("ascii"),
            "hash": base64.b64encode(dk).decode("ascii"),
            "iterations": iterations
        }
        self.save()

    def verify_master_password(self, password: str) -> bool:
        master = self._data.get("master")
        if not master:
            return False
        salt = base64.b64decode(master["salt"])
        iterations = master.get("iterations", 200_000)
        expected = base64.b64decode(master["hash"])
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(dk, expected)

    def list_entries(self):
        return list(self._data["entries"])

    def add_entry(self, entry):
        entry["id"] = str(uuid.uuid4())
        now = datetime.utcnow().isoformat() + "Z"
        entry["created_at"] = now
        entry["updated_at"] = now
        entry.setdefault("history", [])
        self._data["entries"].append(entry)
        self.save()
        return entry

    def update_entry(self, entry_id, updated_fields):
        for e in self._data["entries"]:
            if e["id"] == entry_id:
                snapshot = {k: e.get(k) for k in ["name", "username", "email", "url", "password", "notes", "tags", "folder", "updated_at"]}
                e.setdefault("history", []).append(snapshot)
                for k, v in updated_fields.items():
                    if k not in ["id", "created_at"]:
                        e[k] = v
                e["updated_at"] = datetime.utcnow().isoformat() + "Z"
                self.save()
                return e
        return None

    def delete_entry(self, entry_id):
        before = len(self._data["entries"])
        self._data["entries"] = [e for e in self._data["entries"] if e.get("id") != entry_id]
        if len(self._data["entries"]) != before:
            self.save()
            return True
        return False