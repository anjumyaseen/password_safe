import os
import json
import uuid
import base64
import hashlib
import hmac
from datetime import datetime, timezone

try:
    # AES-GCM for authenticated encryption at rest
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:  # pragma: no cover - import-time guard
    AESGCM = None

class VaultStorage:
    def __init__(self, path):
        self.path = path
        self._data = None  # raw JSON dict persisted to disk
        self._key = None   # derived encryption key (bytes) after unlock
        self._entries = [] # decrypted entries kept in-memory during a session
        self._encrypted_blob = None  # cached encrypted payload before unlock
        self._folders = []  # custom folders (persisted), can be empty
        self._load()

    def _default_data(self):
        return {"version": 1, "master": None, "entries": [], "folders": []}

    def _load(self):
        if not os.path.exists(self.path):
            self._data = self._default_data()
            self._encrypted_blob = None
            self._entries = []
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self._data = json.load(f)
            # Detect encrypted payload
            vault = self._data.get("vault")
            if isinstance(vault, dict) and "nonce" in vault and "ciphertext" in vault:
                self._encrypted_blob = vault
                self._entries = []  # will fill after unlock
            else:
                # Plaintext (v1) format
                self._data.setdefault("entries", [])
                self._data.setdefault("folders", [])
                self._entries = list(self._data.get("entries", []))
                self._folders = list(self._data.get("folders", []))
                self._encrypted_blob = None
        except Exception:
            self._data = self._default_data()
            self._encrypted_blob = None
            self._entries = []
            self._folders = []

    def save(self):
        directory = os.path.dirname(self.path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)

        # If unlocked and we have a key, encrypt entries at rest
        if self._key is not None and AESGCM is not None:
            self._data["version"] = 2
            # Encrypt entries list
            blob = self._encrypt_payload()
            self._data["vault"] = blob
            # Remove plaintext entries if present
            if "entries" in self._data:
                try:
                    del self._data["entries"]
                except Exception:
                    pass
            if "folders" in self._data:
                try:
                    del self._data["folders"]
                except Exception:
                    pass
        else:
            # Keep plaintext only for uninitialized vaults (no master yet)
            self._data.setdefault("version", 1)
            self._data["entries"] = list(self._entries)
            self._data["folders"] = list(self._folders)

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
            "iterations": iterations,
        }
        # Keep derived key in memory and encrypt any existing plaintext entries
        self._key = dk
        # If we loaded plaintext entries, migrate them into encrypted blob
        self.save()

    def verify_master_password(self, password: str) -> bool:
        master = self._data.get("master")
        if not master:
            return False
        salt = base64.b64decode(master["salt"])
        iterations = master.get("iterations", 200_000)
        expected = base64.b64decode(master["hash"])
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        if not hmac.compare_digest(dk, expected):
            return False

        # Password verified — store key and attempt decryption/migration
        self._key = dk

        # If encrypted blob exists, decrypt entries now
        if self._data.get("vault"):
            try:
                entries, folders = self._decrypt_payload()
                self._entries = entries
                self._folders = folders
            except Exception:
                # Decryption failure should be treated as invalid password
                self._key = None
                self._entries = []
                self._folders = []
                return False
        else:
            # v1 plaintext: entries were loaded in _load(); migrate on first unlock
            # Ensure entries field exists
            self._entries = list(self._data.get("entries", []))
            self._folders = list(self._data.get("folders", []))
            self.save()
        return True

    def change_master_password(self, old_password: str, new_password: str, iterations: int = 200_000) -> bool:
        """Change the master password and re-encrypt the vault.

        Returns True on success, False if the old password is invalid.
        Raises RuntimeError if cryptography/AESGCM is unavailable.
        """
        if AESGCM is None:
            raise RuntimeError("cryptography is required to change the master password")

        # Verify old password and ensure entries are decrypted in memory
        if not self.verify_master_password(old_password):
            return False

        # Derive new key and update master record
        salt = os.urandom(16)
        new_key = hashlib.pbkdf2_hmac("sha256", new_password.encode("utf-8"), salt, iterations)
        self._data["master"] = {
            "salt": base64.b64encode(salt).decode("ascii"),
            "hash": base64.b64encode(new_key).decode("ascii"),
            "iterations": iterations,
        }
        # Swap in the new key and persist (will write encrypted blob with new key)
        self._key = new_key
        self.save()
        return True

    def lock(self):
        """Forget the in-memory key and entries; require re-unlock.

        Disk remains encrypted. Next verify_master_password() will decrypt entries again.
        """
        self._key = None
        try:
            self._entries = []
        except Exception:
            pass

    def list_entries(self):
        return list(self._entries)

    def list_folders(self):
        return list(self._folders)

    def add_entry(self, entry):
        entry = dict(entry)
        entry["id"] = str(uuid.uuid4())
        entry["created_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        entry["updated_at"] = entry["created_at"]
        entry.setdefault("history", [])
        self._entries.append(entry)
        self.save()
        return entry

    def update_entry(self, entry_id, updated_fields):
        for e in self._entries:
            if e["id"] == entry_id:
                snapshot = {k: e.get(k) for k in [
                    "name", "username", "email", "url", "password", "notes", "tags", "folder", "updated_at"
                ]}
                e.setdefault("history", []).append(snapshot)
                for k, v in updated_fields.items():
                    if k not in ["id", "created_at"]:
                        e[k] = v
                e["updated_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                self.save()
                return e
        return None

    def delete_entry(self, entry_id):
        before = len(self._entries)
        self._entries = [e for e in self._entries if e.get("id") != entry_id]
        if len(self._entries) != before:
            self.save()
            return True
        return False

    # --- Encryption helpers ---
    def _aesgcm(self):
        if AESGCM is None:
            raise RuntimeError("cryptography is required for encrypted vaults")
        if self._key is None:
            raise RuntimeError("Vault is locked; no key available")
        return AESGCM(self._key)

    def _encrypt_payload(self):
        # Serialize and encrypt entries + folders using AES-GCM
        aad = b"password_safe:v1"
        payload = {"entries": list(self._entries), "folders": list(self._folders)}
        plaintext = json.dumps(payload).encode("utf-8")
        nonce = os.urandom(12)
        aesgcm = self._aesgcm()
        ct = aesgcm.encrypt(nonce, plaintext, aad)
        return {
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ct).decode("ascii"),
        }

    def _decrypt_payload(self):
        vault = self._data.get("vault")
        if not vault:
            return list(self._data.get("entries", [])), list(self._data.get("folders", []))
        nonce = base64.b64decode(vault["nonce"])
        ct = base64.b64decode(vault["ciphertext"])
        aad = b"password_safe:v1"
        aesgcm = self._aesgcm()
        pt = aesgcm.decrypt(nonce, ct, aad)
        obj = json.loads(pt.decode("utf-8"))
        if isinstance(obj, list):
            # Backward-compat: original format stored list of entries only
            return obj, []
        return list(obj.get("entries", [])), list(obj.get("folders", []))

    # --- Folder helpers ---
    def add_folder(self, path: str):
        if not path:
            return
        if path not in self._folders and path not in ["Personal", "Work", "Finance", "Shopping", "Other"]:
            self._folders.append(path)
            self.save()

    def remove_folder(self, prefix: str):
        if not prefix:
            return
        # Remove the folder and any of its subpaths
        keep = [f for f in self._folders if not (f == prefix or f.startswith(prefix + "/"))]
        if len(keep) != len(self._folders):
            self._folders = keep
            self.save()

    def rename_folder(self, old: str, new: str):
        if not old or not new or old == new:
            return
        # Update folder list
        updated = []
        for f in self._folders:
            if f == old or f.startswith(old + "/"):
                updated.append(new + f[len(old):])
            else:
                updated.append(f)
        self._folders = []
        # normalize unique
        for f in updated:
            if f not in self._folders:
                self._folders.append(f)
        # Update entries
        for e in self._entries:
            f = e.get("folder") or "Other"
            if f == old or f.startswith(old + "/"):
                e["folder"] = new + f[len(old):]
        self.save()
