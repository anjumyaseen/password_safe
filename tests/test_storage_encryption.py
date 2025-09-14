import os
import json
import base64
import hashlib
import tempfile
import unittest
from datetime import datetime, timezone

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
    CRYPTO_OK = True
except Exception:
    CRYPTO_OK = False

from storage import VaultStorage


@unittest.skipUnless(CRYPTO_OK, "cryptography not available")
class TestVaultEncryption(unittest.TestCase):
    def test_encrypts_and_decrypts_entries(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "vault.json")

            vs = VaultStorage(path)
            self.assertFalse(vs.is_initialized())

            vs.set_master_password("secret1234")
            vs.add_entry({
                "name": "Email",
                "username": "user@example.com",
                "password": "p@ssW0rd!",
                "url": "https://mail.example.com",
                "notes": "Test",
                "tags": ["test"],
                "folder": "Personal",
            })

            # File should contain encrypted blob and no plaintext entries
            with open(path, "r", encoding="utf-8") as f:
                doc = json.load(f)
            self.assertIn("vault", doc)
            self.assertNotIn("entries", doc)
            self.assertIn("nonce", doc["vault"])  # base64 string
            self.assertIn("ciphertext", doc["vault"])  # base64 string
            self.assertEqual(doc.get("version"), 2)

            # Reopen and unlock
            vs2 = VaultStorage(path)
            self.assertTrue(vs2.verify_master_password("secret1234"))
            entries = vs2.list_entries()
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["name"], "Email")
            self.assertEqual(entries[0]["password"], "p@ssW0rd!")

    def test_migrate_plaintext_v1(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "vault.json")

            # Build a legacy plaintext v1 file
            password = "migrate-please"
            salt = os.urandom(16)
            iterations = 200_000
            dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
            legacy = {
                "version": 1,
                "master": {
                    "salt": base64.b64encode(salt).decode("ascii"),
                    "hash": base64.b64encode(dk).decode("ascii"),
                    "iterations": iterations,
                },
                "entries": [
                    {
                        "id": "legacy-id-1",
                        "name": "LegacySite",
                        "username": "legacy",
                        "password": "legacyPass#1",
                        "url": "example.com",
                        "notes": "legacy note",
                        "tags": ["legacy"],
                        "folder": "Other",
                        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        "history": [],
                    }
                ],
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(legacy, f, indent=2)

            # Open and unlock -> should migrate to encrypted format
            vs = VaultStorage(path)
            self.assertTrue(vs.verify_master_password(password))
            ents = vs.list_entries()
            self.assertEqual(len(ents), 1)
            self.assertEqual(ents[0]["name"], "LegacySite")

            # File should now be encrypted
            with open(path, "r", encoding="utf-8") as f:
                doc2 = json.load(f)
            self.assertIn("vault", doc2)
            self.assertNotIn("entries", doc2)
            self.assertEqual(doc2.get("version"), 2)


if __name__ == "__main__":
    unittest.main()
