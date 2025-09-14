import json
import os


DEFAULT_SETTINGS = {
    "clipboard_ttl_sec": 30,
    "require_show_to_copy": False,
    # Plaintext export auto-delete time in seconds
    "plaintext_export_autodelete_sec": 600,
    # Idle lock now expressed in seconds (backward-compatible with legacy minutes key)
    "auto_lock_enabled": True,
    "auto_lock_seconds": 60,
    # Terms acceptance
    "terms_accepted": False,
    "terms_accepted_at": None,
}


def settings_path() -> str:
    base = os.path.join(os.path.expanduser("~"), ".simple_vault")
    return os.path.join(base, "settings.json")


def load_settings() -> dict:
    path = settings_path()
    data = dict(DEFAULT_SETTINGS)
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                file_data = json.load(f)
            if isinstance(file_data, dict):
                data.update({k: file_data.get(k, v) for k, v in DEFAULT_SETTINGS.items()})
                # Backward compatibility: convert legacy minutes to seconds if present
                if "auto_lock_minutes" in file_data and "auto_lock_seconds" not in file_data:
                    try:
                        data["auto_lock_seconds"] = int(file_data.get("auto_lock_minutes", 5)) * 60
                    except Exception:
                        pass
                if "plaintext_export_autodelete_min" in file_data and "plaintext_export_autodelete_sec" not in file_data:
                    try:
                        data["plaintext_export_autodelete_sec"] = int(file_data.get("plaintext_export_autodelete_min", 10)) * 60
                    except Exception:
                        pass
    except Exception:
        # Fall back to defaults on any error
        data = dict(DEFAULT_SETTINGS)
    return data


def save_settings(values: dict) -> None:
    path = settings_path()
    directory = os.path.dirname(path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
    data = dict(DEFAULT_SETTINGS)
    if isinstance(values, dict):
        data.update({k: values.get(k, v) for k, v in DEFAULT_SETTINGS.items()})
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)
