import json
import os


DEFAULT_SETTINGS = {
    "clipboard_ttl_sec": 30,
    "require_show_to_copy": False,
    "plaintext_export_autodelete_min": 10,
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

