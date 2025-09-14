from importlib import import_module as _im
_m = _im('settings')

DEFAULT_SETTINGS = _m.DEFAULT_SETTINGS
settings_path = _m.settings_path
load_settings = _m.load_settings
save_settings = _m.save_settings

__all__ = [
    'DEFAULT_SETTINGS',
    'settings_path',
    'load_settings',
    'save_settings',
]

