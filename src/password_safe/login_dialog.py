from importlib import import_module as _im
_m = _im('login_dialog')
LoginDialog = _m.LoginDialog

__all__ = ['LoginDialog']

