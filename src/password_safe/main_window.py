from importlib import import_module as _im
_m = _im('main_window')
MainWindow = _m.MainWindow

__all__ = ['MainWindow']

