from importlib import import_module as _im
_m = _im('dashboard')
VaultDashboard = _m.VaultDashboard

__all__ = ['VaultDashboard']

