"""P11-F bounded event collector application factory.

The live lab supplies an ephemeral source registry and temporary SQLite store;
this module deliberately has no default keys or persistent database.
"""

from aegis.detection.security_analytics import create_collector_app

__all__ = ["create_collector_app"]
