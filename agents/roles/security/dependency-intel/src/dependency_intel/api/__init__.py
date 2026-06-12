"""HTTP API surface for dependency-intel."""
from .app import Service, create_app

__all__ = ["Service", "create_app"]
