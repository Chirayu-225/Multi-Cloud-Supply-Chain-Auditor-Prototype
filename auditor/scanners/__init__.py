"""Scanner registry — the worker runs every scanner whose applies() is true."""

from .base import Finding, Scanner
from .cross_source import CrossSourceScanner
from .pickle_opcodes import PickleImportScanner
from .serialization import SerializationFormatScanner
from .typosquat import TyposquatScanner


def default_scanners() -> list[Scanner]:
    return [
        SerializationFormatScanner(),
        PickleImportScanner(),
        TyposquatScanner(),
        CrossSourceScanner(),
    ]


__all__ = ["Finding", "Scanner", "default_scanners"]
