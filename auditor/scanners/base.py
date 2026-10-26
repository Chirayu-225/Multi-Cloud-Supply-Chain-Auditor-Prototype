"""
Scanner interface. Each check is a small class:

    applies(artifact) -> bool    cheap test: is this check relevant?
    scan(artifact)    -> Finding the actual analysis

Adding a new check means writing one class and registering it in
scanners/__init__.py — the worker and the risk logic don't change.
"""

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass

from ..artifact import Artifact


@dataclass
class Finding:
    check: str
    risky: bool
    weight: int
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


class Scanner(ABC):
    name: str = "scanner"

    @abstractmethod
    def applies(self, artifact: Artifact) -> bool: ...

    @abstractmethod
    def scan(self, artifact: Artifact) -> Finding: ...

    def ok(self, detail: str) -> Finding:
        return Finding(check=self.name, risky=False, weight=0, detail=detail)

    def flag(self, weight: int, detail: str) -> Finding:
        return Finding(check=self.name, risky=True, weight=weight, detail=detail)
