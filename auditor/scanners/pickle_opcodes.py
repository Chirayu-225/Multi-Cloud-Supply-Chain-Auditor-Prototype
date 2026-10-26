"""
Static pickle import scan — never unpickles (never executes) the file.

Earlier versions used a short denylist (os.system, eval, ...), which is
easy to evade with any callable not on the list. This uses an allowlist
of imports that legitimate PyTorch / NumPy / sklearn checkpoints need;
anything else is flagged, and known code-execution primitives are
flagged harder. Same approach as picklescan / fickling.
"""

from ..artifact import Artifact
from .base import Finding, Scanner
from .pickle_utils import collect, is_pickle_candidate

SAFE_GLOBALS = {
    ("collections", "OrderedDict"),
    ("builtins", "set"), ("builtins", "frozenset"), ("builtins", "slice"),
    ("builtins", "complex"), ("builtins", "bytearray"), ("builtins", "range"),
    ("_codecs", "encode"),
    ("torch", "Size"), ("torch", "device"), ("torch", "dtype"),
    ("torch._tensor", "_rebuild_from_type_v2"),
    ("torch.nn.parameter", "Parameter"),
    ("numpy", "ndarray"), ("numpy", "dtype"),
    ("numpy.core.multiarray", "_reconstruct"), ("numpy.core.multiarray", "scalar"),
    ("numpy._core.multiarray", "_reconstruct"), ("numpy._core.multiarray", "scalar"),
}
SAFE_PREFIX_RULES = (
    # module, predicate on name
    ("torch._utils", lambda n: n.startswith("_rebuild_")),
    ("torch", lambda n: n.endswith("Storage")),
)

DANGEROUS_MODULES = {
    "os", "posix", "nt", "subprocess", "sys", "socket", "shutil", "pty",
    "runpy", "importlib", "ctypes", "webbrowser", "pickle", "marshal",
    "code", "codeop", "multiprocessing", "asyncio", "requests", "urllib",
}
DANGEROUS_BUILTINS = {"eval", "exec", "compile", "open", "getattr", "setattr", "__import__", "globals", "vars", "breakpoint", "input"}


def classify(module: str, name: str) -> str:
    """Return 'safe', 'dangerous' or 'unknown'."""
    if (module, name) in SAFE_GLOBALS:
        return "safe"
    for mod, rule in SAFE_PREFIX_RULES:
        if module == mod and rule(name):
            return "safe"
    root = module.split(".", 1)[0]
    if root in DANGEROUS_MODULES:
        return "dangerous"
    if root in ("builtins", "__builtin__") and name in DANGEROUS_BUILTINS:
        return "dangerous"
    return "unknown"


class PickleImportScanner(Scanner):
    name = "pickle_imports"

    def applies(self, artifact: Artifact) -> bool:
        return is_pickle_candidate(artifact)

    def scan(self, artifact: Artifact) -> Finding:
        dangerous, unknown, errors = set(), set(), []
        for result in collect(artifact):
            if result.parse_error:
                errors.append(result.stream)
            for module, name in result.imports:
                verdict = classify(module, name)
                if verdict == "dangerous":
                    dangerous.add(f"{module}.{name}")
                elif verdict == "unknown":
                    unknown.add(f"{module}.{name}")

        if dangerous:
            return self.flag(80, f"Code-execution imports in pickle: {', '.join(sorted(dangerous))[:400]}")
        if unknown:
            return self.flag(30, f"Imports outside the safe allowlist (review before loading): {', '.join(sorted(unknown))[:400]}")
        if errors:
            return self.flag(20, f"Pickle stream could not be parsed statically ({', '.join(errors)[:200]}) — treat as suspicious")
        return self.ok("Only allowlisted imports found")
