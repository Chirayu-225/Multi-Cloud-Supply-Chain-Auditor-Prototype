"""
Shared pickle helpers: find every pickle stream in an artifact (raw
pickle file, or pickles inside a PyTorch zip checkpoint) and extract
the (module, name) globals each stream imports — without ever
unpickling anything.
"""

import io
import pickletools
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass

from ..artifact import Artifact

PICKLE_EXTENSIONS = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib"}
MAX_MEMBER_BYTES = 512 * 1024 * 1024  # zip-bomb guard for a single member

STRING_OPCODES = {
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8",
    "SHORT_BINSTRING", "BINSTRING", "UNICODE", "STRING",
}
MEMO_GET_OPCODES = {"GET", "BINGET", "LONG_BINGET"}
MEMO_PUT_OPCODES = {"PUT", "BINPUT", "LONG_BINPUT"}


@dataclass
class PickleGlobals:
    stream: str                       # "<file>" or zip member name
    imports: list[tuple[str, str]]    # (module, name) pairs
    parse_error: str | None = None


def is_pickle_candidate(artifact: Artifact) -> bool:
    """Decide by content as well as extension, so renaming evil.pkl to
    evil.txt doesn't skip the scan."""
    return (
        artifact.extension in PICKLE_EXTENSIONS
        or artifact.looks_like_raw_pickle
        or bool(artifact.zip_pickle_members)
    )


def iter_pickle_streams(artifact: Artifact) -> Iterator[tuple[str, bytes]]:
    if artifact.zip_pickle_members:
        with zipfile.ZipFile(artifact.path) as zf:
            for name in artifact.zip_pickle_members:
                info = zf.getinfo(name)
                if info.file_size > MAX_MEMBER_BYTES:
                    yield name, b""  # parsed as an error below
                    continue
                yield name, zf.read(name)
    else:
        with open(artifact.path, "rb") as f:
            yield "<file>", f.read()


def extract_globals(data: bytes) -> list[tuple[str, str]]:
    """Walk the opcode stream, tracking just enough state to resolve
    STACK_GLOBAL arguments — including strings fetched back from the
    memo, which real payloads use to hide the module/name pair."""
    imports: list[tuple[str, str]] = []
    recent: list[str | None] = []  # last values pushed (strings or None)
    memo: dict[int, str | None] = {}

    def push(value: str | None) -> None:
        recent.append(value)
        if len(recent) > 2:
            recent.pop(0)

    for opcode, arg, _pos in pickletools.genops(io.BytesIO(data)):
        name = opcode.name
        if name in STRING_OPCODES:
            push(str(arg))
        elif name in MEMO_GET_OPCODES:
            push(memo.get(arg))
        elif name in MEMO_PUT_OPCODES:
            memo[arg] = recent[-1] if recent else None
        elif name == "MEMOIZE":
            memo[len(memo)] = recent[-1] if recent else None
        elif name in ("GLOBAL", "INST"):
            module, _, attr = str(arg).partition(" ")
            imports.append((module, attr))
            push(None)
        elif name == "STACK_GLOBAL":
            if len(recent) == 2 and all(v is not None for v in recent):
                imports.append((recent[0], recent[1]))
            else:
                imports.append(("<unresolved>", "<unresolved>"))
            push(None)
        elif name not in ("FRAME", "PROTO", "STOP"):
            push(None)
    return imports


def collect(artifact: Artifact) -> list[PickleGlobals]:
    results = []
    for stream, data in iter_pickle_streams(artifact):
        try:
            if not data:
                raise ValueError("member too large or empty")
            results.append(PickleGlobals(stream, extract_globals(data)))
        except Exception as e:  # malformed / truncated / not a pickle
            results.append(PickleGlobals(stream, [], parse_error=str(e)[:200]))
    return results
