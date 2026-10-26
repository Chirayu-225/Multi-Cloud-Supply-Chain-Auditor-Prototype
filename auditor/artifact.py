"""
Artifact: a downloaded file plus everything scanners commonly need
(hash, size, extension, first bytes, sniffed format). Built once per
job, so the file is downloaded and hashed exactly once.
"""

import os
import zipfile
from dataclasses import dataclass, field
from functools import cached_property

PICKLE_PROTO_MAGIC = b"\x80"  # protocol 2+ pickles start with PROTO opcode 0x80
ZIP_MAGIC = b"PK\x03\x04"


@dataclass
class Artifact:
    bucket: str
    key: str
    path: str
    size: int
    sha256: str
    header: bytes = field(default=b"", repr=False)

    @classmethod
    def from_file(cls, bucket: str, key: str, path: str, size: int, sha256: str) -> "Artifact":
        with open(path, "rb") as f:
            header = f.read(16)
        return cls(bucket=bucket, key=key, path=path, size=size, sha256=sha256, header=header)

    @property
    def filename(self) -> str:
        return self.key.rsplit("/", 1)[-1]

    @property
    def extension(self) -> str:
        name = self.filename
        return "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""

    @property
    def is_zip(self) -> bool:
        return self.header.startswith(ZIP_MAGIC)

    @property
    def looks_like_raw_pickle(self) -> bool:
        return self.header.startswith(PICKLE_PROTO_MAGIC)

    @cached_property
    def zip_pickle_members(self) -> list[str]:
        """Pickle members inside a zip — e.g. 'archive/data.pkl' in a
        PyTorch >= 1.6 checkpoint written by torch.save."""
        if not self.is_zip:
            return []
        try:
            with zipfile.ZipFile(self.path) as zf:
                return [n for n in zf.namelist() if n.endswith(".pkl")]
        except zipfile.BadZipFile:
            return []

    def read_text(self, limit: int = 1024 * 1024) -> str:
        with open(self.path, "rb") as f:
            return f.read(limit).decode("utf-8", errors="ignore")

    def cleanup(self) -> None:
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass
