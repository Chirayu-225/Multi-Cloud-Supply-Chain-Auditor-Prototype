"""
Serialization format check. Pickle-based formats (including PyTorch
checkpoints, which are zip archives with a pickle inside) can execute
code on load; safetensors / ONNX only hold tensor data.
"""

from ..artifact import Artifact
from .base import Finding, Scanner
from .pickle_utils import PICKLE_EXTENSIONS, is_pickle_candidate

SAFE_EXTENSIONS = {".safetensors", ".onnx", ".gguf"}


class SerializationFormatScanner(Scanner):
    name = "serialization_format"

    def applies(self, artifact: Artifact) -> bool:
        return artifact.extension in SAFE_EXTENSIONS or is_pickle_candidate(artifact)

    def scan(self, artifact: Artifact) -> Finding:
        if artifact.zip_pickle_members:
            return self.flag(40, "PyTorch-style zip checkpoint containing pickle data — can execute code on load. Recommend converting to safetensors.")
        if artifact.looks_like_raw_pickle:
            return self.flag(40, "Pickle serialization — can execute arbitrary code on load. Recommend converting to safetensors.")
        if artifact.extension in SAFE_EXTENSIONS:
            return self.ok(f"Tensor-only format ({artifact.extension})")
        if artifact.extension in PICKLE_EXTENSIONS:
            # Protocol 0/1 pickles have no magic header; the opcode
            # scanner will tell us whether it really parses as pickle.
            return self.flag(15, f"Pickle-style extension ({artifact.extension}) without a recognised header — possibly an old-protocol pickle")
        return self.ok("No pickle content detected")
