"""
Cross-source tamper check: compares the stored copy's SHA-256 with the
hash Hugging Face publishes for the same file. A mismatch means one
copy was modified — the pattern behind compromised-mirror attacks.

Only LFS-tracked files have a comparable content SHA-256 on the Hub;
small git-tracked files expose a git blob SHA-1, which hashes something
else, so those are skipped rather than reported as mismatches.
"""

from huggingface_hub import HfApi

from ..artifact import Artifact
from .base import Finding, Scanner

# "storage_object_key": ("hf_repo_id", "hf_filename")
SOURCE_MAP: dict[str, tuple[str, str]] = {
    "hf_reference_test/model.safetensors": ("hf-internal-testing/tiny-random-bert-safetensors", "model.safetensors"),
}


def reference_sha256(repo_id: str, filename: str) -> str | None:
    info = HfApi().model_info(repo_id, files_metadata=True)
    sibling = next((s for s in info.siblings if s.rfilename == filename), None)
    lfs = getattr(sibling, "lfs", None) if sibling else None
    if not lfs:
        return None
    return lfs.get("sha256") if isinstance(lfs, dict) else getattr(lfs, "sha256", None)


class CrossSourceScanner(Scanner):
    name = "cross_source_diff"

    def __init__(self, source_map: dict[str, tuple[str, str]] | None = None, resolver=reference_sha256):
        self.source_map = SOURCE_MAP if source_map is None else source_map
        self.resolver = resolver

    def applies(self, artifact: Artifact) -> bool:
        return artifact.key in self.source_map

    def scan(self, artifact: Artifact) -> Finding:
        repo_id, filename = self.source_map[artifact.key]
        try:
            expected = self.resolver(repo_id, filename)
        except Exception as e:
            return self.flag(15, f"Could not fetch Hugging Face reference hash for {repo_id}/{filename}: {str(e)[:150]}")
        if not expected:
            return self.ok(f"No comparable SHA-256 on the Hub for {repo_id}/{filename} (not LFS-tracked) — skipped")
        if expected != artifact.sha256:
            return self.flag(70, f"Hash mismatch with Hugging Face source {repo_id}/{filename} — possible tampering")
        return self.ok(f"SHA-256 matches {repo_id}/{filename}")
