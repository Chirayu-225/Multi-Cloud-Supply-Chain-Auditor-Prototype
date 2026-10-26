"""
Typosquat check for requirements files: flags package names one or two
edits away from a popular package (e.g. "tensrflow", "reqeusts").

Fixes over the first version:
  * names normalized per PEP 503, so "Scikit_Learn" == "scikit-learn"
  * proper line parsing: comments, -r/-e options, extras, markers, ~= < !=
  * real packages that happen to look similar (spacy/scipy, numba/numpy)
    are allowlisted instead of being false positives
  * only requirements-style files are parsed, not every .txt
"""

import re

from ..artifact import Artifact
from .base import Finding, Scanner

POPULAR_PACKAGES = {
    "torch", "tensorflow", "keras", "jax", "numpy", "pandas", "scikit-learn",
    "scipy", "matplotlib", "seaborn", "pillow", "opencv-python", "transformers",
    "huggingface-hub", "datasets", "tokenizers", "accelerate", "safetensors",
    "onnx", "onnxruntime", "requests", "urllib3", "boto3", "botocore", "flask",
    "django", "fastapi", "pydantic", "uvicorn", "langchain", "openai",
    "anthropic", "tqdm", "pyyaml", "setuptools", "xgboost", "lightgbm",
}
# Legitimate packages within edit distance of a popular one.
KNOWN_LEGIT = {
    "spacy", "numba", "scipy", "numpy", "flax", "jaxlib", "torchx", "pandera",
    "keras-nlp", "boto", "pyyml", "dask", "fastapi-utils", "langsmith", "onnxsim",
}

NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
REQUIREMENTS_NAME_RE = re.compile(r"^requirements[\w.-]*\.(txt|in)$", re.IGNORECASE)


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        current = [i + 1]
        for j, cb in enumerate(b):
            current.append(min(previous[j + 1] + 1, current[j] + 1, previous[j] + (ca != cb)))
        previous = current
    return previous[-1]


def parse_requirement_names(text: str) -> list[str]:
    names = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = NAME_RE.match(line)
        if match:
            names.append(normalize(match.group(1)))
    return names


def nearest_popular(name: str) -> str | None:
    if name in POPULAR_PACKAGES or name in KNOWN_LEGIT:
        return None
    threshold = 1 if len(name) <= 6 else 2
    for legit in POPULAR_PACKAGES:
        if abs(len(name) - len(legit)) <= threshold and 0 < levenshtein(name, legit) <= threshold:
            return legit
    return None


class TyposquatScanner(Scanner):
    name = "typosquat_check"

    def applies(self, artifact: Artifact) -> bool:
        return bool(REQUIREMENTS_NAME_RE.match(artifact.filename))

    def scan(self, artifact: Artifact) -> Finding:
        suspicious = []
        for pkg in dict.fromkeys(parse_requirement_names(artifact.read_text())):
            target = nearest_popular(pkg)
            if target:
                suspicious.append(f"'{pkg}' looks like a typosquat of '{target}'")
        if suspicious:
            return self.flag(50, "; ".join(suspicious)[:600])
        return self.ok("No typosquat patterns found")
