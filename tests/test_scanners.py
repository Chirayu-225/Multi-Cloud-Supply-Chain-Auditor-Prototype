import os
import pickle
import tempfile
import zipfile
from collections import OrderedDict

import pytest

from auditor.artifact import Artifact
from auditor.pipeline import run_scanners
from auditor.risk import aggregate
from auditor.scanners import default_scanners
from auditor.scanners.base import Finding
from auditor.scanners.cross_source import CrossSourceScanner
from auditor.scanners.pickle_opcodes import PickleImportScanner
from auditor.scanners.serialization import SerializationFormatScanner
from auditor.scanners.typosquat import TyposquatScanner, nearest_popular
from auditor import security


class Evil:
    def __reduce__(self):
        return (os.system, ("echo pwned",))  # never executed: we only dump


def make_artifact(tmp_path, name: str, data: bytes) -> Artifact:
    path = tmp_path / name
    path.write_bytes(data)
    import hashlib
    return Artifact.from_file("supply-chain-artifacts", name, str(path), len(data), hashlib.sha256(data).hexdigest())


def zip_with(member: str, data: bytes) -> bytes:
    buf = tempfile.SpooledTemporaryFile()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(member, data)
    buf.seek(0)
    return buf.read()


@pytest.mark.parametrize("protocol", [2, 4, 5])
def test_malicious_pickle_flagged_any_protocol(tmp_path, protocol):
    art = make_artifact(tmp_path, "model.pkl", pickle.dumps(Evil(), protocol=protocol))
    finding = PickleImportScanner().scan(art)
    assert finding.risky and finding.weight == 80
    assert "system" in finding.detail


def test_protocol0_pickle_without_magic_is_detected(tmp_path):
    art = make_artifact(tmp_path, "model.pkl", pickle.dumps(Evil(), protocol=0))
    assert not art.looks_like_raw_pickle
    assert PickleImportScanner().scan(art).weight == 80


def test_renamed_pickle_is_still_scanned(tmp_path):
    art = make_artifact(tmp_path, "notes.txt", pickle.dumps(Evil(), protocol=4))
    assert PickleImportScanner().applies(art)


def test_benign_pickle_is_clean(tmp_path):
    art = make_artifact(tmp_path, "weights.pkl", pickle.dumps(OrderedDict(a=[1, 2, 3]), protocol=4))
    assert not PickleImportScanner().scan(art).risky


def test_unknown_import_is_medium(tmp_path):
    art = make_artifact(tmp_path, "x.pkl", pickle.dumps(tempfile.TemporaryDirectory, protocol=4))
    finding = PickleImportScanner().scan(art)
    assert finding.risky and finding.weight == 30


def test_pytorch_zip_checkpoint(tmp_path):
    clean = make_artifact(tmp_path, "model.pt", zip_with("archive/data.pkl", pickle.dumps(OrderedDict(w=1), protocol=2)))
    assert clean.zip_pickle_members == ["archive/data.pkl"]
    assert SerializationFormatScanner().scan(clean).weight == 40
    assert not PickleImportScanner().scan(clean).risky

    evil = make_artifact(tmp_path, "evil.pt", zip_with("archive/data.pkl", pickle.dumps(Evil(), protocol=2)))
    assert PickleImportScanner().scan(evil).weight == 80


def test_garbage_with_pickle_extension(tmp_path):
    art = make_artifact(tmp_path, "broken.pkl", b"\x80\x04garbage-not-a-pickle")
    assert PickleImportScanner().scan(art).weight == 20


def test_safetensors_is_safe(tmp_path):
    art = make_artifact(tmp_path, "model.safetensors", b"\x08\x00\x00\x00\x00\x00\x00\x00{}      ")
    assert not SerializationFormatScanner().scan(art).risky
    assert not PickleImportScanner().applies(art)


def test_typosquat_true_and_false_positives(tmp_path):
    reqs = b"""# comment
tensrflow==2.15
reqeusts>=2
spacy==3.7
numba~=0.59
scikit_learn==1.4
uvicorn[standard]==0.30
-r other.txt
"""
    art = make_artifact(tmp_path, "requirements.txt", reqs)
    scanner = TyposquatScanner()
    assert scanner.applies(art)
    finding = scanner.scan(art)
    assert "tensrflow" in finding.detail and "reqeusts" in finding.detail
    assert "spacy" not in finding.detail and "numba" not in finding.detail
    assert "scikit" not in finding.detail and "uvicorn" not in finding.detail


def test_typosquat_only_requirements_files(tmp_path):
    assert not TyposquatScanner().applies(make_artifact(tmp_path, "notes.txt", b"tensrflow"))
    assert TyposquatScanner().applies(make_artifact(tmp_path, "a1b2c3d4e5f6-requirements.txt", b"x"))
    assert TyposquatScanner().applies(make_artifact(tmp_path, "requirements-dev.txt", b"x"))
    assert not TyposquatScanner().applies(make_artifact(tmp_path, "myrequirements.txt", b"x"))
    assert nearest_popular("numpi") == "numpy"


def test_cross_source(tmp_path):
    art = make_artifact(tmp_path, "m.safetensors", b"abc")
    match = CrossSourceScanner({"m.safetensors": ("r", "f")}, resolver=lambda r, f: art.sha256)
    mismatch = CrossSourceScanner({"m.safetensors": ("r", "f")}, resolver=lambda r, f: "0" * 64)
    assert not match.scan(art).risky
    assert mismatch.scan(art).weight == 70


def test_risk_aggregation_capped():
    findings = [Finding("a", True, 80, ""), Finding("b", True, 40, ""), Finding("c", True, 70, "")]
    assert aggregate(findings) == 100
    assert aggregate([Finding("a", True, 40, ""), Finding("b", True, 20, "")]) == 45
    assert aggregate([Finding("a", False, 0, "")]) == 0


def test_full_pipeline_on_evil_checkpoint(tmp_path):
    art = make_artifact(tmp_path, "evil.pt", zip_with("archive/data.pkl", pickle.dumps(Evil(), protocol=2)))
    score, findings = run_scanners(default_scanners(), art)
    assert score == 90  # 80 + 40 // 4
    assert {f.check for f in findings} == {"serialization_format", "pickle_imports"}


def test_signature_verification():
    body = b'{"job_id": 1}'
    sig = security.sign("s3cret", "1000", body)
    assert security.verify("s3cret", "1000", sig, body, now=1000)
    assert not security.verify("s3cret", "1000", sig, body + b"x", now=1000)
    assert not security.verify("wrong", "1000", sig, body, now=1000)
    assert not security.verify("s3cret", "1000", sig, body, now=5000)  # replay window
    assert not security.verify("s3cret", None, None, body)
