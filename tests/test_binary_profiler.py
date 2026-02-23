"""Tests for binary profiler (Layer 0)."""
import json
import pytest
from pathlib import Path

from src.intake.binary_profiler import BinaryProfiler, BinaryFormat, SourceLanguage


def test_profiler_missing_file():
    p = BinaryProfiler()
    with pytest.raises(FileNotFoundError):
        p.profile("/nonexistent/binary.exe")


def test_profiler_creates_profile_for_any_file(tmp_path):
    """Even a garbage file should produce a BinaryProfile (not crash)."""
    dummy = tmp_path / "dummy.bin"
    dummy.write_bytes(b"\x00" * 128)
    p = BinaryProfiler()
    profile = p.profile(str(dummy))
    assert profile.path == str(dummy)
    assert profile.format == BinaryFormat.UNKNOWN


def test_profile_serialises_to_json(tmp_path):
    dummy = tmp_path / "dummy.bin"
    dummy.write_bytes(b"\x00" * 64)
    p = BinaryProfiler()
    profile = p.profile(str(dummy))
    data = json.loads(profile.to_json())
    assert "format" in data
    assert "protection_level" in data
    assert "bypass_strategy" in data
