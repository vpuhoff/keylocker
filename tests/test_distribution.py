"""Regression tests for the release artifact/version gate."""

import io
import tarfile
import zipfile

import pytest

from scripts.verify_distribution import verify_distributions


def distributions(path, wheel_version="0.4.9", source_version="0.4.9", name="keylocker"):
    headers = f"Name: {name}\nVersion: {wheel_version}\n\n".encode()
    with zipfile.ZipFile(path / "package.whl", "w") as wheel:
        wheel.writestr("keylocker.dist-info/METADATA", headers)
    headers = f"Name: {name}\nVersion: {source_version}\n\n".encode()
    with tarfile.open(path / "package.tar.gz", "w:gz") as source:
        member = tarfile.TarInfo("keylocker/PKG-INFO")
        member.size = len(headers)
        source.addfile(member, io.BytesIO(headers))


def test_release_versions_match_tag(tmp_path):
    distributions(tmp_path)
    assert verify_distributions(tmp_path, "v0.4.9") == "0.4.9"


def test_branch_build_allows_development_version(tmp_path):
    distributions(tmp_path, "0.4.9.dev3+abc", "0.4.9.dev3+abc")
    assert verify_distributions(tmp_path) == "0.4.9.dev3+abc"


@pytest.mark.parametrize("tag", ["v0.4.8", "0.4.9"])
def test_reject_wrong_tag(tmp_path, tag):
    distributions(tmp_path)
    with pytest.raises(ValueError, match="does not match tag"):
        verify_distributions(tmp_path, tag)


def test_reject_mismatched_distributions(tmp_path):
    distributions(tmp_path, source_version="0.4.8")
    with pytest.raises(ValueError, match="versions must match"):
        verify_distributions(tmp_path)


@pytest.mark.parametrize("missing", ["package.whl", "package.tar.gz"])
def test_require_both_distributions(tmp_path, missing):
    distributions(tmp_path)
    (tmp_path / missing).unlink()
    with pytest.raises(ValueError, match="exactly one wheel"):
        verify_distributions(tmp_path)


def test_reject_wrong_project(tmp_path):
    distributions(tmp_path, name="not-keylocker")
    with pytest.raises(ValueError, match="belong to keylocker"):
        verify_distributions(tmp_path)
