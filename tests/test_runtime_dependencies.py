"""Keep package metadata, Pipenv, and both requirements files consistent."""

import json
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
import pytest


ROOT = Path(__file__).resolve().parents[1]


def declared_requirements():
    with (ROOT / "pyproject.toml").open("rb") as source:
        project = tomllib.load(source)["project"]
    requirements = [Requirement(value) for value in project["dependencies"]]
    return {canonicalize_name(req.name): req.specifier for req in requirements}


def test_package_declares_all_direct_runtime_dependencies():
    assert set(declared_requirements()) == {"cryptography", "pyyaml"}


@pytest.mark.parametrize("path", ["requirements.txt", "keylocker/requirements.txt"])
def test_requirements_files_match_package_metadata(path):
    requirements = [
        Requirement(line.strip())
        for line in (ROOT / path).read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    actual = {canonicalize_name(req.name): req.specifier for req in requirements}
    assert len(actual) == len(requirements), "Duplicate runtime requirement"
    assert all(not req.extras and not req.marker and not req.url for req in requirements)
    assert actual == declared_requirements()


def test_pipfile_matches_package_metadata():
    with (ROOT / "Pipfile").open("rb") as source:
        packages = tomllib.load(source)["packages"]
    requirements = [Requirement(f"{name}{specifier}") for name, specifier in packages.items()]
    assert {
        canonicalize_name(req.name): req.specifier for req in requirements
    } == declared_requirements()


def test_lock_contains_compatible_runtime_versions():
    lock = json.loads((ROOT / "Pipfile.lock").read_text())
    for name, specifier in declared_requirements().items():
        assert lock["default"][name]["version"].removeprefix("==") in specifier


@pytest.mark.parametrize(
    "name,minimum,obsolete,next_breaking",
    [
        ("cryptography", "50.0.2", "44.0.1", "51.0.0"),
        ("pyyaml", "6.0.3", "5.0", "7.0"),
    ],
)
def test_supported_ranges_exclude_old_and_untested_versions(
    name, minimum, obsolete, next_breaking
):
    specifier = declared_requirements()[name]
    assert minimum in specifier
    assert obsolete not in specifier
    assert next_breaking not in specifier
