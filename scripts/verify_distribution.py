"""Check built package metadata before artifacts reach the publishing job."""

import argparse
from email.parser import BytesParser
import os
from pathlib import Path, PurePosixPath
import tarfile
import zipfile


def verify_distributions(directory, release_tag=None):
    directory = Path(directory)
    wheels = list(directory.glob("*.whl"))
    sources = list(directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sources) != 1:
        raise ValueError("Expected exactly one wheel and one source distribution")

    with zipfile.ZipFile(wheels[0]) as wheel:
        metadata = [
            name for name in wheel.namelist() if name.endswith(".dist-info/METADATA")
        ]
        if len(metadata) != 1:
            raise ValueError("Expected exactly one wheel METADATA")
        wheel_headers = BytesParser().parsebytes(wheel.read(metadata[0]))

    with tarfile.open(sources[0], "r:gz") as source:
        metadata = [
            member for member in source.getmembers()
            if member.isfile()
            and len(PurePosixPath(member.name).parts) == 2
            and PurePosixPath(member.name).name == "PKG-INFO"
        ]
        if len(metadata) != 1:
            raise ValueError("Expected exactly one top-level sdist PKG-INFO")
        with source.extractfile(metadata[0]) as stream:
            source_headers = BytesParser().parse(stream)

    version = wheel_headers.get("Version")
    if not version or source_headers.get("Version") != version:
        raise ValueError("Wheel and sdist versions must match and be nonempty")
    if wheel_headers.get("Name") != "keylocker" or source_headers.get("Name") != "keylocker":
        raise ValueError("Both distributions must belong to keylocker")
    if release_tag and (
        not release_tag.startswith("v") or version != release_tag[1:]
    ):
        raise ValueError(f"Built version {version!r} does not match tag {release_tag!r}")
    return version


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    version = verify_distributions(args.directory, os.environ.get("RELEASE_TAG"))
    print(f"Verified keylocker wheel and sdist: {version}")
