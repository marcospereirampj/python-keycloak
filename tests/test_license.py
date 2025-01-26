"""Tests for license."""

import os
import pathlib


def test_license_present() -> None:
    """Test that the MIT license is present in the header of each module file."""
    for path, _, files in os.walk("src/keycloak"):
        for _file in files:
            if _file.endswith(".py"):
                with pathlib.Path(pathlib.Path(path) / _file).open("r") as fp:
                    content = fp.read()
                assert content.startswith(
                    "#\n# The MIT License (MIT)\n#\n#",
                )
