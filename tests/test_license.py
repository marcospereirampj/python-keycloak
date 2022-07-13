"""Tests for license."""
import os


def test_license_present():
    """Test that the MIT license is present in the header of each module file."""
    for path, _, files in os.walk("src/keycloak"):
        for _file in files:
            if _file.endswith(".py"):
                with open(os.path.join(path, _file), "r") as fp:
                    content = fp.read()
                assert content.startswith(
                    "# -*- coding: utf-8 -*-\n#\n# The MIT License (MIT)\n#\n#"
                )
