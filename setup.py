"""Build lepy."""

import os
import subprocess

from setuptools import setup
from setuptools.command.build_py import build_py as build_py_orig


def build_go_library():
    """Build the lego application into a shared .so file."""
    os.chdir("src/lepy")
    subprocess.check_call(["go", "build", "-o", "lego.so", "-buildmode=c-shared", "lego-stub.go"])
    os.chdir("../..")


class build_py(build_py_orig):  # noqa: N801
    """Build requirements for the package."""

    def run(self):
        """Build modules, packages, and copy data files to build directory."""
        build_go_library()
        super().run()


setup(cmdclass={"build_py": build_py})
