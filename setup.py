"""Build pylego."""

import os
import subprocess

from setuptools import setup
from setuptools.command.build_py import build_py as build_py_orig


def build_go_library():
    """Build the lego application into a shared .so file."""
    os.chdir("src/pylego")
    subprocess.check_call(["go", "build", "-o", "lego.so", "-buildmode=c-shared", "lego.go"])
    os.chdir("../..")


class BuildPy(build_py_orig):
    """Build requirements for the package."""

    def run(self):
        """Build modules, packages, and copy data files to build directory."""
        build_go_library()
        super().run()


setup(cmdclass={"build_py": BuildPy})
