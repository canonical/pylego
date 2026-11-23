"""Build pylego."""

import os
import subprocess

from setuptools import setup
from setuptools.command.bdist_wheel import bdist_wheel as bdist_wheel_orig
from setuptools.command.build_py import build_py as build_py_orig
from setuptools.dist import Distribution


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


class BinaryDistribution(Distribution):
    """Mark the package as platform-specific because it contains a Go shared library."""

    def has_ext_modules(self):
        """Return whether this distribution contains platform-specific code."""
        return True


class BDistWheel(bdist_wheel_orig):
    """Build a platform-specific wheel usable across supported Python 3 versions."""

    def get_tag(self):
        """Use a generic Python tag while retaining the current platform tag."""
        _, _, platform_tag = super().get_tag()
        return "py3", "none", platform_tag


setup(
    cmdclass={"build_py": BuildPy, "bdist_wheel": BDistWheel},
    distclass=BinaryDistribution,
)
