"""AWS library for Robot Framework"""

from importlib.metadata import version, PackageNotFoundError
from .AWS import AWS

# pylint: disable=invalid-name

try:
    __version__ = version("AWS")
except PackageNotFoundError:
    __version__ = "0.0.0"
