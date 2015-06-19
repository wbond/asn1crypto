# coding: utf-8

"""
Exceptions for help trying to use cffi, then ctypes for shared library access
"""

from __future__ import unicode_literals



class LibraryNotFoundError(Exception):

    """
    An exception when trying to find a shared library
    """

    pass


class FFIEngineError(Exception):

    """
    An exception when trying to instantiate ctypes or cffi
    """

    pass
