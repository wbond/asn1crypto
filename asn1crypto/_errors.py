# coding: utf-8

"""
Helpers for creating exceptions. Exports the following items:

 - object_name()
"""

from __future__ import unicode_literals, division, absolute_import, print_function


def object_name(value):
    """
    :param value:
        A value to get the object name of

    :return:
        A unicode string of the object name
    """

    cls = value.__class__
    if cls.__module__ == 'builtins':
        return cls.__name__
    return '%s.%s' % (cls.__module__, cls.__name__)
