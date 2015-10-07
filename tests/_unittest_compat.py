# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys
import unittest


_non_local = {'patched': False}


def patch():
    if not sys.version_info < (2, 7):
        return

    if _non_local['patched']:
        return

    unittest.TestCase.assertIsInstance = _assert_is_instance
    unittest.TestCase.assertRaises = _assert_raises
    _non_local['patched'] = True


def _assert_is_instance(self, obj, cls, msg=None):
    """Same as self.assertTrue(isinstance(obj, cls)), with a nicer
    default message."""
    if not isinstance(obj, cls):
        if not msg:
            msg = '%s is not an instance of %r' % (obj, cls)
        self.fail(msg)


def _assert_raises(self, excClass, callableObj=None, *args, **kwargs):  # noqa
    context = _AssertRaisesContext(excClass, self)
    if callableObj is None:
        return context
    with context:
        callableObj(*args, **kwargs)


class _AssertRaisesContext(object):
    """A context manager used to implement TestCase.assertRaises* methods."""

    def __init__(self, expected, test_case, expected_regexp=None):
        self.expected = expected
        self.failureException = test_case.failureException
        self.expected_regexp = expected_regexp

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        if exc_type is None:
            try:
                exc_name = self.expected.__name__
            except AttributeError:
                exc_name = str(self.expected)
            raise self.failureException(
                "{0} not raised".format(exc_name))
        if not issubclass(exc_type, self.expected):
            # let unexpected exceptions pass through
            return False
        self.exception = exc_value  # store for later retrieval
        if self.expected_regexp is None:
            return True

        expected_regexp = self.expected_regexp
        if not expected_regexp.search(str(exc_value)):
            raise self.failureException(
                '"%s" does not match "%s"' %
                (expected_regexp.pattern, str(exc_value))
            )
        return True
