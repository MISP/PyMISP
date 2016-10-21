#!/usr/bin/env python
# -*- coding: utf-8 -*-

class PyMISPError(Exception):
    def __init__(self, message):
        super(PyMISPError, self).__init__(message)
        self.message = message


class NewEventError(PyMISPError):
    pass


class NewAttributeError(PyMISPError):
    pass


class SearchError(PyMISPError):
    pass


class MissingDependency(PyMISPError):
    pass


class NoURL(PyMISPError):
    pass


class NoKey(PyMISPError):
    pass
