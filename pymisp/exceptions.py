# -*- coding: utf-8 -*-


class PyMISPError(Exception):
    def __init__(self, message):
        super(PyMISPError, self).__init__(message)
        self.message = message


class NewEventError(PyMISPError):
    pass


class UpdateEventError(PyMISPError):
    pass


class NewAttributeError(PyMISPError):
    pass


class UpdateAttributeError(PyMISPError):
    pass


class SearchError(PyMISPError):
    pass


class MissingDependency(PyMISPError):
    pass


class NoURL(PyMISPError):
    pass


class NoKey(PyMISPError):
    pass


class MISPObjectException(PyMISPError):
    pass


class InvalidMISPObject(MISPObjectException):
    """Exception raised when an object doesn't respect the contrains in the definition"""
    pass


class UnknownMISPObjectTemplate(MISPObjectException):
    """Exception raised when the template is unknown"""
    pass


class PyMISPInvalidFormat(PyMISPError):
    pass


class MISPServerError(PyMISPError):
    pass


class PyMISPNotImplementedYet(PyMISPError):
    pass


class PyMISPUnexpectedResponse(PyMISPError):
    pass


class PyMISPEmptyResponse(PyMISPError):
    pass
