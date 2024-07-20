from __future__ import annotations


class PyMISPError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class NewEventError(PyMISPError):
    pass


class UpdateEventError(PyMISPError):
    pass


class NewAttributeError(PyMISPError):
    pass


class NewEventReportError(PyMISPError):
    pass


class NewAnalystDataError(PyMISPError):
    pass


class NewNoteError(PyMISPError):
    pass


class NewOpinionError(PyMISPError):
    pass


class NewRelationshipError(PyMISPError):
    pass


class UpdateAttributeError(PyMISPError):
    pass


class NewGalaxyClusterError(PyMISPError):
    pass


class NewGalaxyClusterRelationError(PyMISPError):
    pass


class SearchError(PyMISPError):
    pass


class MissingDependency(PyMISPError):
    pass


class NoURL(PyMISPError):
    pass


class NoKey(PyMISPError):
    pass


class MISPAttributeException(PyMISPError):
    """A base class for attribute specific exceptions"""

class MISPObjectException(PyMISPError):
    """A base class for object specific exceptions"""


class InvalidMISPAttribute(MISPAttributeException):
    """Exception raised when an attribute doesn't respect the constraints in the definition"""

class InvalidMISPObjectAttribute(MISPAttributeException):
    """Exception raised when an object attribute doesn't respect the constraints in the definition"""

class InvalidMISPObject(MISPObjectException):
    """Exception raised when an object doesn't respect the constraints in the definition"""


class UnknownMISPObjectTemplate(MISPObjectException):
    """Exception raised when the template is unknown"""



class InvalidMISPGalaxy(PyMISPError):
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
