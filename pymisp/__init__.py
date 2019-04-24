__version__ = '2.4.106'
import logging
import functools
import warnings
import sys

FORMAT = "%(levelname)s [%(filename)s:%(lineno)s - %(funcName)s() ] %(message)s"
formatter = logging.Formatter(FORMAT)
default_handler = logging.StreamHandler()
default_handler.setFormatter(formatter)

logger = logging.getLogger(__name__)
logger.addHandler(default_handler)
logger.setLevel(logging.WARNING)


def deprecated(func):
    '''This is a decorator which can be used to mark functions
    as deprecated. It will result in a warning being emitted
    when the function is used.'''

    @functools.wraps(func)
    def new_func(*args, **kwargs):
        warnings.showwarning(
            "Call to deprecated function {}.".format(func.__name__),
            category=DeprecationWarning,
            filename=func.__code__.co_filename,
            lineno=func.__code__.co_firstlineno + 1
        )
        return func(*args, **kwargs)
    return new_func


try:
    from .exceptions import PyMISPError, NewEventError, NewAttributeError, MissingDependency, NoURL, NoKey, InvalidMISPObject, UnknownMISPObjectTemplate, PyMISPInvalidFormat, MISPServerError, PyMISPNotImplementedYet, PyMISPUnexpectedResponse, PyMISPEmptyResponse  # noqa
    from .api import PyMISP  # noqa
    from .abstract import AbstractMISP, MISPEncode, MISPTag, Distribution, ThreatLevel, Analysis  # noqa
    from .mispevent import MISPEvent, MISPAttribute, MISPObjectReference, MISPObjectAttribute, MISPObject, MISPUser, MISPOrganisation, MISPSighting, MISPLog, MISPShadowAttribute  # noqa
    from .tools import AbstractMISPObjectGenerator  # noqa
    from .tools import Neo4j  # noqa
    from .tools import stix  # noqa
    from .tools import openioc  # noqa
    from .tools import load_warninglists  # noqa
    from .tools import ext_lookups  # noqa

    if sys.version_info >= (3, 6):
        # Let's not bother with old python
        try:
            from .tools import reportlab_generator  # noqa
        except ImportError:
            # FIXME: The import should not raise an exception if reportlab isn't installed
            pass
        except NameError:
            # FIXME: The import should not raise an exception if reportlab isn't installed
            pass
    if sys.version_info >= (3, 6):
        from .aping import ExpandedPyMISP  # noqa
    logger.debug('pymisp loaded properly')
except ImportError as e:
    logger.warning('Unable to load pymisp properly: {}'.format(e))
