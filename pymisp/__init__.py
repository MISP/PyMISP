__version__ = '2.4.85'
import sys
import logging
import functools
import warnings

logger = logging.getLogger(__name__)
FORMAT = "%(levelname)s [%(filename)s:%(lineno)s - %(funcName)s() ] %(message)s"
logging.basicConfig(stream=sys.stderr, level=logging.WARNING, format=FORMAT)


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
    from .exceptions import PyMISPError, NewEventError, NewAttributeError, MissingDependency, NoURL, NoKey, InvalidMISPObject, UnknownMISPObjectTemplate, PyMISPInvalidFormat  # noqa
    from .api import PyMISP  # noqa
    from .abstract import AbstractMISP, MISPEncode, MISPTag  # noqa
    from .mispevent import MISPEvent, MISPAttribute, MISPObjectReference, MISPObjectAttribute, MISPObject, MISPUser, MISPOrganisation, MISPSighting   # noqa
    from .tools import AbstractMISPObjectGenerator  # noqa
    from .tools import Neo4j  # noqa
    from .tools import stix  # noqa
    from .tools import openioc  # noqa
    logger.debug('pymisp loaded properly')
except ImportError as e:
    logger.warning('Unable to load pymisp properly: {}'.format(e))
