__version__ = '2.4.111.1'
import logging
import warnings
import sys

FORMAT = "%(levelname)s [%(filename)s:%(lineno)s - %(funcName)s() ] %(message)s"
formatter = logging.Formatter(FORMAT)
default_handler = logging.StreamHandler()
default_handler.setFormatter(formatter)

logger = logging.getLogger(__name__)
logger.addHandler(default_handler)
logger.setLevel(logging.WARNING)


def warning_2020():

    if sys.version_info < (3, 6):
        warnings.warn("""
Python 2.7 is officially end of life the 2020-01-01. For this occasion,
we decided to review which versions of Python we support and our conclusion
is to only support python 3.6+ starting the 2020-01-01.

Every version of pymisp released after the 2020-01-01 will fail if the
python interpreter is prior to python 3.6.

**Please update your codebase.**""", DeprecationWarning, stacklevel=3)


try:
    warning_2020()
    from .exceptions import PyMISPError, NewEventError, NewAttributeError, MissingDependency, NoURL, NoKey, InvalidMISPObject, UnknownMISPObjectTemplate, PyMISPInvalidFormat, MISPServerError, PyMISPNotImplementedYet, PyMISPUnexpectedResponse, PyMISPEmptyResponse  # noqa
    from .api import PyMISP  # noqa
    from .abstract import AbstractMISP, MISPEncode, MISPTag, Distribution, ThreatLevel, Analysis  # noqa
    from .mispevent import MISPEvent, MISPAttribute, MISPObjectReference, MISPObjectAttribute, MISPObject, MISPUser, MISPOrganisation, MISPSighting, MISPLog, MISPShadowAttribute, MISPWarninglist, MISPTaxonomy, MISPNoticelist, MISPObjectTemplate, MISPSharingGroup, MISPRole, MISPServer, MISPFeed # noqa
    from .tools import AbstractMISPObjectGenerator  # noqa
    from .tools import Neo4j  # noqa
    from .tools import stix  # noqa
    from .tools import openioc  # noqa
    from .tools import load_warninglists  # noqa
    from .tools import ext_lookups  # noqa

    if sys.version_info >= (3, 6):
        from .aping import ExpandedPyMISP  # noqa
        # Let's not bother with old python
        try:
            from .tools import reportlab_generator  # noqa
        except ImportError:
            # FIXME: The import should not raise an exception if reportlab isn't installed
            pass
        except NameError:
            # FIXME: The import should not raise an exception if reportlab isn't installed
            pass
    logger.debug('pymisp loaded properly')
except ImportError as e:
    logger.warning('Unable to load pymisp properly: {}'.format(e))
