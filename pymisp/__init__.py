__version__ = '2.4.82'
import sys
import logging
logger = logging.getLogger(__name__)
FORMAT = "%(levelname)s [%(filename)s:%(lineno)s - %(funcName)s() ] %(message)s"
logging.basicConfig(stream=sys.stderr, level=logging.WARNING, format=FORMAT)

try:
    from .exceptions import PyMISPError, NewEventError, NewAttributeError, MissingDependency, NoURL, NoKey, InvalidMISPObject, UnknownMISPObjectTemplate  # noqa
    from .api import PyMISP  # noqa
    from .abstract import AbstractMISP, MISPEncode  # noqa
    from .mispevent import MISPEvent, MISPAttribute, MISPObjectReference, MISPObjectAttribute, MISPObject  # noqa
    from .tools import AbstractMISPObjectGenerator  # noqa
    from .tools import Neo4j  # noqa
    from .tools import stix  # noqa
    from .tools import openioc  # noqa
    logger.debug('pymisp loaded properly')
except ImportError as e:
    logger.warning('Unable to load pymisp properly: {}'.format(e))
