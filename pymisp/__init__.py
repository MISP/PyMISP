import logging
import sys
import warnings

import importlib.metadata

logger = logging.getLogger(__name__)

__version__ = importlib.metadata.version("pymisp")


def warning_2024():
    if sys.version_info < (3, 10):
        warnings.warn("""
As our baseline system is the latest Ubuntu LTS, and Ubuntu LTS 22.04 has Python 3.10 available,
we will officially deprecate python versions below 3.10 on January 1st 2024.
**Please update your codebase.**""", DeprecationWarning, stacklevel=3)


everything_broken = '''Unknown error: the response is not in JSON.
Something is broken server-side, please send us everything that follows (careful with the auth key):
Request headers:
{}
Request body:
{}
Response (if any):
{}'''


try:
    warning_2024()
    from .exceptions import (PyMISPError, NewEventError, NewAttributeError, MissingDependency, NoURL, NoKey, # noqa
                             InvalidMISPObject, UnknownMISPObjectTemplate, PyMISPInvalidFormat, MISPServerError, PyMISPNotImplementedYet, PyMISPUnexpectedResponse, PyMISPEmptyResponse)
    from .abstract import AbstractMISP, MISPEncode, pymisp_json_default, MISPTag, Distribution, ThreatLevel, Analysis # noqa
    from .mispevent import (MISPEvent, MISPAttribute, MISPObjectReference, MISPObjectAttribute, MISPObject, MISPUser, # noqa
                            MISPOrganisation, MISPSighting, MISPLog, MISPShadowAttribute, MISPWarninglist, MISPTaxonomy,
                            MISPNoticelist, MISPObjectTemplate, MISPSharingGroup, MISPRole, MISPServer, MISPFeed,
                            MISPEventDelegation, MISPUserSetting, MISPInbox, MISPEventBlocklist, MISPOrganisationBlocklist,
                            MISPEventReport, MISPCorrelationExclusion, MISPDecayingModel, MISPGalaxy, MISPGalaxyCluster,
                            MISPGalaxyClusterElement, MISPGalaxyClusterRelation)
    from .tools import AbstractMISPObjectGenerator  # noqa
    from .tools import Neo4j  # noqa
    from .tools import stix  # noqa
    from .tools import openioc  # noqa
    from .tools import ext_lookups  # noqa
    from .tools import update_objects  # noqa

    from .api import PyMISP, register_user  # noqa
    from .api import PyMISP as ExpandedPyMISP  # noqa
    from .tools import load_warninglists  # noqa
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
