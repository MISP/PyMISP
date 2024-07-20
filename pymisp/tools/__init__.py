from __future__ import annotations

from .vtreportobject import VTReportObject  # noqa
from .neo4j import Neo4j  # noqa
from .fileobject import FileObject  # noqa
from .create_misp_object import make_binary_objects  # noqa
from .abstractgenerator import AbstractMISPObjectGenerator  # noqa
from .genericgenerator import GenericObjectGenerator  # noqa
from .openioc import load_openioc, load_openioc_file  # noqa
from .sbsignatureobject import SBSignatureObject  # noqa
from .fail2banobject import Fail2BanObject  # noqa
from .domainipobject import DomainIPObject  # noqa
from .asnobject import ASNObject  # noqa
from .geolocationobject import GeolocationObject  # noqa
from .git_vuln_finder_object import GitVulnFinderObject  # noqa

from .vehicleobject import VehicleObject  # noqa
from .csvloader import CSVLoader  # noqa
from .sshauthkeyobject import SSHAuthorizedKeysObject  # noqa
from .feed import feed_meta_generator  # noqa
from .update_objects import update_objects  # noqa

try:
    from .emailobject import EMailObject  # noqa
except ImportError:
    # Requires 'extract_msg', "RTFDE", "oletools"
    # pymisp needs to be installed with the email parameter
    pass

try:
    from .urlobject import URLObject  # noqa
except ImportError:
    # Requires pyfaup, optional dependency [url]
    pass
except OSError:
    # faup required liblua-5.3
    pass

try:
    from .peobject import PEObject, PESectionObject  # noqa
    from .elfobject import ELFObject, ELFSectionObject  # noqa
    from .machoobject import MachOObject, MachOSectionObject  # noqa
except ImportError:
    # Requires lief, optional [fileobjects]
    pass

__all__ = ['VTReportObject', 'Neo4j', 'FileObject', 'make_binary_objects',
           'AbstractMISPObjectGenerator', 'GenericObjectGenerator',
           'load_openioc', 'load_openioc_file', 'SBSignatureObject',
           'Fail2BanObject', 'DomainIPObject', 'ASNObject', 'GeolocationObject',
           'GitVulnFinderObject', 'VehicleObject', 'CSVLoader',
           'SSHAuthorizedKeysObject', 'feed_meta_generator', 'update_objects',
           'EMailObject', 'URLObject', 'PEObject', 'PESectionObject', 'ELFObject',
           'ELFSectionObject', 'MachOObject', 'MachOSectionObject'
           ]
