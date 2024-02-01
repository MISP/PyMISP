#!/usr/bin/env python

from __future__ import annotations

import logging

from io import BytesIO
from typing import Any, TYPE_CHECKING

from ..exceptions import MISPObjectException
logger = logging.getLogger('pymisp')

try:
    import lief
    import lief.logging
    lief.logging.disable()
    HAS_LIEF = True

    from .peobject import make_pe_objects
    from .elfobject import make_elf_objects
    from .machoobject import make_macho_objects
    from . import FileObject

except AttributeError:
    HAS_LIEF = False
    logger.critical('You need lief >= 0.11.0. The quick and dirty fix is: pip3 install --force pymisp[fileobjects]')

except ImportError:
    HAS_LIEF = False

if TYPE_CHECKING:
    from . import PEObject, ELFObject, MachOObject, PESectionObject, ELFSectionObject, MachOSectionObject


class FileTypeNotImplemented(MISPObjectException):
    pass


def make_binary_objects(filepath: str | None = None,
                        pseudofile: BytesIO | bytes | None = None,
                        filename: str | None = None,
                        standalone: bool = True,
                        default_attributes_parameters: dict[str, Any] = {}) -> tuple[FileObject, PEObject | ELFObject | MachOObject | None, list[PESectionObject] | list[ELFSectionObject] | list[MachOSectionObject]]:
    misp_file = FileObject(filepath=filepath, pseudofile=pseudofile, filename=filename,
                           standalone=standalone, default_attributes_parameters=default_attributes_parameters)
    if HAS_LIEF and (filepath or pseudofile):
        if filepath:
            lief_parsed = lief.parse(filepath=filepath)
        elif pseudofile:
            if isinstance(pseudofile, bytes):
                lief_parsed = lief.parse(raw=pseudofile)
            else:  # BytesIO
                lief_parsed = lief.parse(obj=pseudofile)
        else:
            logger.critical('You need either a filepath, or a pseudofile and a filename.')
            lief_parsed = None

        if isinstance(lief_parsed, lief.lief_errors):
            logger.warning('Got an error parsing the file: {lief_parsed}')
        elif isinstance(lief_parsed, lief.PE.Binary):
            return make_pe_objects(lief_parsed, misp_file, standalone, default_attributes_parameters)
        elif isinstance(lief_parsed, lief.ELF.Binary):
            return make_elf_objects(lief_parsed, misp_file, standalone, default_attributes_parameters)
        elif isinstance(lief_parsed, lief.MachO.Binary):
            return make_macho_objects(lief_parsed, misp_file, standalone, default_attributes_parameters)
        else:
            logger.critical(f'Unexpected type from lief: {type(lief_parsed)}')
    if not HAS_LIEF:
        logger.warning('Please install lief, documentation here: https://github.com/lief-project/LIEF')
    return misp_file, None, []
