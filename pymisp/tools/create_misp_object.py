#!/usr/bin/env python
# -*- coding: utf-8 -*-

from io import BytesIO

from . import FileObject
from ..exceptions import MISPObjectException
import logging
from typing import Optional

logger = logging.getLogger('pymisp')

try:
    import lief
    lief.logging.disable()
    HAS_LIEF = True

    from .peobject import make_pe_objects
    from .elfobject import make_elf_objects
    from .machoobject import make_macho_objects

except AttributeError:
    HAS_LIEF = False
    logger.critical('You need lief >= 0.11.0. The quick and dirty fix is: pip3 install --force pymisp[fileobjects]')

except ImportError:
    HAS_LIEF = False


class FileTypeNotImplemented(MISPObjectException):
    pass


def make_binary_objects(filepath: Optional[str] = None, pseudofile: Optional[BytesIO] = None, filename: Optional[str] = None, standalone: bool = True, default_attributes_parameters: dict = {}):
    misp_file = FileObject(filepath=filepath, pseudofile=pseudofile, filename=filename,
                           standalone=standalone, default_attributes_parameters=default_attributes_parameters)
    if HAS_LIEF and (filepath or (pseudofile and filename)):
        if filepath:
            lief_parsed = lief.parse(filepath=filepath)
        elif pseudofile and filename:
            lief_parsed = lief.parse(raw=pseudofile.getvalue(), name=filename)
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
