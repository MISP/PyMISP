#!/usr/bin/env python
# -*- coding: utf-8 -*-

from io import BytesIO

from . import FileObject
from ..exceptions import MISPObjectException
import logging
from typing import Optional

logger = logging.getLogger('pymisp')

try:
    import lief  # type: ignore
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
    logger.critical('You need lief >= 0.11.0. The quick and dirty fix is: pip3 install --force pymisp[fileobjects]')


class FileTypeNotImplemented(MISPObjectException):
    pass


def make_binary_objects(filepath: Optional[str] = None, pseudofile: Optional[BytesIO] = None, filename: Optional[str] = None, standalone: bool = True, default_attributes_parameters: dict = {}):
    misp_file = FileObject(filepath=filepath, pseudofile=pseudofile, filename=filename,
                           standalone=standalone, default_attributes_parameters=default_attributes_parameters)
    if HAS_LIEF and (filepath or (pseudofile and filename)):
        try:
            if filepath:
                lief_parsed = lief.parse(filepath=filepath)
            elif pseudofile and filename:
                lief_parsed = lief.parse(raw=pseudofile.getvalue(), name=filename)
            else:
                logger.critical('You need either a filepath, or a pseudofile and a filename.')
                lief_parsed = None
            if isinstance(lief_parsed, lief.PE.Binary):
                return make_pe_objects(lief_parsed, misp_file, standalone, default_attributes_parameters)
            elif isinstance(lief_parsed, lief.ELF.Binary):
                return make_elf_objects(lief_parsed, misp_file, standalone, default_attributes_parameters)
            elif isinstance(lief_parsed, lief.MachO.Binary):
                return make_macho_objects(lief_parsed, misp_file, standalone, default_attributes_parameters)
        except lief.bad_format as e:
            logger.warning('Bad format: {}'.format(e))
        except lief.bad_file as e:
            logger.warning('Bad file: {}'.format(e))
        except lief.conversion_error as e:
            logger.warning('Conversion file: {}'.format(e))
        except lief.builder_error as e:
            logger.warning('Builder file: {}'.format(e))
        except lief.parser_error as e:
            logger.warning('Parser error: {}'.format(e))
        except lief.integrity_error as e:
            logger.warning('Integrity error: {}'.format(e))
        except lief.pe_error as e:
            logger.warning('PE error: {}'.format(e))
        except lief.type_error as e:
            logger.warning('Type error: {}'.format(e))
        except lief.exception as e:
            logger.warning('Lief exception: {}'.format(e))
        except FileTypeNotImplemented as e:
            logger.warning(e)
    if not HAS_LIEF:
        logger.warning('Please install lief, documentation here: https://github.com/lief-project/LIEF')
    return misp_file, None, []
