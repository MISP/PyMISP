#!/usr/bin/env python
# -*- coding: utf-8 -*-

import six

from . import FileObject, PEObject, ELFObject, MachOObject
from ..exceptions import MISPObjectException
import logging

logger = logging.getLogger('pymisp')

try:
    import lief
    from lief import Logger
    Logger.disable()
    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False


class FileTypeNotImplemented(MISPObjectException):
    pass


def make_pe_objects(lief_parsed, misp_file, standalone=True, default_attributes_parameters={}):
    pe_object = PEObject(parsed=lief_parsed, standalone=standalone, default_attributes_parameters=default_attributes_parameters)
    misp_file.add_reference(pe_object.uuid, 'included-in', 'PE indicators')
    pe_sections = []
    for s in pe_object.sections:
        pe_sections.append(s)
    return misp_file, pe_object, pe_sections


def make_elf_objects(lief_parsed, misp_file, standalone=True, default_attributes_parameters={}):
    elf_object = ELFObject(parsed=lief_parsed, standalone=standalone, default_attributes_parameters=default_attributes_parameters)
    misp_file.add_reference(elf_object.uuid, 'included-in', 'ELF indicators')
    elf_sections = []
    for s in elf_object.sections:
        elf_sections.append(s)
    return misp_file, elf_object, elf_sections


def make_macho_objects(lief_parsed, misp_file, standalone=True, default_attributes_parameters={}):
    macho_object = MachOObject(parsed=lief_parsed, standalone=standalone, default_attributes_parameters=default_attributes_parameters)
    misp_file.add_reference(macho_object.uuid, 'included-in', 'MachO indicators')
    macho_sections = []
    for s in macho_object.sections:
        macho_sections.append(s)
    return misp_file, macho_object, macho_sections


def make_binary_objects(filepath=None, pseudofile=None, filename=None, standalone=True, default_attributes_parameters={}):
    misp_file = FileObject(filepath=filepath, pseudofile=pseudofile, filename=filename,
                           standalone=standalone, default_attributes_parameters=default_attributes_parameters)
    if HAS_LIEF and filepath or (pseudofile and filename):
        try:
            if filepath:
                lief_parsed = lief.parse(filepath=filepath)
            else:
                if six.PY2:
                    logger.critical('Pseudofile is not supported in python2. Just update.')
                    lief_parsed = None
                else:
                    lief_parsed = lief.parse(raw=pseudofile.getvalue(), name=filename)
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
    return misp_file, None, None
