#!/usr/bin/env python
# -*- coding: utf-8 -*-

from . import FileObject, PEObject, ELFObject, MachOObject
from ..exceptions import MISPObjectException
import warnings

try:
    import lief
    from lief import Logger
    Logger.disable()
    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False


class FileTypeNotImplemented(MISPObjectException):
    pass


def make_pe_objects(lief_parsed, misp_file):
    pe_object = PEObject(parsed=lief_parsed)
    misp_file.add_reference(pe_object.uuid, 'included-in', 'PE indicators')
    pe_sections = []
    for s in pe_object.sections:
        pe_sections.append(s)
    return misp_file, pe_object, pe_sections


def make_elf_objects(lief_parsed, misp_file):
    elf_object = ELFObject(parsed=lief_parsed)
    misp_file.add_reference(elf_object.uuid, 'included-in', 'ELF indicators')
    elf_sections = []
    for s in elf_object.sections:
        elf_sections.append(s)
    return misp_file, elf_object, elf_sections


def make_macho_objects(lief_parsed, misp_file):
    macho_object = MachOObject(parsed=lief_parsed)
    misp_file.add_reference(macho_object.uuid, 'included-in', 'MachO indicators')
    macho_sections = []
    for s in macho_object.sections:
        macho_sections.append(s)
    return misp_file, macho_object, macho_sections


def make_binary_objects(filepath):
    misp_file = FileObject(filepath)
    if HAS_LIEF:
        try:
            lief_parsed = lief.parse(filepath)
            if isinstance(lief_parsed, lief.PE.Binary):
                return make_pe_objects(lief_parsed, misp_file)
            elif isinstance(lief_parsed, lief.ELF.Binary):
                return make_elf_objects(lief_parsed, misp_file)
            elif isinstance(lief_parsed, lief.MachO.Binary):
                return make_macho_objects(lief_parsed, misp_file)
        except lief.bad_format as e:
            warnings.warn('\tBad format: ', e)
        except lief.bad_file as e:
            warnings.warn('\tBad file: ', e)
        except lief.parser_error as e:
            warnings.warn('\tParser error: ', e)
        except FileTypeNotImplemented as e:  # noqa
            warnings.warn(e)
    else:
        warnings.warn('Please install lief, documentation here: https://github.com/lief-project/LIEF')
    return misp_file, None, None
