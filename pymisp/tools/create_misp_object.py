#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp.tools import FileObject, PEObject, ELFObject, MachOObject, MISPObjectException

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
    if not HAS_LIEF:
        raise ImportError('Please install lief, documentation here: https://github.com/lief-project/LIEF')
    misp_file = FileObject(filepath)
    try:
        lief_parsed = lief.parse(filepath)
        if isinstance(lief_parsed, lief.PE.Binary):
            return make_pe_objects(lief_parsed, misp_file)
        elif isinstance(lief_parsed, lief.ELF.Binary):
            return make_elf_objects(lief_parsed, misp_file)
        elif isinstance(lief_parsed, lief.MachO.Binary):
            return make_macho_objects(lief_parsed, misp_file)
    except lief.bad_format as e:
        # print('\tBad format: ', e)
        pass
    except lief.bad_file as e:
        # print('\tBad file: ', e)
        pass
    except lief.parser_error as e:
        # print('\tParser error: ', e)
        pass
    except FileTypeNotImplemented as e:  # noqa
        # print(e)
        pass
    return misp_file, None, None
