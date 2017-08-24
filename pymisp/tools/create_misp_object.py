#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp.tools import FileObject, PEObject, MISPObjectException

try:
    import lief
    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False


class FileTypeNotImplemented(MISPObjectException):
    pass


def make_pe_objects(lief_parsed, misp_file):
    misp_pe = PEObject(parsed=lief_parsed)
    misp_file.add_reference(misp_pe.uuid, 'included-in', 'PE indicators')
    file_object = misp_file
    pe_object = misp_pe
    pe_sections = []
    for s in misp_pe.sections:
        pe_sections.append(s)
    return file_object, pe_object, pe_sections


def make_binary_objects(filepath):
    if not HAS_LIEF:
        raise ImportError('Please install lief, documentation here: https://github.com/lief-project/LIEF')
    misp_file = FileObject(filepath)
    try:
        lief_parsed = lief.parse(filepath)
        if isinstance(lief_parsed, lief.PE.Binary):
            return make_pe_objects(lief_parsed, misp_file)
        elif isinstance(lief_parsed, lief.ELF.Binary):
            raise FileTypeNotImplemented('ELF not implemented yet.')
        elif isinstance(lief_parsed, lief.MachO.Binary):
            raise FileTypeNotImplemented('MachO not implemented yet.')
    except lief.bad_format as e:
        print('\tBad format: ', e)
    except lief.bad_file as e:
        print('\tBad file: ', e)
    except lief.parser_error as e:
        print('\tParser error: ', e)
    except FileTypeNotImplemented as e:
        print(e)
    file_object = misp_file.to_json()
    return file_object, None, None
