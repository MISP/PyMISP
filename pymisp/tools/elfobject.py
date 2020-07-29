#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .abstractgenerator import AbstractMISPObjectGenerator
from ..exceptions import InvalidMISPObject
from io import BytesIO
from hashlib import md5, sha1, sha256, sha512
import logging
from typing import Union
from pathlib import Path
from . import FileObject

import lief  # type: ignore

try:
    import pydeep  # type: ignore
    HAS_PYDEEP = True
except ImportError:
    HAS_PYDEEP = False

logger = logging.getLogger('pymisp')


def make_elf_objects(lief_parsed: lief.Binary, misp_file: FileObject, standalone: bool = True, default_attributes_parameters: dict = {}):
    elf_object = ELFObject(parsed=lief_parsed, standalone=standalone, default_attributes_parameters=default_attributes_parameters)
    misp_file.add_reference(elf_object.uuid, 'includes', 'ELF indicators')
    elf_sections = []
    for s in elf_object.sections:
        elf_sections.append(s)
    return misp_file, elf_object, elf_sections


class ELFObject(AbstractMISPObjectGenerator):

    def __init__(self, parsed: lief.ELF.Binary = None, filepath: Union[Path, str] = None, pseudofile: Union[BytesIO, bytes] = None, **kwargs):
        super(ELFObject, self).__init__('elf', **kwargs)
        if not HAS_PYDEEP:
            logger.warning("Please install pydeep: pip install git+https://github.com/kbandla/pydeep.git")
        if pseudofile:
            if isinstance(pseudofile, BytesIO):
                self.__elf = lief.ELF.parse(raw=pseudofile.getvalue())
            elif isinstance(pseudofile, bytes):
                self.__elf = lief.ELF.parse(raw=pseudofile)
            else:
                raise InvalidMISPObject('Pseudo file can be BytesIO or bytes got {}'.format(type(pseudofile)))
        elif filepath:
            self.__elf = lief.ELF.parse(filepath)
        elif parsed:
            # Got an already parsed blob
            if isinstance(parsed, lief.ELF.Binary):
                self.__elf = parsed
            else:
                raise InvalidMISPObject('Not a lief.ELF.Binary: {}'.format(type(parsed)))
        self.generate_attributes()

    def generate_attributes(self):
        # General information
        self.add_attribute('type', value=str(self.__elf.header.file_type).split('.')[1])
        self.add_attribute('entrypoint-address', value=self.__elf.entrypoint)
        self.add_attribute('arch', value=str(self.__elf.header.machine_type).split('.')[1])
        self.add_attribute('os_abi', value=str(self.__elf.header.identity_os_abi).split('.')[1])
        # Sections
        self.sections = []
        if self.__elf.sections:
            pos = 0
            for section in self.__elf.sections:
                s = ELFSectionObject(section, standalone=self._standalone, default_attributes_parameters=self._default_attributes_parameters)
                self.add_reference(s.uuid, 'includes', 'Section {} of ELF'.format(pos))
                pos += 1
                self.sections.append(s)
        self.add_attribute('number-sections', value=len(self.sections))


class ELFSectionObject(AbstractMISPObjectGenerator):

    def __init__(self, section: lief.ELF.Section, **kwargs):
        # Python3 way
        # super().__init__('pe-section')
        super(ELFSectionObject, self).__init__('elf-section', **kwargs)
        self.__section = section
        self.__data = bytes(self.__section.content)
        self.generate_attributes()

    def generate_attributes(self):
        self.add_attribute('name', value=self.__section.name)
        self.add_attribute('type', value=str(self.__section.type).split('.')[1])
        for flag in self.__section.flags_list:
            self.add_attribute('flag', value=str(flag).split('.')[1])
        size = self.add_attribute('size-in-bytes', value=self.__section.size)
        if int(size.value) > 0:
            self.add_attribute('entropy', value=self.__section.entropy)
            self.add_attribute('md5', value=md5(self.__data).hexdigest())
            self.add_attribute('sha1', value=sha1(self.__data).hexdigest())
            self.add_attribute('sha256', value=sha256(self.__data).hexdigest())
            self.add_attribute('sha512', value=sha512(self.__data).hexdigest())
            if HAS_PYDEEP:
                self.add_attribute('ssdeep', value=pydeep.hash_buf(self.__data).decode())
