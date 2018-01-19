#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ..exceptions import InvalidMISPObject
from .abstractgenerator import AbstractMISPObjectGenerator
from io import BytesIO
from hashlib import md5, sha1, sha256, sha512
import logging

logger = logging.getLogger('pymisp')


try:
    import lief
    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False

try:
    import pydeep
    HAS_PYDEEP = True
except ImportError:
    HAS_PYDEEP = False


class MachOObject(AbstractMISPObjectGenerator):

    def __init__(self, parsed=None, filepath=None, pseudofile=None, standalone=True, **kwargs):
        if not HAS_PYDEEP:
            logger.warning("Please install pydeep: pip install git+https://github.com/kbandla/pydeep.git")
        if not HAS_LIEF:
            raise ImportError('Please install lief, documentation here: https://github.com/lief-project/LIEF')
        if pseudofile:
            if isinstance(pseudofile, BytesIO):
                self.__macho = lief.MachO.parse(raw=pseudofile.getvalue())
            elif isinstance(pseudofile, bytes):
                self.__macho = lief.MachO.parse(raw=pseudofile)
            else:
                raise InvalidMISPObject('Pseudo file can be BytesIO or bytes got {}'.format(type(pseudofile)))
        elif filepath:
            self.__macho = lief.MachO.parse(filepath)
        elif parsed:
            # Got an already parsed blob
            if isinstance(parsed, lief.MachO.Binary):
                self.__macho = parsed
            else:
                raise InvalidMISPObject('Not a lief.MachO.Binary: {}'.format(type(parsed)))
        # Python3 way
        # super().__init__('elf')
        super(MachOObject, self).__init__('macho', standalone=standalone, **kwargs)
        self.generate_attributes()

    def generate_attributes(self):
        self.add_attribute('type', value=str(self.__macho.header.file_type).split('.')[1])
        self.add_attribute('name', value=self.__macho.name)
        # General information
        if self.__macho.has_entrypoint:
            self.add_attribute('entrypoint-address', value=self.__macho.entrypoint)
        # Sections
        self.sections = []
        if self.__macho.sections:
            pos = 0
            for section in self.__macho.sections:
                s = MachOSectionObject(section, self._standalone, default_attributes_parameters=self._default_attributes_parameters)
                self.add_reference(s.uuid, 'included-in', 'Section {} of MachO'.format(pos))
                pos += 1
                self.sections.append(s)
        self.add_attribute('number-sections', value=len(self.sections))


class MachOSectionObject(AbstractMISPObjectGenerator):

    def __init__(self, section, standalone=True, **kwargs):
        # Python3 way
        # super().__init__('pe-section')
        super(MachOSectionObject, self).__init__('macho-section', standalone=standalone, **kwargs)
        self.__section = section
        self.__data = bytes(self.__section.content)
        self.generate_attributes()

    def generate_attributes(self):
        self.add_attribute('name', value=self.__section.name)
        size = self.add_attribute('size-in-bytes', value=self.__section.size)
        if int(size.value) > 0:
            self.add_attribute('entropy', value=self.__section.entropy)
            self.add_attribute('md5', value=md5(self.__data).hexdigest())
            self.add_attribute('sha1', value=sha1(self.__data).hexdigest())
            self.add_attribute('sha256', value=sha256(self.__data).hexdigest())
            self.add_attribute('sha512', value=sha512(self.__data).hexdigest())
            if HAS_PYDEEP:
                self.add_attribute('ssdeep', value=pydeep.hash_buf(self.__data).decode())
