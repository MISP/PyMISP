#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pymisp.tools import MISPObjectGenerator
from io import BytesIO
from hashlib import md5, sha1, sha256, sha512
import warnings


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


class MachOObject(MISPObjectGenerator):

    def __init__(self, parsed=None, filepath=None, pseudofile=None):
        if not HAS_PYDEEP:
            warnings.warn("Please install pydeep: pip install git+https://github.com/kbandla/pydeep.git")
        if not HAS_LIEF:
            raise ImportError('Please install lief, documentation here: https://github.com/lief-project/LIEF')
        if pseudofile:
            if isinstance(pseudofile, BytesIO):
                self.macho = lief.MachO.parse(raw=pseudofile.getvalue())
            elif isinstance(pseudofile, bytes):
                self.macho = lief.MachO.parse(raw=pseudofile)
            else:
                raise Exception('Pseudo file can be BytesIO or bytes got {}'.format(type(pseudofile)))
        elif filepath:
            self.macho = lief.MachO.parse(filepath)
        elif parsed:
            # Got an already parsed blob
            if isinstance(parsed, lief.MachO.Binary):
                self.macho = parsed
            else:
                raise Exception('Not a lief.MachO.Binary: {}'.format(type(parsed)))
        # Python3 way
        # super().__init__('elf')
        super(MachOObject, self).__init__('macho')
        self.generate_attributes()

    def generate_attributes(self):
        self._create_attribute('type', value=str(self.macho.header.file_type).split('.')[1])
        self._create_attribute('name', value=self.macho.name)
        # General information
        if self.macho.has_entrypoint:
            self._create_attribute('entrypoint-address', value=self.macho.entrypoint)
        # Sections
        self.sections = []
        if self.macho.sections:
            pos = 0
            for section in self.macho.sections:
                s = MachOSectionObject(section)
                self.add_reference(s.uuid, 'included-in', 'Section {} of MachO'.format(pos))
                pos += 1
                self.sections.append(s)
        self._create_attribute('number-sections', value=len(self.sections))


class MachOSectionObject(MISPObjectGenerator):

    def __init__(self, section):
        # Python3 way
        # super().__init__('pe-section')
        super(MachOSectionObject, self).__init__('macho-section')
        self.section = section
        self.data = bytes(self.section.content)
        self.generate_attributes()

    def generate_attributes(self):
        self._create_attribute('name', value=self.section.name)
        size = self._create_attribute('size-in-bytes', value=self.section.size)
        if int(size.value) > 0:
            self._create_attribute('entropy', value=self.section.entropy)
            self._create_attribute('md5', value=md5(self.data).hexdigest())
            self._create_attribute('sha1', value=sha1(self.data).hexdigest())
            self._create_attribute('sha256', value=sha256(self.data).hexdigest())
            self._create_attribute('sha512', value=sha512(self.data).hexdigest())
            if HAS_PYDEEP:
                self._create_attribute('ssdeep', value=pydeep.hash_buf(self.data).decode())
