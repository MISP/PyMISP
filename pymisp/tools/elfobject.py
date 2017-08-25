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


class ELFObject(MISPObjectGenerator):

    def __init__(self, parsed=None, filepath=None, pseudofile=None):
        if not HAS_PYDEEP:
            warnings.warn("Please install pydeep: pip install git+https://github.com/kbandla/pydeep.git")
        if not HAS_LIEF:
            raise ImportError('Please install lief, documentation here: https://github.com/lief-project/LIEF')
        if pseudofile:
            if isinstance(pseudofile, BytesIO):
                self.elf = lief.ELF.parse(raw=pseudofile.getvalue())
            elif isinstance(pseudofile, bytes):
                self.elf = lief.ELF.parse(raw=pseudofile)
            else:
                raise Exception('Pseudo file can be BytesIO or bytes got {}'.format(type(pseudofile)))
        elif filepath:
            self.elf = lief.ELF.parse(filepath)
        elif parsed:
            # Got an already parsed blob
            if isinstance(parsed, lief.ELF.Binary):
                self.elf = parsed
            else:
                raise Exception('Not a lief.ELF.Binary: {}'.format(type(parsed)))
        # Python3 way
        # super().__init__('elf')
        super(ELFObject, self).__init__('elf')
        self.generate_attributes()

    def generate_attributes(self):
        # General information
        self._create_attribute('type', value=str(self.elf.header.file_type).split('.')[1])
        self._create_attribute('entrypoint-address', value=self.elf.entrypoint)
        self._create_attribute('arch', value=str(self.elf.header.machine_type).split('.')[1])
        self._create_attribute('os_abi', value=str(self.elf.header.identity_os_abi).split('.')[1])
        # Sections
        self.sections = []
        if self.elf.sections:
            pos = 0
            for section in self.elf.sections:
                s = ELFSectionObject(section)
                self.add_reference(s.uuid, 'included-in', 'Section {} of ELF'.format(pos))
                pos += 1
                self.sections.append(s)
        self._create_attribute('number-sections', value=len(self.sections))


class ELFSectionObject(MISPObjectGenerator):

    def __init__(self, section):
        # Python3 way
        # super().__init__('pe-section')
        super(ELFSectionObject, self).__init__('elf-section')
        self.section = section
        self.data = bytes(self.section.content)
        self.generate_attributes()

    def generate_attributes(self):
        self._create_attribute('name', value=self.section.name)
        self._create_attribute('type', value=str(self.section.type).split('.')[1])
        print(self.section.flags)
        # self._create_attribute('flag', value=str(self.section.flags).split('.')[1])
        size = self._create_attribute('size-in-bytes', value=self.section.size)
        if int(size.value) > 0:
            self._create_attribute('entropy', value=self.section.entropy)
            self._create_attribute('md5', value=md5(self.data).hexdigest())
            self._create_attribute('sha1', value=sha1(self.data).hexdigest())
            self._create_attribute('sha256', value=sha256(self.data).hexdigest())
            self._create_attribute('sha512', value=sha512(self.data).hexdigest())
            if HAS_PYDEEP:
                self._create_attribute('ssdeep', value=pydeep.hash_buf(self.data).decode())
