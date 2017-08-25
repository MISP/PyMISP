#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pymisp.tools import MISPObjectGenerator
from io import BytesIO
from hashlib import md5, sha1, sha256, sha512
from datetime import datetime
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


class PEObject(MISPObjectGenerator):

    def __init__(self, parsed=None, filepath=None, pseudofile=None):
        if not HAS_PYDEEP:
            warnings.warn("Please install pydeep: pip install git+https://github.com/kbandla/pydeep.git")
        if not HAS_LIEF:
            raise ImportError('Please install lief, documentation here: https://github.com/lief-project/LIEF')
        if pseudofile:
            if isinstance(pseudofile, BytesIO):
                self.pe = lief.PE.parse(raw=pseudofile.getvalue())
            elif isinstance(pseudofile, bytes):
                self.pe = lief.PE.parse(raw=pseudofile)
            else:
                raise Exception('Pseudo file can be BytesIO or bytes got {}'.format(type(pseudofile)))
        elif filepath:
            self.pe = lief.PE.parse(filepath)
        elif parsed:
            # Got an already parsed blob
            if isinstance(parsed, lief.PE.Binary):
                self.pe = parsed
            else:
                raise Exception('Not a lief.PE.Binary: {}'.format(type(parsed)))
        # Python3 way
        # super().__init__('pe')
        super(PEObject, self).__init__('pe')
        self.generate_attributes()

    def _is_exe(self):
        if not self._is_dll() and not self._is_driver():
            return self.pe.header.has_characteristic(lief.PE.HEADER_CHARACTERISTICS.EXECUTABLE_IMAGE)
        return False

    def _is_dll(self):
        return self.pe.header.has_characteristic(lief.PE.HEADER_CHARACTERISTICS.DLL)

    def _is_driver(self):
        # List from pefile
        system_DLLs = set(('ntoskrnl.exe', 'hal.dll', 'ndis.sys', 'bootvid.dll', 'kdcom.dll'))
        if system_DLLs.intersection([imp.lower() for imp in self.pe.libraries]):
            return True
        return False

    def _get_pe_type(self):
        if self._is_dll():
            return 'dll'
        elif self._is_driver():
            return 'driver'
        elif self._is_exe():
            return 'exe'
        else:
            return 'unknown'

    def generate_attributes(self):
        self._create_attribute('type', value=self._get_pe_type())
        # General information
        self._create_attribute('entrypoint-address', value=self.pe.entrypoint)
        self._create_attribute('compilation-timestamp', value=datetime.utcfromtimestamp(self.pe.header.time_date_stamps).isoformat())
        # self.imphash = self.pe.get_imphash()
        try:
            if (self.pe.has_resources and
                    self.pe.resources_manager.has_version and
                    self.pe.resources_manager.version.has_string_file_info and
                    self.pe.resources_manager.version.string_file_info.langcode_items):
                fileinfo = dict(self.pe.resources_manager.version.string_file_info.langcode_items[0].items.items())
                self._create_attribute('original-filename', value=fileinfo.get('OriginalFilename'))
                self._create_attribute('internal-filename', value=fileinfo.get('InternalName'))
                self._create_attribute('file-description', value=fileinfo.get('FileDescription'))
                self._create_attribute('file-version', value=fileinfo.get('FileVersion'))
                self._create_attribute('lang-id', value=self.pe.resources_manager.version.string_file_info.langcode_items[0].key)
                self._create_attribute('product-name', value=fileinfo.get('ProductName'))
                self._create_attribute('product-version', value=fileinfo.get('ProductVersion'))
                self._create_attribute('company-name', value=fileinfo.get('CompanyName'))
                self._create_attribute('legal-copyright', value=fileinfo.get('LegalCopyright'))
        except lief.read_out_of_bound:
            # The file is corrupted
            pass
        # Sections
        self.sections = []
        if self.pe.sections:
            pos = 0
            for section in self.pe.sections:
                s = PESectionObject(section)
                self.add_reference(s.uuid, 'included-in', 'Section {} of PE'.format(pos))
                if ((self.pe.entrypoint >= section.virtual_address) and
                        (self.pe.entrypoint < (section.virtual_address + section.virtual_size))):
                    self._create_attribute('entrypoint-section|position', value='{}|{}'.format(section.name, pos))
                pos += 1
                self.sections.append(s)
        self._create_attribute('number-sections', value=len(self.sections))
        # TODO: TLSSection / DIRECTORY_ENTRY_TLS


class PESectionObject(MISPObjectGenerator):

    def __init__(self, section):
        # Python3 way
        # super().__init__('pe-section')
        super(PESectionObject, self).__init__('pe-section')
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
