#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ..exceptions import InvalidMISPObject
from .abstractgenerator import AbstractMISPObjectGenerator
from io import BytesIO
from hashlib import md5, sha1, sha256, sha512
from datetime import datetime
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


class PEObject(AbstractMISPObjectGenerator):

    def __init__(self, parsed=None, filepath=None, pseudofile=None, standalone=True, **kwargs):
        if not HAS_PYDEEP:
            logger.warning("Please install pydeep: pip install git+https://github.com/kbandla/pydeep.git")
        if not HAS_LIEF:
            raise ImportError('Please install lief, documentation here: https://github.com/lief-project/LIEF')
        if pseudofile:
            if isinstance(pseudofile, BytesIO):
                self.__pe = lief.PE.parse(raw=pseudofile.getvalue())
            elif isinstance(pseudofile, bytes):
                self.__pe = lief.PE.parse(raw=pseudofile)
            else:
                raise InvalidMISPObject('Pseudo file can be BytesIO or bytes got {}'.format(type(pseudofile)))
        elif filepath:
            self.__pe = lief.PE.parse(filepath)
        elif parsed:
            # Got an already parsed blob
            if isinstance(parsed, lief.PE.Binary):
                self.__pe = parsed
            else:
                raise InvalidMISPObject('Not a lief.PE.Binary: {}'.format(type(parsed)))
        # Python3 way
        # super().__init__('pe')
        super(PEObject, self).__init__('pe', standalone=standalone, **kwargs)
        self.generate_attributes()

    def _is_exe(self):
        if not self._is_dll() and not self._is_driver():
            return self.__pe.header.has_characteristic(lief.PE.HEADER_CHARACTERISTICS.EXECUTABLE_IMAGE)
        return False

    def _is_dll(self):
        return self.__pe.header.has_characteristic(lief.PE.HEADER_CHARACTERISTICS.DLL)

    def _is_driver(self):
        # List from pefile
        system_DLLs = set(('ntoskrnl.exe', 'hal.dll', 'ndis.sys', 'bootvid.dll', 'kdcom.dll'))
        if system_DLLs.intersection([imp.lower() for imp in self.__pe.libraries]):
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
        self.add_attribute('type', value=self._get_pe_type())
        # General information
        self.add_attribute('entrypoint-address', value=self.__pe.entrypoint)
        self.add_attribute('compilation-timestamp', value=datetime.utcfromtimestamp(self.__pe.header.time_date_stamps).isoformat())
        # self.imphash = self.__pe.get_imphash()
        try:
            if (self.__pe.has_resources and
                    self.__pe.resources_manager.has_version and
                    self.__pe.resources_manager.version.has_string_file_info and
                    self.__pe.resources_manager.version.string_file_info.langcode_items):
                fileinfo = dict(self.__pe.resources_manager.version.string_file_info.langcode_items[0].items.items())
                self.add_attribute('original-filename', value=fileinfo.get('OriginalFilename'))
                self.add_attribute('internal-filename', value=fileinfo.get('InternalName'))
                self.add_attribute('file-description', value=fileinfo.get('FileDescription'))
                self.add_attribute('file-version', value=fileinfo.get('FileVersion'))
                self.add_attribute('lang-id', value=self.__pe.resources_manager.version.string_file_info.langcode_items[0].key)
                self.add_attribute('product-name', value=fileinfo.get('ProductName'))
                self.add_attribute('product-version', value=fileinfo.get('ProductVersion'))
                self.add_attribute('company-name', value=fileinfo.get('CompanyName'))
                self.add_attribute('legal-copyright', value=fileinfo.get('LegalCopyright'))
        except lief.read_out_of_bound:
            # The file is corrupted
            pass
        # Sections
        self.sections = []
        if self.__pe.sections:
            pos = 0
            for section in self.__pe.sections:
                s = PESectionObject(section, self._standalone, default_attributes_parameters=self._default_attributes_parameters)
                self.add_reference(s.uuid, 'included-in', 'Section {} of PE'.format(pos))
                if ((self.__pe.entrypoint >= section.virtual_address) and
                        (self.__pe.entrypoint < (section.virtual_address + section.virtual_size))):
                    self.add_attribute('entrypoint-section-at-position', value='{}|{}'.format(section.name, pos))
                pos += 1
                self.sections.append(s)
        self.add_attribute('number-sections', value=len(self.sections))
        # TODO: TLSSection / DIRECTORY_ENTRY_TLS


class PESectionObject(AbstractMISPObjectGenerator):

    def __init__(self, section, standalone=True, **kwargs):
        # Python3 way
        # super().__init__('pe-section')
        super(PESectionObject, self).__init__('pe-section', standalone=standalone, **kwargs)
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
