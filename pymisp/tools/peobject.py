#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pymisp.tools import MISPObjectGenerator
from io import BytesIO
from hashlib import md5, sha1, sha256, sha512
from datetime import datetime


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
            raise ImportError("Please install pydeep: pip install git+https://github.com/kbandla/pydeep.git")
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
        MISPObjectGenerator.__init__(self, 'pe')
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

    def generate_attributes(self):
        if self._is_dll():
            self.pe_type = 'dll'
        elif self._is_driver():
            self.pe_type = 'driver'
        elif self._is_exe():
            self.pe_type = 'exe'
        else:
            self.pe_type = 'unknown'
        # General information
        self.entrypoint_address = self.pe.entrypoint
        self.compilation_timestamp = datetime.utcfromtimestamp(self.pe.header.time_date_stamps).isoformat()
        # self.imphash = self.pe.get_imphash()
        try:
            if (self.pe.has_resources and
                    self.pe.resources_manager.has_version and
                    self.pe.resources_manager.version.has_string_file_info and
                    self.pe.resources_manager.version.string_file_info.langcode_items):
                fileinfo = dict(self.pe.resources_manager.version.string_file_info.langcode_items[0].items.items())
                self.original_filename = fileinfo.get('OriginalFilename')
                self.internal_filename = fileinfo.get('InternalName')
                self.file_description = fileinfo.get('FileDescription')
                self.file_version = fileinfo.get('FileVersion')
                self.lang_id = self.pe.resources_manager.version.string_file_info.langcode_items[0].key
                self.product_name = fileinfo.get('ProductName')
                self.product_version = fileinfo.get('ProductVersion')
                self.company_name = fileinfo.get('CompanyName')
                self.legal_copyright = fileinfo.get('LegalCopyright')
        except lief.read_out_of_bound:
            # The file is corrupted
            pass
        # Sections
        self.sections = []
        if self.pe.sections:
            pos = 0
            for section in self.pe.sections:
                s = PESectionObject(section)
                self.add_link(s.uuid, 'Section {} of PE'.format(pos))
                if ((self.entrypoint_address >= section.virtual_address) and
                        (self.entrypoint_address < (section.virtual_address + section.virtual_size))):
                    self.entrypoint_section = (section.name, pos)  # Tuple: (section_name, position)
                pos += 1
                self.sections.append(s)
        self.nb_sections = len(self.sections)
        # TODO: TLSSection / DIRECTORY_ENTRY_TLS

    def dump(self):
        pe_object = {}
        pe_object['type'] = {'value': self.pe_type}
        if hasattr(self, 'imphash'):
            pe_object['imphash'] = {'value': self.imphash}
        if hasattr(self, 'original_filename'):
            pe_object['original-filename'] = {'value': self.original_filename}
        if hasattr(self, 'internal_filename'):
            pe_object['internal-filename'] = {'value': self.internal_filename}
        if hasattr(self, 'compilation_timestamp'):
            pe_object['compilation-timestamp'] = {'value': self.compilation_timestamp}
        if hasattr(self, 'entrypoint_section'):
            pe_object['entrypoint-section|position'] = {'value': '{}|{}'.format(*self.entrypoint_section)}
        if hasattr(self, 'entrypoint_address'):
            pe_object['entrypoint-address'] = {'value': self.entrypoint_address}
        if hasattr(self, 'file_description'):
            pe_object['file-description'] = {'value': self.file_description}
        if hasattr(self, 'file_version'):
            pe_object['file-version'] = {'value': self.file_version}
        if hasattr(self, 'lang_id'):
            pe_object['lang-id'] = {'value': self.lang_id}
        if hasattr(self, 'product_name'):
            pe_object['product-name'] = {'value': self.product_name}
        if hasattr(self, 'product_version'):
            pe_object['product-version'] = {'value': self.product_version}
        if hasattr(self, 'company_name'):
            pe_object['company-name'] = {'value': self.company_name}
        if hasattr(self, 'nb_sections'):
            pe_object['number-sections'] = {'value': self.nb_sections}
        return self._fill_object(pe_object)


class PESectionObject(MISPObjectGenerator):

    def __init__(self, section):
        MISPObjectGenerator.__init__(self, 'pe-section')
        self.section = section
        self.data = bytes(self.section.content)
        self.generate_attributes()

    def generate_attributes(self):
        self.name = self.section.name
        self.size = self.section.size
        if self.size > 0:
            self.entropy = self.section.entropy
            self.md5 = md5(self.data).hexdigest()
            self.sha1 = sha1(self.data).hexdigest()
            self.sha256 = sha256(self.data).hexdigest()
            self.sha512 = sha512(self.data).hexdigest()
            if HAS_PYDEEP:
                self.ssdeep = pydeep.hash_buf(self.data).decode()

    def dump(self):
        section = {}
        section['name'] = {'value': self.name}
        section['size-in-bytes'] = {'value': self.size}
        if self.size > 0:
            section['entropy'] = {'value': self.entropy}
            section['md5'] = {'value': self.md5}
            section['sha1'] = {'value': self.sha1}
            section['sha256'] = {'value': self.sha256}
            section['sha512'] = {'value': self.sha512}
            section['ssdeep'] = {'value': self.ssdeep}
        return self._fill_object(section)
