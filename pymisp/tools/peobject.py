#!/usr/bin/env python3

from __future__ import annotations

import logging

from base64 import b64encode
from datetime import datetime
from hashlib import md5, sha1, sha256, sha512
from io import BytesIO
from pathlib import Path
from typing import Any

from . import FileObject
from .abstractgenerator import AbstractMISPObjectGenerator
from ..exceptions import InvalidMISPObject

import lief
import lief.PE

try:
    import pydeep  # type: ignore
    HAS_PYDEEP = True
except ImportError:
    HAS_PYDEEP = False

logger = logging.getLogger('pymisp')


def make_pe_objects(lief_parsed: lief.PE.Binary,
                    misp_file: FileObject,
                    standalone: bool = True,
                    default_attributes_parameters: dict[str, Any] = {}) -> tuple[FileObject, PEObject, list[PESectionObject]]:
    pe_object = PEObject(parsed=lief_parsed, standalone=standalone, default_attributes_parameters=default_attributes_parameters)
    misp_file.add_reference(pe_object.uuid, 'includes', 'PE indicators')
    pe_sections = []
    for s in pe_object.sections:
        pe_sections.append(s)
    return misp_file, pe_object, pe_sections


class PEObject(AbstractMISPObjectGenerator):

    __pe: lief.PE.Binary

    def __init__(self, parsed: lief.PE.Binary | None = None,  # type: ignore[no-untyped-def]
                 filepath: Path | str | None = None,
                 pseudofile: BytesIO | list[int] | None = None,
                 **kwargs) -> None:
        """Creates an PE object, with lief"""
        super().__init__('pe', **kwargs)
        if not HAS_PYDEEP:
            logger.warning("pydeep is missing, please install pymisp this way: pip install pymisp[fileobjects]")
        if pseudofile:
            if isinstance(pseudofile, BytesIO):
                p = lief.PE.parse(obj=pseudofile)
            elif isinstance(pseudofile, bytes):
                p = lief.PE.parse(raw=list(pseudofile))
            elif isinstance(pseudofile, list):
                p = lief.PE.parse(raw=pseudofile)
            else:
                raise InvalidMISPObject(f'Pseudo file can be BytesIO or bytes got {type(pseudofile)}')
            if not p:
                raise InvalidMISPObject('Unable to parse pseudofile')
            self.__pe = p
        elif filepath:
            if p := lief.PE.parse(filepath):
                self.__pe = p
            else:
                raise InvalidMISPObject(f'Unable to parse {filepath}')
        elif parsed:
            # Got an already parsed blob
            if isinstance(parsed, lief.PE.Binary):
                self.__pe = parsed
            else:
                raise InvalidMISPObject(f'Not a lief.PE.Binary: {type(parsed)}')
        self.generate_attributes()

    def _is_exe(self) -> bool:
        if not self._is_dll() and not self._is_driver():
            return self.__pe.header.has_characteristic(lief.PE.Header.CHARACTERISTICS.EXECUTABLE_IMAGE)
        return False

    def _is_dll(self) -> bool:
        return self.__pe.header.has_characteristic(lief.PE.Header.CHARACTERISTICS.DLL)

    def _is_driver(self) -> bool:
        # List from pefile
        system_DLLs = {'ntoskrnl.exe', 'hal.dll', 'ndis.sys', 'bootvid.dll', 'kdcom.dll'}
        if system_DLLs.intersection([imp.lower() for imp in self.__pe.libraries]):
            return True
        return False

    def _get_pe_type(self) -> str:
        if self._is_dll():
            return 'dll'
        elif self._is_driver():
            return 'driver'
        elif self._is_exe():
            return 'exe'
        else:
            return 'unknown'

    def generate_attributes(self) -> None:
        self.add_attribute('type', value=self._get_pe_type())
        # General information
        self.add_attribute('entrypoint-address', value=self.__pe.entrypoint)
        self.add_attribute('compilation-timestamp', value=datetime.utcfromtimestamp(self.__pe.header.time_date_stamps).isoformat())
        self.add_attribute('imphash', value=lief.PE.get_imphash(self.__pe, lief.PE.IMPHASH_MODE.PEFILE))
        self.add_attribute('authentihash', value=self.__pe.authentihash_sha256.hex())
        r_manager = self.__pe.resources_manager
        if isinstance(r_manager, lief.PE.ResourcesManager):
            version = r_manager.version
            if isinstance(version, lief.PE.ResourceVersion) and version.string_file_info is not None:
                fileinfo = dict(version.string_file_info.langcode_items[0].items.items())
                self.add_attribute('original-filename', value=fileinfo.get('OriginalFilename'))
                self.add_attribute('internal-filename', value=fileinfo.get('InternalName'))
                self.add_attribute('file-description', value=fileinfo.get('FileDescription'))
                self.add_attribute('file-version', value=fileinfo.get('FileVersion'))
                self.add_attribute('product-name', value=fileinfo.get('ProductName'))
                self.add_attribute('product-version', value=fileinfo.get('ProductVersion'))
                self.add_attribute('company-name', value=fileinfo.get('CompanyName'))
                self.add_attribute('legal-copyright', value=fileinfo.get('LegalCopyright'))
                self.add_attribute('lang-id', value=version.string_file_info.langcode_items[0].key)
        # Sections
        self.sections = []
        if self.__pe.sections:
            pos = 0
            for section in self.__pe.sections:
                if not section.name and not section.size:
                    # Skip section if name is none AND size is 0.
                    continue
                s = PESectionObject(section, standalone=self._standalone, default_attributes_parameters=self._default_attributes_parameters)
                self.add_reference(s.uuid, 'includes', f'Section {pos} of PE')
                if ((self.__pe.entrypoint >= section.virtual_address)
                        and (self.__pe.entrypoint < (section.virtual_address + section.virtual_size))):
                    if isinstance(section.name, bytes):
                        section_name = section.name.decode()
                    else:
                        section_name = section.name
                    self.add_attribute('entrypoint-section-at-position', value=f'{section_name}|{pos}')
                pos += 1
                self.sections.append(s)
        self.add_attribute('number-sections', value=len(self.sections))
        # Signatures
        self.certificates = []
        self.signers = []
        for sign in self.__pe.signatures:
            for c in sign.certificates:
                cert_obj = PECertificate(c)
                self.add_reference(cert_obj.uuid, 'signed-by')
                self.certificates.append(cert_obj)
            for s_info in sign.signers:
                signer_obj = PESigners(s_info)
                self.add_reference(signer_obj.uuid, 'signed-by')
                self.signers.append(signer_obj)


class PECertificate(AbstractMISPObjectGenerator):

    def __init__(self, certificate: lief.PE.x509, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__('x509')
        self.__certificate = certificate
        self.generate_attributes()

    def generate_attributes(self) -> None:
        self.add_attribute('issuer', value=self.__certificate.issuer)
        self.add_attribute('serial-number', value=self.__certificate.serial_number)
        if len(self.__certificate.valid_from) == 6:
            self.add_attribute('validity-not-before',
                               value=datetime(year=self.__certificate.valid_from[0],
                                              month=self.__certificate.valid_from[1],
                                              day=self.__certificate.valid_from[2],
                                              hour=self.__certificate.valid_from[3],
                                              minute=self.__certificate.valid_from[4],
                                              second=self.__certificate.valid_from[5]))
        if len(self.__certificate.valid_to) == 6:
            self.add_attribute('validity-not-after',
                               value=datetime(year=self.__certificate.valid_to[0],
                                              month=self.__certificate.valid_to[1],
                                              day=self.__certificate.valid_to[2],
                                              hour=self.__certificate.valid_to[3],
                                              minute=self.__certificate.valid_to[4],
                                              second=self.__certificate.valid_to[5]))
        self.add_attribute('version', value=self.__certificate.version)
        self.add_attribute('subject', value=self.__certificate.subject)
        self.add_attribute('signature_algorithm', value=self.__certificate.signature_algorithm)
        self.add_attribute('raw-base64', value=b64encode(self.__certificate.raw))


class PESigners(AbstractMISPObjectGenerator):

    def __init__(self, signer: lief.PE.SignerInfo, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__('authenticode-signerinfo')
        self.__signer = signer
        self.generate_attributes()

    def generate_attributes(self) -> None:
        self.add_attribute('issuer', value=self.__signer.issuer)
        self.add_attribute('serial-number', value=self.__signer.serial_number)
        self.add_attribute('version', value=self.__signer.version)
        self.add_attribute('digest_algorithm', value=str(self.__signer.digest_algorithm))
        self.add_attribute('encryption_algorithm', value=str(self.__signer.encryption_algorithm))
        self.add_attribute('digest-base64', value=b64encode(self.__signer.encrypted_digest))
        info: lief.PE.SpcSpOpusInfo = self.__signer.get_attribute(lief.PE.Attribute.TYPE.SPC_SP_OPUS_INFO)  # type: ignore[assignment]
        if info:
            self.add_attribute('program-name', value=info.program_name)
            self.add_attribute('url', value=info.more_info)


class PESectionObject(AbstractMISPObjectGenerator):

    def __init__(self, section: lief.PE.Section, **kwargs) -> None:  # type: ignore[no-untyped-def]
        """Creates an PE Section object. Object generated by PEObject."""
        super().__init__('pe-section')
        self.__section = section
        self.__data = bytes(self.__section.content)
        self.generate_attributes()

    def generate_attributes(self) -> None:
        self.add_attribute('name', value=self.__section.name)
        self.add_attribute('size-in-bytes', value=self.__section.size)
        if int(self.__section.size) > 0:
            # zero-filled sections can create too many correlations
            to_ids = float(self.__section.entropy) > 0
            disable_correlation = not to_ids
            self.add_attribute('entropy', value=self.__section.entropy)
            self.add_attribute('md5', value=md5(self.__data).hexdigest(), disable_correlation=disable_correlation, to_ids=to_ids)
            self.add_attribute('sha1', value=sha1(self.__data).hexdigest(), disable_correlation=disable_correlation, to_ids=to_ids)
            self.add_attribute('sha256', value=sha256(self.__data).hexdigest(), disable_correlation=disable_correlation, to_ids=to_ids)
            self.add_attribute('sha512', value=sha512(self.__data).hexdigest(), disable_correlation=disable_correlation, to_ids=to_ids)
            if HAS_PYDEEP and float(self.__section.entropy) > 0:
                if self.__section.name == '.rsrc':
                    # ssdeep of .rsrc creates too many correlations
                    disable_correlation = True
                    to_ids = False
                self.add_attribute('ssdeep', value=pydeep.hash_buf(self.__data).decode(), disable_correlation=disable_correlation, to_ids=to_ids)
