#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ..exceptions import InvalidMISPObject
from .abstractgenerator import AbstractMISPObjectGenerator
from io import BytesIO
import logging
import os
import codecs
import json
import subprocess
import re

logger = logging.getLogger('pymisp')

try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False


class MIMETypeObject(AbstractMISPObjectGenerator):

    def __init__(self, filepath=None, pseudofile=None, filename=None, standalone=True, **kwargs):
        if not HAS_MAGIC:
            logger.warning("Please install python-magic: pip install python-magic.")
        if filename:
            # Useful in case the file is copied with a pre-defined name by a script but we want to keep the original name
            self.__filename = filename
        elif filepath:
            self.__filename = os.path.basename(filepath)
        else:
            raise InvalidMISPObject('A file name is required (either in the path, or as a parameter).')

        if filepath:
            with open(filepath, 'rb') as f:
                self.__pseudofile = BytesIO(f.read())
        elif pseudofile and isinstance(pseudofile, BytesIO):
            # WARNING: lief.parse requires a path
            self.__pseudofile = pseudofile
        else:
            raise InvalidMISPObject('File buffer (BytesIO) or a path is required.')

        mime = magic.from_buffer(self.__pseudofile.getvalue(), mime=True)
        mime_type = re.sub(r'\W', '-', mime)

        # PY3 way:
        # super().__init__('file')
        super(MIMETypeObject, self).__init__('MIME-' + mime_type, standalone=standalone, **kwargs)
        self.__data = self.__pseudofile.getvalue()

        self.generate_attributes()

    def base64_encode_bytes(self, pseudofile):
        """
        Base64 encodes bytes for passing self.__pseudofile to subprocess.
        :return:
        """
        return codecs.encode(pseudofile, 'base64')

    def extract_exif(self, base64_string):
        """
        Uses ExifTool via subprocess to extract file metadata.
        :return:
        """
        p1 = subprocess.Popen(("echo", base64_string), stdout=subprocess.PIPE)
        p2 = subprocess.Popen(("base64", "--decode"), stdin=p1.stdout, stdout=subprocess.PIPE)
        p3 = subprocess.Popen(("exiftool", "-G", "-n", "-j", "-"), stdin=p2.stdout, stdout=subprocess.PIPE)
        output = p3.communicate()[0]
        return json.loads(output.decode('utf-8'))[0]

    def generate_attributes(self):
        """
        Adds attributes from ExifTool output.
        :return:
        """
        base64_file = self.base64_encode_bytes(self.__data)

        file_metadata = self.extract_exif(base64_file)

        self.add_attribute('source-file', value=self.__filename)

        for k, v in file_metadata.items():
            sanitized_key_name = re.sub(r'\W', '-', k)
            if type(v) is None:
                pass
            elif v == '':
                pass
            else:
                self.add_attribute(sanitized_key_name, value=v)

