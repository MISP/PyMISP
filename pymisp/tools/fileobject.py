#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ..exceptions import InvalidMISPObject
from .abstractgenerator import AbstractMISPObjectGenerator
import os
from io import BytesIO
from hashlib import md5, sha1, sha256, sha512
import math
from collections import Counter
import logging
from pathlib import Path
from typing import Union

logger = logging.getLogger('pymisp')


try:
    import pydeep  # type: ignore
    HAS_PYDEEP = True
except ImportError:
    HAS_PYDEEP = False

try:
    import magic  # type: ignore
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False


class FileObject(AbstractMISPObjectGenerator):

    def __init__(self, filepath: Union[Path, str] = None, pseudofile: BytesIO = None, filename: str = None, **kwargs):
        # PY3 way:
        # super().__init__('file')
        super(FileObject, self).__init__('file', **kwargs)
        if not HAS_PYDEEP:
            logger.warning("Please install pydeep: pip install git+https://github.com/kbandla/pydeep.git")
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
        self.__data = self.__pseudofile.getvalue()
        self.generate_attributes()

    def generate_attributes(self):
        self.add_attribute('filename', value=self.__filename)
        size = self.add_attribute('size-in-bytes', value=len(self.__data))
        if int(size.value) > 0:
            self.add_attribute('entropy', value=self.__entropy_H(self.__data))
            self.add_attribute('md5', value=md5(self.__data).hexdigest())
            self.add_attribute('sha1', value=sha1(self.__data).hexdigest())
            self.add_attribute('sha256', value=sha256(self.__data).hexdigest())
            self.add_attribute('sha512', value=sha512(self.__data).hexdigest())
            self.add_attribute('malware-sample', value=self.__filename, data=self.__pseudofile, disable_correlation=True)
            if HAS_MAGIC:
                self.add_attribute('mimetype', value=magic.from_buffer(self.__data, mime=True))
            if HAS_PYDEEP:
                self.add_attribute('ssdeep', value=pydeep.hash_buf(self.__data).decode())

    def __entropy_H(self, data: bytes) -> float:
        """Calculate the entropy of a chunk of data."""
        # NOTE: copy of the entropy function from pefile

        if len(data) == 0:
            return 0.0

        occurrences = Counter(bytearray(data))

        entropy = 0.0
        for x in occurrences.values():
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)

        return entropy
