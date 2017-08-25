#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pymisp.tools import MISPObjectGenerator
import os
from io import BytesIO
from hashlib import md5, sha1, sha256, sha512
import math
from collections import Counter
import warnings

try:
    import pydeep
    HAS_PYDEEP = True
except ImportError:
    HAS_PYDEEP = False

try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False


class FileObject(MISPObjectGenerator):

    def __init__(self, filepath=None, pseudofile=None, filename=None):
        if not HAS_PYDEEP:
            warnings.warn("Please install pydeep: pip install git+https://github.com/kbandla/pydeep.git")
        if not HAS_MAGIC:
            warnings.warn("Please install python-magic: pip install python-magic.")
        if filepath:
            self.filepath = filepath
            self.filename = os.path.basename(self.filepath)
            with open(filepath, 'rb') as f:
                self.pseudofile = BytesIO(f.read())
        elif pseudofile and isinstance(pseudofile, BytesIO):
            # WARNING: lief.parse requires a path
            self.filepath = None
            self.pseudofile = pseudofile
            self.filename = filename
        else:
            raise Exception('File buffer (BytesIO) or a path is required.')
        # PY3 way:
        # super().__init__('file')
        super(FileObject, self).__init__('file')
        self.data = self.pseudofile.getvalue()
        self.generate_attributes()

    def generate_attributes(self):
        self._create_attribute('filename', value=self.filename)
        size = self._create_attribute('size-in-bytes', value=len(self.data))
        if int(size.value) > 0:
            self._create_attribute('entropy', value=self.__entropy_H(self.data))
            self._create_attribute('md5', value=md5(self.data).hexdigest())
            self._create_attribute('sha1', value=sha1(self.data).hexdigest())
            self._create_attribute('sha256', value=sha256(self.data).hexdigest())
            self._create_attribute('sha512', value=sha512(self.data).hexdigest())
            self._create_attribute('malware-sample', value=self.filename, data=self.pseudofile)
            if HAS_MAGIC:
                self._create_attribute('mimetype', value=magic.from_buffer(self.data))
            if HAS_PYDEEP:
                self._create_attribute('ssdeep', value=pydeep.hash_buf(self.data).decode())

    def __entropy_H(self, data):
        """Calculate the entropy of a chunk of data."""
        # NOTE: copy of the entropy function from pefile

        if len(data) == 0:
            return 0.0

        occurences = Counter(bytearray(data))

        entropy = 0
        for x in occurences.values():
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)

        return entropy
