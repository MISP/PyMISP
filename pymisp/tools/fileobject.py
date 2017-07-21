#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pymisp.tools import MISPObjectGenerator
import os
from io import BytesIO
from hashlib import md5, sha1, sha256, sha512
import math
from collections import Counter

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
            raise ImportError("Please install pydeep: pip install git+https://github.com/kbandla/pydeep.git")
        if not HAS_MAGIC:
            raise ImportError("Please install python-magic: pip install python-magic.")
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
        MISPObjectGenerator.__init__(self, 'file')
        self.data = self.pseudofile.getvalue()
        self.generate_attributes()

    def generate_attributes(self):
        self.size = len(self.data)
        if self.size > 0:
            self.entropy = self.__entropy_H(self.data)
            self.md5 = md5(self.data).hexdigest()
            self.sha1 = sha1(self.data).hexdigest()
            self.sha256 = sha256(self.data).hexdigest()
            self.sha512 = sha512(self.data).hexdigest()
            self.filetype = magic.from_buffer(self.data)
            self.ssdeep = pydeep.hash_buf(self.data).decode()

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

    def dump(self):
        file_object = {}
        file_object['filename'] = {'value': self.filename}
        file_object['size-in-bytes'] = {'value': self.size}
        if self.size > 0:
            file_object['entropy'] = {'value': self.entropy}
            file_object['ssdeep'] = {'value': self.ssdeep}
            file_object['sha512'] = {'value': self.sha512}
            file_object['md5'] = {'value': self.md5}
            file_object['sha1'] = {'value': self.sha1}
            file_object['sha256'] = {'value': self.sha256}
            file_object['malware-sample'] = {'value': '{}|{}'.format(self.filename, self.md5), 'data': self.pseudofile}
            # file_object['authentihash'] = self.
            # file_object['sha-224'] = self.
            # file_object['sha-384'] = self.
            # file_object['sha512/224'] = self.
            # file_object['sha512/256'] = self.
            # file_object['tlsh'] = self.
        return self._fill_object(file_object)
