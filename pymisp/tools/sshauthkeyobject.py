#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ..exceptions import InvalidMISPObject
from .abstractgenerator import AbstractMISPObjectGenerator
from io import StringIO
import logging
from typing import Optional, Union
from pathlib import Path

logger = logging.getLogger('pymisp')


class SSHAuthorizedKeysObject(AbstractMISPObjectGenerator):

    def __init__(self, authorized_keys_path: Optional[Union[Path, str]] = None, authorized_keys_pseudofile: Optional[StringIO] = None, **kwargs):
        # PY3 way:
        # super().__init__('file')
        super(SSHAuthorizedKeysObject, self).__init__('ssh-authorized-keys', **kwargs)
        if authorized_keys_path:
            with open(authorized_keys_path, 'r') as f:
                self.__pseudofile = StringIO(f.read())
        elif authorized_keys_pseudofile and isinstance(authorized_keys_pseudofile, StringIO):
            self.__pseudofile = authorized_keys_pseudofile
        else:
            raise InvalidMISPObject('File buffer (StringIO) or a path is required.')
        self.__data = self.__pseudofile.getvalue()
        self.generate_attributes()

    def generate_attributes(self):
        for line in self.__pseudofile:
            if line.startswith('ssh') or line.startswith('ecdsa'):
                key = line.split(' ')[1]
                self.add_attribute('key', key)
