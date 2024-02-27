#!/usr/bin/env python3

from __future__ import annotations

import logging

from io import StringIO
from pathlib import Path

from ..exceptions import InvalidMISPObject
from .abstractgenerator import AbstractMISPObjectGenerator

logger = logging.getLogger('pymisp')


class SSHAuthorizedKeysObject(AbstractMISPObjectGenerator):

    def __init__(self, authorized_keys_path: Path | str | None = None,  # type: ignore[no-untyped-def]
                 authorized_keys_pseudofile: StringIO | None = None, **kwargs):
        super().__init__('ssh-authorized-keys', **kwargs)
        if authorized_keys_path:
            with open(authorized_keys_path) as f:
                self.__pseudofile = StringIO(f.read())
        elif authorized_keys_pseudofile and isinstance(authorized_keys_pseudofile, StringIO):
            self.__pseudofile = authorized_keys_pseudofile
        else:
            raise InvalidMISPObject('File buffer (StringIO) or a path is required.')
        self.__data = self.__pseudofile.getvalue()
        self.generate_attributes()

    def generate_attributes(self) -> None:
        for line in self.__pseudofile:
            if line.startswith('ssh') or line.startswith('ecdsa'):
                key = line.split(' ')[1]
                self.add_attribute('key', key)
