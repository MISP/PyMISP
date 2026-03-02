#!/usr/bin/env python

from __future__ import annotations

import logging
import re

from io import BytesIO

from .abstractgenerator import AbstractMISPObjectGenerator
from ..exceptions import MISPObjectException

logger = logging.getLogger('pymisp')


class DataURLObject(AbstractMISPObjectGenerator):

    def __init__(self, dataurl: str, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__('data-url', **kwargs)

        if stripped_dataurl := dataurl.strip():
            if not re.match("data:", stripped_dataurl, re.I):
                raise MISPObjectException('Not a data URL (does not start with data:')

            self._dataurl = stripped_dataurl[5:]
            self.generate_attributes()
        else:
            raise MISPObjectException('No Data URL provided (empty string)')

    def _parse_dataurl(self) -> tuple[str, str, bool, str]:
        base64 = bool(re.match(r'.*;base64,.*', self._dataurl))
        if base64:
            mime, data = self._dataurl.split(';base64,')
        else:
            mime, data = self._dataurl.split(',')
        if mime and ';' in mime:
            mime, param = mime.split(';', 1)
        else:
            param = ''

        return mime, param, base64, data

    def generate_attributes(self) -> None:
        try:
            mime, param, base64, data = self._parse_dataurl()
        except Exception as e:
            raise MISPObjectException(f'Invalid Data URL: {self._dataurl} - {e}')

        self.add_attribute('data', value='data.txt', data=BytesIO(data.encode()))
        self.add_attribute('base64', value=base64)
        if mime:
            self.add_attribute('media-type', value=mime)
        if param:
            self.add_attribute('mime-type-parameter', value=param)
