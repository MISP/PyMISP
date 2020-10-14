#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .abstractgenerator import AbstractMISPObjectGenerator
import logging
from pyfaup.faup import Faup  # type: ignore
from urllib.parse import unquote_plus

logger = logging.getLogger('pymisp')

faup = Faup()


class URLObject(AbstractMISPObjectGenerator):

    def __init__(self, url: str, **kwargs):
        # PY3 way:
        # super().__init__('file')
        super(URLObject, self).__init__('url', **kwargs)
        faup.decode(unquote_plus(url))
        self.generate_attributes()

    def generate_attributes(self):
        self.add_attribute('url', value=faup.url.decode())
        if faup.get_host():
            self.add_attribute('host', value=faup.get_host())
        if faup.get_domain():
            self.add_attribute('domain', value=faup.get_domain())
