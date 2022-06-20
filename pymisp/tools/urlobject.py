#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .abstractgenerator import AbstractMISPObjectGenerator
import logging
from urllib.parse import unquote_plus

try:
    from pyfaup.faup import Faup  # type: ignore
except (OSError, ImportError):
    from ._psl_faup import PSLFaup as Faup

logger = logging.getLogger('pymisp')

faup = Faup()


class URLObject(AbstractMISPObjectGenerator):

    def __init__(self, url: str, generate_all=False, **kwargs):
        super().__init__('url', **kwargs)
        self._generate_all = True if generate_all is True else False
        faup.decode(unquote_plus(url))
        self.generate_attributes()

    def generate_attributes(self):
        self.add_attribute('url', value=faup.url.decode())
        if faup.get_host():
            self.add_attribute('host', value=faup.get_host())
        if faup.get_domain():
            self.add_attribute('domain', value=faup.get_domain())
        if self._generate_all:
            if hasattr(faup, 'ip_as_host') and faup.ip_as_host:
                self.attributes = [attr for attr in self.attributes
                                   if attr.object_relation not in ('host', 'domain')]
                self.add_attribute('ip', value=faup.ip_as_host)
            if faup.get_credential():
                self.add_attribute('credential', value=faup.get_credential())
            if faup.get_fragment():
                self.add_attribute('fragment', value=faup.get_fragment())
            if faup.get_port():
                self.add_attribute('port', value=faup.get_port())
            if faup.get_query_string():
                self.add_attribute('query_string', value=faup.get_query_string())
            if faup.get_resource_path():
                self.add_attribute('resource_path', value=faup.get_resource_path())
            if faup.get_scheme():
                self.add_attribute('scheme', value=faup.get_scheme())
            if faup.get_tld():
                self.add_attribute('tld', value=faup.get_tld())
            if faup.get_domain_without_tld():
                self.add_attribute('domain_without_tld', value=faup.get_domain_without_tld())
            if faup.get_subdomain():
                self.add_attribute('subdomain', value=faup.get_subdomain())
            if hasattr(faup, 'get_unicode_host') and faup.get_unicode_host() != faup.get_host():
                self.add_attribute('text', value=faup.get_unicode_host())
