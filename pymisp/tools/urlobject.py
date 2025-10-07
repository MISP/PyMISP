#!/usr/bin/env python

from __future__ import annotations

import logging

from ipaddress import ip_address
from urllib.parse import unquote_plus

from .abstractgenerator import AbstractMISPObjectGenerator

try:
    from pyfaup import Url
    HAS_FAUP_RS = True
except (OSError, ImportError):
    from ._psl_faup import PSLFaup as Faup
    faup = Faup()
    HAS_FAUP_RS = False

logger = logging.getLogger('pymisp')


class URLObject(AbstractMISPObjectGenerator):

    def __init__(self, url: str, generate_all=False, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__('url', **kwargs)
        self._generate_all = True if generate_all is True else False
        if not HAS_FAUP_RS:
            faup.decode(unquote_plus(url))
        else:
            self.parsed_url = Url(unquote_plus(url))
        self.generate_attributes()

    def generate_attributes(self) -> None:
        if HAS_FAUP_RS:
            self.add_attribute('url', value=self.parsed_url.orig)
            self.add_attribute('host', value=self.parsed_url.host)
            self.add_attribute('domain', value=self.parsed_url.domain)
            if self._generate_all:
                try:
                    ip = ip_address(self.parsed_url.host)
                    self.add_attribute('ip', value=str(ip))
                except Exception:
                    # not an IP
                    pass
                self.add_attribute('fragment', value=self.parsed_url.fragment)
                self.add_attribute('port', value=self.parsed_url.port)
                self.add_attribute('query_string', value=self.parsed_url.query)
                self.add_attribute('resource_path', value=self.parsed_url.path)
                self.add_attribute('scheme', value=self.parsed_url.scheme)
                self.add_attribute('tld', value=self.parsed_url.suffix)
                self.add_attribute('subdomain', value=self.parsed_url.subdomain)
        else:
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
