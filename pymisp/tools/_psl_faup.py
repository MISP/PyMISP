#!/usr/bin/env python

from __future__ import annotations

import ipaddress
import socket
import idna
from publicsuffixlist import PublicSuffixList  # type: ignore
from urllib.parse import urlparse, urlunparse, ParseResult


class UrlNotDecoded(Exception):
    pass


class PSLFaup:
    """
    Fake Faup Python Library using PSL for Windows support
    """

    def __init__(self) -> None:
        self.decoded = False
        self.psl = PublicSuffixList()
        self._url: ParseResult | None = None
        self._retval: dict[str, str | int | None | bytes] = {}
        self.ip_as_host = ''

    def _clear(self) -> None:
        self.decoded = False
        self._url = None
        self._retval = {}
        self.ip_as_host = ''

    def decode(self, url: str) -> None:
        """
        This function creates a dict of all the url fields.
        :param url: The URL to normalize
        """
        self._clear()
        if isinstance(url, bytes) and b'//' not in url[:10]:
            url = b'//' + url
        elif '//' not in url[:10]:
            url = '//' + url
        self._url = urlparse(url)

        if self._url is None:
            raise UrlNotDecoded("Unable to parse URL")

        self.ip_as_host = ''
        if self._url.hostname is None:
            raise UrlNotDecoded("Unable to parse URL")
        hostname = _ensure_str(self._url.hostname)
        try:
            ipv4_bytes = socket.inet_aton(hostname)
            ipv4 = ipaddress.IPv4Address(ipv4_bytes)
            self.ip_as_host = ipv4.compressed
        except (OSError, ValueError):
            try:
                addr, _, _ = hostname.partition('%')
                ipv6 = ipaddress.IPv6Address(addr)
                self.ip_as_host = ipv6.compressed
            except ValueError:
                pass

        self.decoded = True
        self._retval = {}

    @property
    def url(self) -> bytes | None:
        if not self.decoded or not self._url:
            raise UrlNotDecoded("You must call faup.decode() first")

        if host := self.get_host():
            netloc = host + ('' if self.get_port() is None else f':{self.get_port()}')
            return _ensure_bytes(
                urlunparse(
                    (self.get_scheme(), netloc, self.get_resource_path(),
                     '', self.get_query_string(), self.get_fragment(),)
                )
            )
        return None

    def get_scheme(self) -> str:
        """
        Get the scheme of the url given in the decode function
        :returns: The URL scheme
        """
        if not self.decoded or not self._url:
            raise UrlNotDecoded("You must call faup.decode() first")

        return _ensure_str(self._url.scheme if self._url.scheme else '')

    def get_credential(self) -> str | None:
        if not self.decoded or not self._url:
            raise UrlNotDecoded("You must call faup.decode() first")

        if self._url.username and self._url.password:
            return _ensure_str(self._url.username) + ':' + _ensure_str(self._url.password)
        if self._url.username:
            return _ensure_str(self._url.username)
        return None

    def get_subdomain(self) -> str | None:
        if not self.decoded or not self._url:
            raise UrlNotDecoded("You must call faup.decode() first")

        if self.get_host() is not None and not self.ip_as_host:
            domain = self.get_domain()
            host = self.get_host()
            if domain and host and domain in host:
                return host.rsplit(domain, 1)[0].rstrip('.') or None
        return None

    def get_domain(self) -> str | None:
        if not self.decoded or not self._url:
            raise UrlNotDecoded("You must call faup.decode() first")

        if self.get_host() is not None and not self.ip_as_host:
            return self.psl.privatesuffix(self.get_host())
        return None

    def get_domain_without_tld(self) -> str | None:
        if not self.decoded or not self._url:
            raise UrlNotDecoded("You must call faup.decode() first")

        if self.get_tld() is not None and not self.ip_as_host:
            if domain := self.get_domain():
                return domain.rsplit(self.get_tld(), 1)[0].rstrip('.')
        return None

    def get_host(self) -> str | None:
        if not self.decoded or not self._url:
            raise UrlNotDecoded("You must call faup.decode() first")

        if self._url.hostname is None:
            return None
        elif self._url.hostname.isascii():
            return _ensure_str(self._url.hostname)
        else:
            return _ensure_str(idna.encode(self._url.hostname, uts46=True))

    def get_unicode_host(self) -> str | None:
        if not self.decoded or not self._url:
            raise UrlNotDecoded("You must call faup.decode() first")

        if not self.ip_as_host:
            if host := self.get_host():
                return idna.decode(host, uts46=True)
        return None

    def get_tld(self) -> str | None:
        if not self.decoded or not self._url:
            raise UrlNotDecoded("You must call faup.decode() first")

        if self.get_host() is not None and not self.ip_as_host:
            return self.psl.publicsuffix(self.get_host())
        return None

    def get_port(self) -> int | None:
        if not self.decoded or not self._url:
            raise UrlNotDecoded("You must call faup.decode() first")

        return self._url.port

    def get_resource_path(self) -> str:
        if not self.decoded or not self._url:
            raise UrlNotDecoded("You must call faup.decode() first")

        return _ensure_str(self._url.path)

    def get_query_string(self) -> str:
        if not self.decoded or not self._url:
            raise UrlNotDecoded("You must call faup.decode() first")

        return _ensure_str(self._url.query)

    def get_fragment(self) -> str:
        if not self.decoded or not self._url:
            raise UrlNotDecoded("You must call faup.decode() first")

        return _ensure_str(self._url.fragment)

    def get(self) -> dict[str, str | int | None | bytes]:
        self._retval["scheme"] = self.get_scheme()
        self._retval["tld"] = self.get_tld()
        self._retval["domain"] = self.get_domain()
        self._retval["domain_without_tld"] = self.get_domain_without_tld()
        self._retval["subdomain"] = self.get_subdomain()
        self._retval["host"] = self.get_host()
        self._retval["port"] = self.get_port()
        self._retval["resource_path"] = self.get_resource_path()
        self._retval["query_string"] = self.get_query_string()
        self._retval["fragment"] = self.get_fragment()
        self._retval["url"] = self.url
        return self._retval


def _ensure_bytes(binary: str | bytes) -> bytes:
    if isinstance(binary, bytes):
        return binary
    else:
        return binary.encode('utf-8')


def _ensure_str(string: str | bytes) -> str:
    if isinstance(string, str):
        return string
    else:
        return string.decode('utf-8')
