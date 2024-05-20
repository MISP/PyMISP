#!/usr/bin/env python3

from __future__ import annotations

import re
from typing import Any

import requests
try:
    import validators
    has_validators = True
except ImportError:
    has_validators = False


from .abstractgenerator import AbstractMISPObjectGenerator
from .. import InvalidMISPObject


class VTReportObject(AbstractMISPObjectGenerator):
    '''
    VirusTotal Report

    :apikey: VirusTotal API key (private works, but only public features are supported right now)

    :indicator: IOC to search VirusTotal for
    '''
    def __init__(self, apikey: str, indicator: str, vt_proxies: dict[str, str] | None = None, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__('virustotal-report', **kwargs)
        indicator = indicator.strip()
        self._resource_type = self.__validate_resource(indicator)
        if self._resource_type:
            self._proxies = vt_proxies
            self._report = self.__query_virustotal(apikey, indicator)
            self.generate_attributes()
        else:
            error_msg = f"A valid indicator is required. (One of type url, md5, sha1, sha256). Received '{indicator}' instead"
            raise InvalidMISPObject(error_msg)

    def get_report(self) -> dict[str, Any]:
        return self._report

    def generate_attributes(self) -> None:
        ''' Parse the VirusTotal report for relevant attributes '''
        self.add_attribute("last-submission", value=self._report["scan_date"])
        self.add_attribute("permalink", value=self._report["permalink"])
        ratio = "{}/{}".format(self._report["positives"], self._report["total"])
        self.add_attribute("detection-ratio", value=ratio)

    def __validate_resource(self, ioc: str) -> str | bool:
        '''
        Validate the data type of an indicator.
        Domains and IP addresses aren't supported because
        they don't return the same type of data as the URLs/files do

        :ioc: Indicator to search VirusTotal for
        '''
        if not has_validators:
            raise Exception('You need to install validators: pip install validators')
        if validators.url(ioc):
            return "url"
        elif re.match(r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b", ioc):
            return "file"
        return False

    def __query_virustotal(self, apikey: str, resource: str) -> dict[str, Any]:
        '''
        Query VirusTotal for information about an indicator

        :apikey: VirusTotal API key

        :resource: Indicator to search in VirusTotal
        '''
        url = f"https://www.virustotal.com/vtapi/v2/{self._resource_type}/report"
        params = {"apikey": apikey, "resource": resource}
        # for now assume we're using a public API key - we'll figure out private keys later
        if self._proxies:
            report = requests.get(url, params=params, proxies=self._proxies)
        else:
            report = requests.get(url, params=params)
        report_json = report.json()
        if report_json["response_code"] == 1:
            return report_json
        else:
            error_msg = "{}: {}".format(resource, report_json["verbose_msg"])
            raise InvalidMISPObject(error_msg)
