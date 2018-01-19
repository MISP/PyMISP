#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

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
    def __init__(self, apikey, indicator, vt_proxies=None, standalone=True, **kwargs):
        # PY3 way:
        # super().__init__("virustotal-report")
        super(VTReportObject, self).__init__("virustotal-report", standalone=standalone, **kwargs)
        indicator = indicator.strip()
        self._resource_type = self.__validate_resource(indicator)
        if self._resource_type:
            self._proxies = vt_proxies
            self._report = self.__query_virustotal(apikey, indicator)
            self.generate_attributes()
        else:
            error_msg = "A valid indicator is required. (One of type url, md5, sha1, sha256). Received '{}' instead".format(indicator)
            raise InvalidMISPObject(error_msg)

    def get_report(self):
        return self._report

    def generate_attributes(self):
        ''' Parse the VirusTotal report for relevant attributes '''
        self.add_attribute("last-submission", value=self._report["scan_date"])
        self.add_attribute("permalink", value=self._report["permalink"])
        ratio = "{}/{}".format(self._report["positives"], self._report["total"])
        self.add_attribute("detection-ratio", value=ratio)

    def __validate_resource(self, ioc):
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

    def __query_virustotal(self, apikey, resource):
        '''
        Query VirusTotal for information about an indicator

        :apikey: VirusTotal API key

        :resource: Indicator to search in VirusTotal
        '''
        url = "https://www.virustotal.com/vtapi/v2/{}/report".format(self._resource_type)
        params = {"apikey": apikey, "resource": resource}
        # for now assume we're using a public API key - we'll figure out private keys later
        if self._proxies:
            report = requests.get(url, params=params, proxies=self._proxies)
        else:
            report = requests.get(url, params=params)
        report = report.json()
        if report["response_code"] == 1:
            return report
        else:
            error_msg = "{}: {}".format(resource, report["verbose_msg"])
            raise InvalidMISPObject(error_msg)
