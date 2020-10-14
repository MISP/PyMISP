#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .abstractgenerator import AbstractMISPObjectGenerator
import logging

logger = logging.getLogger('pymisp')


class GitVulnFinderObject(AbstractMISPObjectGenerator):

    def __init__(self, parameters: dict, strict: bool = True, **kwargs):
        super(GitVulnFinderObject, self).__init__('git-vuln-finder', strict=strict, **kwargs)
        self._parameters = parameters
        self.generate_attributes()

    def generate_attributes(self):
        authored_date = self._sanitize_timestamp(self._parameters.pop('authored_date', None))
        self._parameters['authored_date'] = authored_date
        committed_date = self._sanitize_timestamp(self._parameters.pop('committed_date', None))
        self._parameters['committed_date'] = committed_date
        if 'stats' in self._parameters:
            stats = self._parameters.pop('stats')
            self._parameters['stats.insertions'] = stats.pop('insertions')
            self._parameters['stats.deletions'] = stats.pop('deletions')
            self._parameters['stats.lines'] = stats.pop('lines')
            self._parameters['stats.files'] = stats.pop('files')
        return super(GitVulnFinderObject, self).generate_attributes()
