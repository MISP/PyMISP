#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .abstractgenerator import AbstractMISPObjectGenerator
import logging

logger = logging.getLogger('pymisp')


class DomainIPObject(AbstractMISPObjectGenerator):

    def __init__(self, parameters: dict, strict: bool = True, **kwargs):
        super().__init__('domain-ip', strict=strict, **kwargs)
        self._parameters = parameters
        self.generate_attributes()

    def generate_attributes(self):
        first = self._sanitize_timestamp(self._parameters.pop('first-seen', None))
        self._parameters['first-seen'] = first
        last = self._sanitize_timestamp(self._parameters.pop('last-seen', None))
        self._parameters['last-seen'] = last
        super().generate_attributes()
