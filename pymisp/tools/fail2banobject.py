#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .abstractgenerator import AbstractMISPObjectGenerator
import logging

logger = logging.getLogger('pymisp')


class Fail2BanObject(AbstractMISPObjectGenerator):

    def __init__(self, parameters: dict, strict: bool = True, **kwargs):
        super().__init__('fail2ban', strict=strict, **kwargs)
        self._parameters = parameters
        self.generate_attributes()

    def generate_attributes(self):
        timestamp = self._sanitize_timestamp(self._parameters.pop('processing-timestamp', None))
        self._parameters['processing-timestamp'] = timestamp
        super().generate_attributes()
