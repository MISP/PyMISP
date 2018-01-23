#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import requests
from .abstractgenerator import AbstractMISPObjectGenerator
from .. import InvalidMISPObject

class SBSignatureObject(AbstractMISPObjectGenerator):
    '''
    Sandbox Analyzer
    '''
    def __init__(self, report, software, parsed=None, filepath=None, pseudofile=None, standalone=True, **kwargs):
        # PY3 way:
        # super().__init__("virustotal-report")
        super(SBSignatureObject, self).__init__("sb-signature", **kwargs)
        self._report = report
        self._software = software
        self.generate_attributes()

    def generate_attributes(self):
        ''' Parse the report for relevant attributes '''
        self.add_attribute("software", value=self._software, type="text")
        for (name, description) in self._report:            
            self.add_attribute("signature", value=name, comment=description, type="text")        
            