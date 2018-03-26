#!/usr/bin/env python
# -*- coding: utf-8 -*-

from datetime import datetime
from .abstractgenerator import AbstractMISPObjectGenerator
import logging
from dateutil.parser import parse

logger = logging.getLogger('pymisp')


class Fail2BanObject(AbstractMISPObjectGenerator):

    def __init__(self, parameters, standalone=True, **kwargs):
        super(Fail2BanObject, self).__init__('fail2ban', standalone=standalone, **kwargs)
        self.__parameters = parameters
        self.generate_attributes()

    def generate_attributes(self):
        self.add_attribute('banned-ip', value=self.__parameters['banned-ip'])
        self.add_attribute('attack-type', value=self.__parameters['attack-type'])
        try:
            timestamp = parse(self.__parameters['processing-timestamp'])
        except Exception:
            timestamp = datetime.now()

        self.add_attribute('processing-timestamp', value=timestamp.isoformat())

        if 'failures' in self.__parameters:
            self.add_attribute('failures', value=self.__parameters['failures'])
        if 'sensor' in self.__parameters:
            self.add_attribute('', value=self.__parameters['sensor'])
        if 'victim' in self.__parameters:
            self.add_attribute('victim', value=self.__parameters['victim'])
