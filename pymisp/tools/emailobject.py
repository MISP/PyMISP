#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ..exceptions import InvalidMISPObject
from .abstractgenerator import AbstractMISPObjectGenerator
from io import BytesIO
import logging
from email import message_from_bytes

logger = logging.getLogger('pymisp')


class EMailObject(AbstractMISPObjectGenerator):

    def __init__(self, filepath=None, pseudofile=None, standalone=True, **kwargs):
        if filepath:
            with open(filepath, 'rb') as f:
                pseudofile = BytesIO(f.read())
        elif pseudofile and isinstance(pseudofile, BytesIO):
            pseudofile = pseudofile
        else:
            raise InvalidMISPObject('File buffer (BytesIO) or a path is required.')
        # PY3 way:
        # super().__init__('file')
        super(EMailObject, self).__init__('email', standalone=standalone, **kwargs)
        self.__email = message_from_bytes(pseudofile.getvalue())
        self.generate_attributes()

    def generate_attributes(self):
        if 'Reply-To' in self.__email:
            self.add_attribute('reply-to', value=self.__email['Reply-To'])
        if 'Message-ID' in self.__email:
            self.add_attribute('message-id', value=self.__email['Message-ID'])
        if 'To' in self.__email:
            for to in self.__email['To'].split(','):
                self.add_attribute('to', value=to.strip())
        if 'Cc' in self.__email:
            for cc in self.__email['Cc'].split(','):
                self.add_attribute('cc', value=cc.strip())
        if 'Subject' in self.__email:
            self.add_attribute('subject', value=self.__email['Subject'])
        if 'From' in self.__email:
            for e_from in self.__email['From'].split(','):
                self.add_attribute('from', value=e_from.strip())
        if 'Return-Path' in self.__email:
            self.add_attribute('return-path', value=self.__email['Return-Path'])
        # TODO: self.add_attribute('attachment', value=)
