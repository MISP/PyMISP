#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ..exceptions import InvalidMISPObject
from .abstractgenerator import AbstractMISPObjectGenerator
from io import BytesIO
import logging
from email import message_from_bytes, policy

logger = logging.getLogger('pymisp')


class EMailObject(AbstractMISPObjectGenerator):

    def __init__(self, filepath=None, pseudofile=None, attach_original_email=True, standalone=True, **kwargs):
        if filepath:
            with open(filepath, 'rb') as f:
                self.__pseudofile = BytesIO(f.read())
        elif pseudofile and isinstance(pseudofile, BytesIO):
            self.__pseudofile = pseudofile
        else:
            raise InvalidMISPObject('File buffer (BytesIO) or a path is required.')
        # PY3 way:
        # super().__init__('file')
        super(EMailObject, self).__init__('email', standalone=standalone, **kwargs)
        self.__email = message_from_bytes(self.__pseudofile.getvalue(), policy=policy.default)
        if attach_original_email:
            self.add_attribute('eml', value='Full email.eml', data=self.__pseudofile)
        self.generate_attributes()

    @property
    def email(self):
        return self.__email

    @property
    def attachments(self):
        to_return = []
        for attachment in self.__email.iter_attachments():
            content = attachment.get_content()
            if isinstance(content, str):
                content = content.encode()
            to_return.append((attachment.get_filename(), BytesIO(content)))
        return to_return

    def generate_attributes(self):
        if self.__email.get_body(preferencelist=('html', 'plain')):
            self.add_attribute('email-body', value=self.__email.get_body(preferencelist=('html', 'plain')).get_payload(decode=True).decode('utf8', 'surrogateescape'))
        if 'Reply-To' in self.__email:
            self.add_attribute('reply-to', value=self.__email['Reply-To'])
        if 'Message-ID' in self.__email:
            self.add_attribute('message-id', value=self.__email['Message-ID'])
        if 'To' in self.__email:
            to_add = [to.strip() for to in self.__email['To'].split(',')]
            self.add_attributes('to', *to_add)
        if 'Cc' in self.__email:
            to_add = [to.strip() for to in self.__email['Cc'].split(',')]
            self.add_attributes('cc', *to_add)
        if 'Subject' in self.__email:
            self.add_attribute('subject', value=self.__email['Subject'])
        if 'From' in self.__email:
            to_add = [to.strip() for to in self.__email['From'].split(',')]
            self.add_attributes('from', *to_add)
        if 'Return-Path' in self.__email:
            self.add_attribute('return-path', value=self.__email['Return-Path'])
        if 'User-Agent' in self.__email:
            self.add_attribute('user-agent', value=self.__email['User-Agent'])
