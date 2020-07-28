#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ..exceptions import InvalidMISPObject
from .abstractgenerator import AbstractMISPObjectGenerator
from io import BytesIO
import logging
from email import message_from_bytes, policy
from pathlib import Path
from typing import Union

logger = logging.getLogger('pymisp')


class EMailObject(AbstractMISPObjectGenerator):

    def __init__(self, filepath: Union[Path, str] = None, pseudofile: BytesIO = None, attach_original_email: bool = True, **kwargs):
        # PY3 way:
        # super().__init__('file')
        super(EMailObject, self).__init__('email', **kwargs)
        if filepath:
            with open(filepath, 'rb') as f:
                self.__pseudofile = BytesIO(f.read())
        elif pseudofile and isinstance(pseudofile, BytesIO):
            self.__pseudofile = pseudofile
        else:
            raise InvalidMISPObject('File buffer (BytesIO) or a path is required.')
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
            # TODO: split name and email address
            to_add = [to.strip() for to in self.__email['To'].split(',')]
            self.add_attributes('to', *to_add)
        if 'Cc' in self.__email:
            # TODO: split name and email address
            to_add = [to.strip() for to in self.__email['Cc'].split(',')]
            self.add_attributes('cc', *to_add)
        if 'Subject' in self.__email:
            self.add_attribute('subject', value=self.__email['Subject'])
        if 'From' in self.__email:
            # TODO: split name and email address
            to_add = [to.strip() for to in self.__email['From'].split(',')]
            self.add_attributes('from', *to_add)
        if 'Return-Path' in self.__email:
            # TODO: split name and email address
            self.add_attribute('return-path', value=self.__email['Return-Path'])
        if 'User-Agent' in self.__email:
            self.add_attribute('user-agent', value=self.__email['User-Agent'])
        if self.__email.get_boundary():
            self.add_attribute('mime-boundary', value=self.__email.get_boundary())
        if 'X-Mailer' in self.__email:
            self.add_attribute('x-mailer', value=self.__email['X-Mailer'])
        if 'Thread-Index' in self.__email:
            self.add_attribute('thread-index', value=self.__email['Thread-Index'])
        # TODO: email-header: all headers in one bloc
        # TODO: BCC?
        # TODO: received headers sometimes have TO email addresses
