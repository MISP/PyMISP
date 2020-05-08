#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .abstractgenerator import AbstractMISPObjectGenerator
import logging

logger = logging.getLogger('pymisp')

class MicroblogObject(AbstractMISPObjectGenerator):

    def __init__(self, parameters: dict, strict: bool = True, standalone: bool = True, **kwargs):
        super(MicroblogObject, self).__init__('microblog', strict=strict, standalone=standalone, **kwargs)
        self._parameters = parameters
        self.generate_attributes()

    def generate_attributes(self):
        # Raw post.
        if self._parameters.get('post'):
            self.add_attribute('post', value=self._parameters['post'])

        # Title of the post.
        if self._parameters.get('title'):
            self.add_attribute('title', value=self._parameters['title'])

        # Original link into the microblog post (Supposed harmless).
        if self._parameters.get('link'):
            self.add_attribute('link', value=self._parameters['link'])

        # Original URL location of the microblog post (potentially malicious.
        if self._parameters.get('url'):
            if type(self._parameters.get('url')) is list:
                for i in self._parameters.get('url'):
                    self.add_attribute('url', value=i)
            else:
                self.add_attribute('url', value=self._parameters['url'])

        # Archive of the original document (Internet Archive, Archive.is, etc).
        if self._parameters.get('archive'):
            if type(self._parameters.get('archive')) == list:
                for i in self._parameters.get('archive'):
                    self.add_attribute('archive', value=i)
            else:
                self.add_attribute('archive', value=self._parameters['archive'])

        # Display name of the account who posted the microblog.
        if self._parameters.get('display-name'):
            self.add_attribute('display-name', value=self._parameters['display-name'])

        # The user ID of the microblog this post replies to.
        if self._parameters.get('in-reply-to-user-id'):
            self.add_attribute('in-reply-to-user-id', value=self._parameters['in-reply-to-user-id'])

        # The microblog ID of the microblog this post replies to.
        if self._parameters.get('in-reply-to-status-id'):
            self.add_attribute('in-reply-to-status-id', value=self._parameters['in-reply-to-status-id'])

        # The user display name of the microblog this post replies to.
        if self._parameters.get('in-reply-to-display-name'):
            self.add_attribute('in-reply-to-display-name', value=self._parameters['in-reply-to-display-name'])

        # The language of the post.
        if self._parameters.get('language'):
            self.add_attribute('language', value=self._parameters['language'], disable_correlation=True)

        # TODO: handle attachments
        # The microblog post file or screen capture.
        # if self._parameters.get('attachment'):
        #     self.add_attribute('attachment', value=self._parameters['attachment'])

        # Type of the microblog post.
        type_allowed_values = ["Twitter", "Facebook", "LinkedIn", "Reddit", "Google+",
                               "Instagram", "Forum", "Other"]
        if self._parameters.get('type'):
            if type(self._parameters.get('type')) == list:
                for i in self._parameters.get('type'):
                    if i in type_allowed_values:
                        self.add_attribute('type', value=i)
            else:
                if self._parameters['type'] in type_allowed_values:
                    self.add_attribute('type', value=self._parameters['type'])

        # State of the microblog post.
        type_allowed_values = ["Informative", "Malicious", "Misinformation", "Disinformation", "Unknown"]
        if self._parameters.get('state'):
            if type(self._parameters.get('state')) == list:
                for i in self._parameters.get('state'):
                    if i in type_allowed_values:
                        self.add_attribute('state', value=i)
            else:
                if self._parameters['state'] in type_allowed_values:
                    self.add_attribute('state', value=self._parameters['state'])

        # Username who posted the microblog post (without the @ prefix).
        if self._parameters.get('username'):
            self.add_attribute('username', value=self._parameters['username'])

        # == the username account verified by the operator of the microblog platform.
        type_allowed_values = ["Verified", "Unverified", "Unknown"]
        if self._parameters.get('verified-username'):
            if type(self._parameters.get('verified-username')) == list:
                for i in self._parameters.get('verified-username'):
                    if i in type_allowed_values:
                        self.add_attribute('verified-username', value=i)
            else:
                if self._parameters['verified-username'] in type_allowed_values:
                    self.add_attribute('verified-username', value=self._parameters['verified-username'])

        # embedded-link.
        if self._parameters.get('embedded-link'):
            if type(self._parameters.get('embedded-link')) == list:
                for i in self._parameters.get('embedded-link'):
                    self.add_attribute('embedded-link', value=i)
            else:
                self.add_attribute('embedded-link', value=self._parameters['embedded-link'])

        # embedded-safe-link
        if self._parameters.get('embedded-safe-link'):
            if type(self._parameters.get('embedded-safe-link')) == list:
                for i in self._parameters.get('embedded-safe-link'):
                    self.add_attribute('embedded-safe-link', value=i)
            else:
                self.add_attribute('embedded-safe-link', value=self._parameters['embedded-safe-link'])

        # Hashtag into the microblog post.
        if self._parameters.get('hashtag'):
            if type(self._parameters.get('hashtag')) == list:
                for i in self._parameters.get('hashtag'):
                    self.add_attribute('hashtag', value=i)
            else:
                self.add_attribute('hashtag', value=self._parameters['hashtag'])

        # username quoted
        if self._parameters.get('username-quoted'):
            if type(self._parameters.get('username-quoted')) == list:
                for i in self._parameters.get('username-quoted'):
                    self.add_attribute('username-quoted', value=i)
            else:
                self.add_attribute('username-quoted', value=self._parameters['username-quoted'])

        # twitter post id
        if self._parameters.get('twitter-id'):
            self.add_attribute('twitter-id', value=self._parameters['twitter-id'])