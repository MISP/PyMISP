#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import six
from .. import MISPObject
from ..exceptions import InvalidMISPObject
from datetime import datetime, date
from dateutil.parser import parse


@six.add_metaclass(abc.ABCMeta)   # Remove that line when discarding python2 support.
# Python3 way: class MISPObjectGenerator(metaclass=abc.ABCMeta):
class AbstractMISPObjectGenerator(MISPObject):

    def _detect_epoch(self, timestamp):
        try:
            tmp = float(timestamp)
            if tmp < 30000000:
                # Assuming the user doesn't want to report anything before datetime(1970, 12, 14, 6, 20)
                # The date is most probably in the format 20180301
                return False
            return True
        except ValueError:
            return False

    def _sanitize_timestamp(self, timestamp):
        if not timestamp:
            return datetime.now()

        if isinstance(timestamp, datetime):
            return timestamp
        elif isinstance(timestamp, date):
            return datetime.combine(timestamp, datetime.min.time())
        elif isinstance(timestamp, dict):
            if not isinstance(timestamp['value'], datetime):
                timestamp['value'] = parse(timestamp['value'])
            return timestamp
        elif not isinstance(timestamp, datetime):  # Supported: float/int/string
            if self._detect_epoch(timestamp):
                return datetime.fromtimestamp(float(timestamp))
            return parse(timestamp)
        return timestamp

    def generate_attributes(self):
        """Contains the logic where all the values of the object are gathered"""
        if hasattr(self, '_parameters'):
            for object_relation in self._definition['attributes']:
                value = self._parameters.pop(object_relation, None)
                if not value:
                    continue
                if isinstance(value, dict):
                    self.add_attribute(object_relation, **value)
                else:
                    # Assume it is the value only
                    self.add_attribute(object_relation, value=value)
            if self._strict and self._known_template and self._parameters:
                raise InvalidMISPObject('Some object relations are unknown in the template and could not be attached: {}'.format(', '.join(self._parameters)))
