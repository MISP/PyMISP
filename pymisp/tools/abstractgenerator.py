#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .. import MISPObject
from ..exceptions import InvalidMISPObject
from datetime import datetime, date
from dateutil.parser import parse
from typing import Union, Optional


class AbstractMISPObjectGenerator(MISPObject):

    def _detect_epoch(self, timestamp: Union[str, int, float]) -> bool:
        try:
            tmp = float(timestamp)
            if tmp < 30000000:
                # Assuming the user doesn't want to report anything before datetime(1970, 12, 14, 6, 20)
                # The date is most probably in the format 20180301
                return False
            return True
        except ValueError:
            return False

    def _sanitize_timestamp(self, timestamp: Optional[Union[datetime, date, dict, str, int, float]] = None) -> datetime:
        if not timestamp:
            return datetime.now()

        if isinstance(timestamp, datetime):
            return timestamp
        elif isinstance(timestamp, date):
            return datetime.combine(timestamp, datetime.min.time())
        elif isinstance(timestamp, dict):
            if not isinstance(timestamp['value'], datetime):
                timestamp['value'] = parse(timestamp['value'])
            return timestamp['value']
        else:  # Supported: float/int/string
            if isinstance(timestamp, (str, int, float)) and self._detect_epoch(timestamp):
                # It converts to the *local* datetime, which is consistent with the rest of the code.
                return datetime.fromtimestamp(float(timestamp))
            elif isinstance(timestamp, str):
                return parse(timestamp)
            else:
                raise Exception(f'Unable to convert {timestamp} to a datetime.')

    def generate_attributes(self):
        """Contains the logic where all the values of the object are gathered"""
        if hasattr(self, '_parameters'):
            for object_relation in self._definition['attributes']:
                value = self._parameters.pop(object_relation, None)
                if not value:
                    continue
                if isinstance(value, dict):
                    self.add_attribute(object_relation, **value)
                elif isinstance(value, list):
                    self.add_attributes(object_relation, *value)
                else:
                    # Assume it is the value only
                    self.add_attribute(object_relation, value=value)
            if self._strict and self._known_template and self._parameters:
                raise InvalidMISPObject('Some object relations are unknown in the template and could not be attached: {}'.format(', '.join(self._parameters)))
