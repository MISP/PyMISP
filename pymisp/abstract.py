#!/usr/bin/env python
# -*- coding: utf-8 -*-

import six  # Remove that import when discarding python2 support.
import abc
import json
from json import JSONEncoder
import collections


class MISPEncode(JSONEncoder):

    def default(self, obj):
        if isinstance(obj, AbstractMISP):
            return obj.jsonable()
        return JSONEncoder.default(self, obj)


@six.add_metaclass(abc.ABCMeta)   # Remove that line when discarding python2 support.
# Python3 way: class MISPObjectGenerator(metaclass=abc.ABCMeta):
class AbstractMISP(collections.MutableMapping):

    attributes = None

    def __init__(self):
        """Initialize the list of class-level attributes to set in the JSON dump"""
        # The attribute names will be set automatically by the schemas when we will have them.
        if self.attributes is None:
            raise NotImplementedError('{} must define attributes'.format(type(self).__name__))
        self.attributes = sorted(self.attributes)

    def __check_dict_key(self, key):
        if key not in self.attributes:
            raise Exception('{} not a valid key in {}. Alowed keys: {}'.format(
                key, type(self).__name__, ', '.join(self.attributes)))
        return True

    def from_dict(self, **kwargs):
        for attribute in self.attributes:
            val = kwargs.pop(attribute, None)
            if val is None:
                continue
            setattr(self, attribute, val)
        if kwargs:
            raise Exception('Unused parameter(s): {}'.format(', '.join(kwargs.keys())))

    def from_json(self, json_string):
        """Load a JSON string"""
        self.from_dict(json.loads(json_string))

    def to_dict(self):
        to_return = {}
        for attribute in self.attributes:
            val = getattr(self, attribute, None)
            if val is None:
                continue
            to_return[attribute] = val
        return to_return

    def jsonable(self):
        return self.to_dict()

    def to_json(self):
        return json.dumps(self.to_dict(), cls=MISPEncode)

    def __getitem__(self, key):
        if self.__check_dict_key(key):
            return getattr(self, key)

    def __setitem__(self, key, value):
        if self.__check_dict_key(key):
            setattr(self, key, value)

    def __delitem__(self, key):
        if self.__check_dict_key(key):
            delattr(self, key)

    def __iter__(self):
        return iter(self.to_dict())

    def __len__(self):
        return len(self.to_dict())
