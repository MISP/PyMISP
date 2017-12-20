#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import json
from json import JSONEncoder
import collections
import six  # Remove that import when discarding python2 support.
import logging

logger = logging.getLogger('pymisp')

if six.PY2:
    logger.warning("You're using python 2, it is strongly recommended to use python >=3.5")


class MISPEncode(JSONEncoder):

    def default(self, obj):
        if isinstance(obj, AbstractMISP):
            return obj.jsonable()
        return JSONEncoder.default(self, obj)


@six.add_metaclass(abc.ABCMeta)   # Remove that line when discarding python2 support.
class AbstractMISP(collections.MutableMapping):

    __not_jsonable = []

    def __init__(self, **kwargs):
        super(AbstractMISP, self).__init__()
        self.edited = True

    def properties(self):
        to_return = []
        for prop, value in vars(self).items():
            if prop.startswith('_') or prop in self.__not_jsonable:
                continue
            to_return.append(prop)
        return to_return

    def from_dict(self, **kwargs):
        for prop, value in kwargs.items():
            if value is None:
                continue
            setattr(self, prop, value)
        # We load an existing dictionary, marking it an not-edited
        self.edited = False

    def update_not_jsonable(self, *args):
        self.__not_jsonable += args

    def set_not_jsonable(self, *args):
        self.__not_jsonable = args

    def from_json(self, json_string):
        """Load a JSON string"""
        self.from_dict(json.loads(json_string))

    def to_dict(self):
        to_return = {}
        for attribute in self.properties():
            val = getattr(self, attribute, None)
            if val is None:
                continue
            to_return[attribute] = val
        return to_return

    def jsonable(self):
        return self.to_dict()

    def to_json(self):
        return json.dumps(self, cls=MISPEncode)

    def __getitem__(self, key):
        try:
            return getattr(self, key)
        except AttributeError:
            # Expected by pop and other dict-related methods
            raise KeyError

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __delitem__(self, key):
        delattr(self, key)

    def __iter__(self):
        return iter(self.to_dict())

    def __len__(self):
        return len(self.to_dict())

    @property
    def edited(self):
        return self.__edited

    @edited.setter
    def edited(self, val):
        if isinstance(val, bool):
            self.__edited = val
        else:
            raise Exception('edited can only be True or False')

    def __setattr__(self, name, value):
        if name in self.properties():
            self.__edited = True
        super(AbstractMISP, self).__setattr__(name, value)
