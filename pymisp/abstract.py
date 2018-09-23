#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import sys
import datetime
import json
from json import JSONEncoder
import collections
import six  # Remove that import when discarding python2 support.
import logging
from enum import Enum

from .exceptions import PyMISPInvalidFormat


logger = logging.getLogger('pymisp')

if six.PY2:
    logger.warning("You're using python 2, it is strongly recommended to use python >=3.6")

    # This is required because Python 2 is a pain.
    from datetime import tzinfo, timedelta

    class UTC(tzinfo):
        """UTC"""

        def utcoffset(self, dt):
            return timedelta(0)

        def tzname(self, dt):
            return "UTC"

        def dst(self, dt):
            return timedelta(0)


class Distribution(Enum):
    your_organisation_only = 0
    this_community_only = 1
    connected_communities = 2
    all_communities = 3
    sharing_group = 4
    inherit = 5


class ThreatLevel(Enum):
    high = 1
    medium = 2
    low = 3
    undefined = 4


class Analysis(Enum):
    initial = 0
    ongoing = 1
    completed = 2


def _int_to_str(d):
    # transform all integer back to string
    for k, v in d.items():
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            d[k] = str(v)
    return d


class MISPEncode(JSONEncoder):

    def default(self, obj):
        if isinstance(obj, AbstractMISP):
            return obj.jsonable()
        elif isinstance(obj, datetime.datetime):
            return obj.isoformat()
        elif isinstance(obj, Enum):
            return obj.value
        return JSONEncoder.default(self, obj)


@six.add_metaclass(abc.ABCMeta)   # Remove that line when discarding python2 support.
class AbstractMISP(collections.MutableMapping):

    __not_jsonable = []

    def __init__(self, **kwargs):
        """Abstract class for all the MISP objects"""
        super(AbstractMISP, self).__init__()
        self.__edited = True  # As we create a new object, we assume it is edited

        if kwargs.get('force_timestamps') is not None:
            # Ignore the edited objects and keep the timestamps.
            self.__force_timestamps = True
        else:
            self.__force_timestamps = False

        # List of classes having tags
        from .mispevent import MISPAttribute, MISPEvent
        self.__has_tags = (MISPAttribute, MISPEvent)
        if isinstance(self, self.__has_tags):
            self.Tag = []
            setattr(AbstractMISP, 'add_tag', AbstractMISP.__add_tag)
            setattr(AbstractMISP, 'tags', property(AbstractMISP.__get_tags, AbstractMISP.__set_tags))

    @property
    def properties(self):
        """All the class public properties that will be dumped in the dictionary, and the JSON export.
        Note: all the properties starting with a `_` (private), or listed in __not_jsonable will be skipped.
        """
        to_return = []
        for prop, value in vars(self).items():
            if prop.startswith('_') or prop in self.__not_jsonable:
                continue
            to_return.append(prop)
        return to_return

    def from_dict(self, **kwargs):
        """Loading all the parameters as class properties, if they aren't `None`.
        This method aims to be called when all the properties requiring a special
        treatment are processed.
        Note: This method is used when you initialize an object with existing data so by default,
        the class is flaged as not edited."""
        for prop, value in kwargs.items():
            if value is None:
                continue
            setattr(self, prop, value)
        # We load an existing dictionary, marking it an not-edited
        self.__edited = False

    def update_not_jsonable(self, *args):
        """Add entries to the __not_jsonable list"""
        self.__not_jsonable += args

    def set_not_jsonable(self, *args):
        """Set __not_jsonable to a new list"""
        self.__not_jsonable = args

    def from_json(self, json_string):
        """Load a JSON string"""
        self.from_dict(**json.loads(json_string))

    def to_dict(self):
        """Dump the lass to a dictionary.
        This method automatically removes the timestamp recursively in every object
        that has been edited is order to let MISP update the event accordingly."""
        to_return = {}
        for attribute in self.properties:
            val = getattr(self, attribute, None)
            if val is None:
                continue
            elif isinstance(val, list) and len(val) == 0:
                continue
            if attribute == 'timestamp':
                if not self.__force_timestamps and self.edited:
                    # In order to be accepted by MISP, the timestamp of an object
                    # needs to be either newer, or None.
                    # If the current object is marked as edited, the easiest is to
                    # skip the timestamp and let MISP deal with it
                    continue
                else:
                    val = self._datetime_to_timestamp(val)
            to_return[attribute] = val
        to_return = _int_to_str(to_return)
        return to_return

    def jsonable(self):
        """This method is used by the JSON encoder"""
        return self.to_dict()

    def to_json(self):
        """Dump recursively any class of type MISPAbstract to a json string"""
        return json.dumps(self, cls=MISPEncode, sort_keys=True, indent=2)

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
        """Recursively check if an object has been edited and update the flag accordingly
        to the parent objects"""
        if self.__edited:
            return self.__edited
        for p in self.properties:
            if self.__edited:
                break
            val = getattr(self, p)
            if isinstance(val, AbstractMISP) and val.edited:
                self.__edited = True
            elif isinstance(val, list) and all(isinstance(a, AbstractMISP) for a in val):
                if any(a.edited for a in val):
                    self.__edited = True
        return self.__edited

    @edited.setter
    def edited(self, val):
        """Set the edit flag"""
        if isinstance(val, bool):
            self.__edited = val
        else:
            raise Exception('edited can only be True or False')

    def __setattr__(self, name, value):
        if name in self.properties:
            self.__edited = True
        super(AbstractMISP, self).__setattr__(name, value)

    def _datetime_to_timestamp(self, d):
        """Convert a datetime.datetime object to a timestamp (int)"""
        if isinstance(d, (int, str)) or (sys.version_info < (3, 0) and isinstance(d, unicode)):
            # Assume we already have a timestamp
            return int(d)
        if sys.version_info >= (3, 3):
            return int(d.timestamp())
        else:
            return int((d - datetime.datetime.fromtimestamp(0, UTC())).total_seconds())

    def __add_tag(self, tag=None, **kwargs):
        """Add a tag to the attribute (by name or a MISPTag object)"""
        if isinstance(tag, str):
            misp_tag = MISPTag()
            misp_tag.from_dict(name=tag)
        elif isinstance(tag, MISPTag):
            misp_tag = tag
        elif isinstance(tag, dict):
            misp_tag = MISPTag()
            misp_tag.from_dict(**tag)
        elif kwargs:
            misp_tag = MISPTag()
            misp_tag.from_dict(**kwargs)
        else:
            raise PyMISPInvalidFormat("The tag is in an invalid format (can be either string, MISPTag, or an expanded dict): {}".format(tag))
        if misp_tag not in self.tags:
            self.Tag.append(misp_tag)
            self.edited = True

    def __get_tags(self):
        """Returns a lost of tags associated to this Attribute"""
        return self.Tag

    def __set_tags(self, tags):
        """Set a list of prepared MISPTag."""
        if all(isinstance(x, MISPTag) for x in tags):
            self.Tag = tags
        else:
            raise PyMISPInvalidFormat('All the attributes have to be of type MISPTag.')

    def __eq__(self, other):
        if isinstance(other, AbstractMISP):
            return self.to_dict() == other.to_dict()
        elif isinstance(other, dict):
            return self.to_dict() == other
        else:
            return False


class MISPTag(AbstractMISP):
    def __init__(self):
        super(MISPTag, self).__init__()

    def from_dict(self, name, **kwargs):
        self.name = name
        super(MISPTag, self).from_dict(**kwargs)

    def __repr__(self):
        if hasattr(self, 'name'):
            return '<{self.__class__.__name__}(name={self.name})'.format(self=self)
        return '<{self.__class__.__name__}(NotInitialized)'.format(self=self)
