#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import datetime

from deprecated import deprecated
from json import JSONEncoder
from uuid import UUID

try:
    from rapidjson import load
    from rapidjson import loads
    from rapidjson import dumps
    import rapidjson
    HAS_RAPIDJSON = True
except ImportError:
    from json import load
    from json import loads
    from json import dumps
    import json
    HAS_RAPIDJSON = False

import logging
from enum import Enum

from .exceptions import PyMISPInvalidFormat, PyMISPError


logger = logging.getLogger('pymisp')

if sys.version_info < (3, 0):
    from collections import MutableMapping
    import os
    from cachetools import cached, LRUCache

    resources_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'data')
    misp_objects_path = os.path.join(resources_path, 'misp-objects', 'objects')
    with open(os.path.join(resources_path, 'describeTypes.json'), 'r') as f:
        describe_types = load(f)['result']

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

    class MISPFileCache(object):
        # cache up to 150 JSON structures in class attribute

        @staticmethod
        @cached(cache=LRUCache(maxsize=150))
        def _load_json(path):
            if not os.path.exists(path):
                return None
            with open(path, 'r') as f:
                data = load(f)
            return data

elif sys.version_info < (3, 4):
    from collections.abc import MutableMapping
    from functools import lru_cache
    import os

    resources_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'data')
    misp_objects_path = os.path.join(resources_path, 'misp-objects', 'objects')
    with open(os.path.join(resources_path, 'describeTypes.json'), 'r') as f:
        describe_types = load(f)['result']

    class MISPFileCache(object):
        # cache up to 150 JSON structures in class attribute

        @staticmethod
        @lru_cache(maxsize=150)
        def _load_json(path):
            if not os.path.exists(path):
                return None
            with open(path, 'r') as f:
                data = load(f)
            return data

else:
    from collections.abc import MutableMapping
    from functools import lru_cache
    from pathlib import Path

    resources_path = Path(__file__).parent / 'data'
    misp_objects_path = resources_path / 'misp-objects' / 'objects'
    with (resources_path / 'describeTypes.json').open('r') as f:
        describe_types = load(f)['result']

    class MISPFileCache(object):
        # cache up to 150 JSON structures in class attribute

        @staticmethod
        @lru_cache(maxsize=150)
        def _load_json(path):
            if not path.exists():
                return None
            with path.open('r') as f:
                data = load(f)
            return data


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


@deprecated(reason=" Use method default=pymisp_json_default instead of cls=MISPEncode", version='2.4.117', action='default')
class MISPEncode(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, AbstractMISP):
            return obj.jsonable()
        elif isinstance(obj, (datetime.datetime, datetime.date)):
            return obj.isoformat()
        elif isinstance(obj, Enum):
            return obj.value
        elif isinstance(obj, UUID):
            return str(obj)
        return JSONEncoder.default(self, obj)


if HAS_RAPIDJSON:
    def pymisp_json_default(obj):
        if isinstance(obj, AbstractMISP):
            return obj.jsonable()
        elif isinstance(obj, (datetime.datetime, datetime.date)):
            return obj.isoformat()
        elif isinstance(obj, Enum):
            return obj.value
        elif isinstance(obj, UUID):
            return str(obj)
        return rapidjson.default(obj)
else:
    def pymisp_json_default(obj):
        if isinstance(obj, AbstractMISP):
            return obj.jsonable()
        elif isinstance(obj, (datetime.datetime, datetime.date)):
            return obj.isoformat()
        elif isinstance(obj, Enum):
            return obj.value
        elif isinstance(obj, UUID):
            return str(obj)
        return json.default(obj)


class AbstractMISP(MutableMapping, MISPFileCache):
    __resources_path = resources_path
    __misp_objects_path = misp_objects_path
    __describe_types = describe_types

    def __init__(self, **kwargs):
        """Abstract class for all the MISP objects"""
        super(AbstractMISP, self).__init__()
        self.__edited = True  # As we create a new object, we assume it is edited
        self.__not_jsonable = []
        self.__self_defined_describe_types = None

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
    def describe_types(self):
        if self.__self_defined_describe_types:
            return self.__self_defined_describe_types
        return self.__describe_types

    @describe_types.setter
    def describe_types(self, describe_types):
        self.__self_defined_describe_types = describe_types

    @property
    def resources_path(self):
        return self.__resources_path

    @property
    def misp_objects_path(self):
        return self.__misp_objects_path

    @misp_objects_path.setter
    def misp_objects_path(self, misp_objects_path):
        if sys.version_info >= (3, 0) and isinstance(misp_objects_path, str):
            misp_objects_path = Path(misp_objects_path)
        self.__misp_objects_path = misp_objects_path

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
        self.from_dict(**loads(json_string))

    def to_dict(self):
        """Dump the class to a dictionary.
        This method automatically removes the timestamp recursively in every object
        that has been edited is order to let MISP update the event accordingly."""
        is_edited = self.edited
        to_return = {}
        for attribute, val in self.items():
            if val is None:
                continue
            elif isinstance(val, list) and len(val) == 0:
                continue
            if attribute == 'timestamp':
                if not self.__force_timestamps and is_edited:
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

    def _to_feed(self):
        if not hasattr(self, '_fields_for_feed'):
            raise PyMISPError('Unable to export in the feed format, _fields_for_feed is missing.')
        to_return = {}
        for field in self._fields_for_feed:
            if getattr(self, field, None) is not None:
                if field in ['timestamp', 'publish_timestamp']:
                    to_return[field] = self._datetime_to_timestamp(getattr(self, field))
                elif isinstance(getattr(self, field), (datetime.datetime, datetime.date)):
                    to_return[field] = getattr(self, field).isoformat()
                else:
                    to_return[field] = getattr(self, field)
        return to_return

    def to_json(self, sort_keys=False, indent=None):
        """Dump recursively any class of type MISPAbstract to a json string"""
        return dumps(self, default=pymisp_json_default, sort_keys=sort_keys, indent=indent)

    def __getitem__(self, key):
        try:
            if key[0] != '_' and key not in self.__not_jsonable:
                return self.__dict__[key]
            raise KeyError
        except AttributeError:
            # Expected by pop and other dict-related methods
            raise KeyError

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __delitem__(self, key):
        delattr(self, key)

    def __iter__(self):
        return iter({k: v for k, v in self.__dict__.items() if not (k[0] == '_' or k in self.__not_jsonable)})

    def __len__(self):
        return len([k for k in self.__dict__.keys() if not (k[0] == '_' or k in self.__not_jsonable)])

    @property
    def edited(self):
        """Recursively check if an object has been edited and update the flag accordingly
        to the parent objects"""
        if self.__edited:
            return self.__edited
        for p, val in self.items():
            if isinstance(val, AbstractMISP) and val.edited:
                self.__edited = True
                break
            elif isinstance(val, list) and all(isinstance(a, AbstractMISP) for a in val):
                if any(a.edited for a in val):
                    self.__edited = True
                    break
        return self.__edited

    @edited.setter
    def edited(self, val):
        """Set the edit flag"""
        if isinstance(val, bool):
            self.__edited = val
        else:
            raise PyMISPError('edited can only be True or False')

    def __setattr__(self, name, value):
        if name[0] != '_' and not self.__edited and name in self.keys():
            # The private members don't matter
            # If we already have a key with that name, we're modifying it.
            self.__edited = True
        super(AbstractMISP, self).__setattr__(name, value)

    def _datetime_to_timestamp(self, d):
        """Convert a datetime.datetime object to a timestamp (int)"""
        if isinstance(d, (int, float, str)) or (sys.version_info < (3, 0) and isinstance(d, unicode)):
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

    def __repr__(self):
        if hasattr(self, 'name'):
            return '<{self.__class__.__name__}(name={self.name})'.format(self=self)
        return '<{self.__class__.__name__}(NotInitialized)'.format(self=self)


class MISPTag(AbstractMISP):

    _fields_for_feed = {'name', 'colour'}

    def __init__(self):
        super(MISPTag, self).__init__()

    def from_dict(self, **kwargs):
        if kwargs.get('Tag'):
            kwargs = kwargs.get('Tag')
        super(MISPTag, self).from_dict(**kwargs)

    def _to_feed(self):
        if hasattr(self, 'exportable') and not self.exportable:
            return False
        return super(MISPTag, self)._to_feed()
