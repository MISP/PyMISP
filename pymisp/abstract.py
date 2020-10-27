#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import date, datetime

from deprecated import deprecated  # type: ignore
from json import JSONEncoder
from uuid import UUID
from abc import ABCMeta

try:
    from rapidjson import load  # type: ignore
    from rapidjson import loads  # type: ignore
    from rapidjson import dumps  # type: ignore
    HAS_RAPIDJSON = True
except ImportError:
    from json import load
    from json import loads
    from json import dumps
    HAS_RAPIDJSON = False

import logging
from enum import Enum
from typing import Union, Optional, Any, Dict, List, Set, Mapping

from .exceptions import PyMISPInvalidFormat, PyMISPError


from collections.abc import MutableMapping
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger('pymisp')

resources_path = Path(__file__).parent / 'data'
misp_objects_path = resources_path / 'misp-objects' / 'objects'
with (resources_path / 'describeTypes.json').open('r') as f:
    describe_types = load(f)['result']


class MISPFileCache(object):
    # cache up to 150 JSON structures in class attribute

    @staticmethod
    @lru_cache(maxsize=150)
    def _load_json(path: Path) -> Union[dict, None]:
        if not path.exists():
            return None
        with path.open('r', encoding='utf-8') as f:
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


def _int_to_str(d: Dict[str, Any]) -> Dict[str, Any]:
    # transform all integer back to string
    for k, v in d.items():
        if isinstance(v, dict):
            d[k] = _int_to_str(v)
        elif isinstance(v, int) and not isinstance(v, bool):
            d[k] = str(v)
    return d


@deprecated(reason=" Use method default=pymisp_json_default instead of cls=MISPEncode", version='2.4.117', action='default')
class MISPEncode(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, AbstractMISP):
            return obj.jsonable()
        elif isinstance(obj, (datetime, date)):
            return obj.isoformat()
        elif isinstance(obj, Enum):
            return obj.value
        elif isinstance(obj, UUID):
            return str(obj)
        return JSONEncoder.default(self, obj)


class AbstractMISP(MutableMapping, MISPFileCache, metaclass=ABCMeta):
    __resources_path = resources_path
    __misp_objects_path = misp_objects_path
    __describe_types = describe_types

    def __init__(self, **kwargs):
        """Abstract class for all the MISP objects.
        NOTE: Every method in every classes inheriting this one are doing
              changes in memory and  do not modify data on a remote MISP instance.
              To do so, you need to call the respective add_* or update_*
              methods in ExpandedPyMISP/PyMISP.
        """
        super().__init__()
        self.__edited: bool = True  # As we create a new object, we assume it is edited
        self.__not_jsonable: List[str] = []
        self._fields_for_feed: Set
        self.__self_defined_describe_types: Optional[Dict] = None
        self.uuid: str

        if kwargs.get('force_timestamps') is not None:
            # Ignore the edited objects and keep the timestamps.
            self.__force_timestamps: bool = True
        else:
            self.__force_timestamps: bool = False

    @property
    def describe_types(self) -> Dict:
        if self.__self_defined_describe_types:
            return self.__self_defined_describe_types
        return self.__describe_types

    @describe_types.setter
    def describe_types(self, describe_types: Dict):
        self.__self_defined_describe_types = describe_types

    @property
    def resources_path(self) -> Path:
        return self.__resources_path

    @property
    def misp_objects_path(self) -> Path:
        return self.__misp_objects_path

    @misp_objects_path.setter
    def misp_objects_path(self, misp_objects_path: Union[str, Path]):
        if isinstance(misp_objects_path, str):
            misp_objects_path = Path(misp_objects_path)
        self.__misp_objects_path = misp_objects_path

    def from_dict(self, **kwargs) -> None:
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

    def update_not_jsonable(self, *args) -> None:
        """Add entries to the __not_jsonable list"""
        self.__not_jsonable += args

    def set_not_jsonable(self, args: List[str]) -> None:
        """Set __not_jsonable to a new list"""
        self.__not_jsonable = args

    def _remove_from_not_jsonable(self, *args) -> None:
        """Remove the entries that are in the __not_jsonable list"""
        for entry in args:
            try:
                self.__not_jsonable.remove(entry)
            except ValueError:
                pass

    def from_json(self, json_string: str) -> None:
        """Load a JSON string"""
        self.from_dict(**loads(json_string))

    def to_dict(self) -> Dict:
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
            elif isinstance(val, str):
                val = val.strip()
            if attribute == 'timestamp':
                if not self.__force_timestamps and is_edited:
                    # In order to be accepted by MISP, the timestamp of an object
                    # needs to be either newer, or None.
                    # If the current object is marked as edited, the easiest is to
                    # skip the timestamp and let MISP deal with it
                    continue
                else:
                    val = self._datetime_to_timestamp(val)
            if (attribute in ['first_seen', 'last_seen', 'datetime']
                    and isinstance(val, datetime)
                    and not val.tzinfo):
                # Need to make sure the timezone is set. Otherwise, it will be processed as UTC on the server
                val = val.astimezone()

            to_return[attribute] = val
        to_return = _int_to_str(to_return)
        return to_return

    def jsonable(self) -> Dict:
        """This method is used by the JSON encoder"""
        return self.to_dict()

    def _to_feed(self) -> Dict:
        if not hasattr(self, '_fields_for_feed') or not self._fields_for_feed:
            raise PyMISPError('Unable to export in the feed format, _fields_for_feed is missing.')
        if hasattr(self, '_set_default') and callable(self._set_default):  # type: ignore
            self._set_default()  # type: ignore
        to_return = {}
        for field in self._fields_for_feed:
            if getattr(self, field, None) is not None:
                if field in ['timestamp', 'publish_timestamp']:
                    to_return[field] = self._datetime_to_timestamp(getattr(self, field))
                elif isinstance(getattr(self, field), (datetime, date)):
                    to_return[field] = getattr(self, field).isoformat()
                else:
                    to_return[field] = getattr(self, field)
            else:
                if field in ['data', 'first_seen', 'last_seen', 'deleted']:
                    # special fields
                    continue
                raise PyMISPError('The field {} is required in {} when generating a feed.'.format(field, self.__class__.__name__))
        to_return = _int_to_str(to_return)
        return to_return

    def to_json(self, sort_keys: bool = False, indent: Optional[int] = None):
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
        '''When we call **self, skip keys:
            * starting with _
            * in __not_jsonable
            * timestamp if the object is edited *unless* it is forced
        '''
        return iter({k: v for k, v in self.__dict__.items()
                     if not (k[0] == '_'
                             or k in self.__not_jsonable
                             or (not self.__force_timestamps and (k == 'timestamp' and self.__edited)))})

    def __len__(self) -> int:
        return len([k for k in self.__dict__.keys() if not (k[0] == '_' or k in self.__not_jsonable)])

    @property
    def edited(self) -> bool:
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
    def edited(self, val: bool):
        """Set the edit flag"""
        if isinstance(val, bool):
            self.__edited = val
        else:
            raise PyMISPError('edited can only be True or False')

    def __setattr__(self, name: str, value: Any):
        if name[0] != '_' and not self.__edited and name in self:
            # The private members don't matter
            # If we already have a key with that name, we're modifying it.
            self.__edited = True
        super().__setattr__(name, value)

    def _datetime_to_timestamp(self, d: Union[int, float, str, datetime]) -> int:
        """Convert a datetime object to a timestamp (int)"""
        if isinstance(d, (int, float, str)):
            # Assume we already have a timestamp
            return int(d)
        return int(d.timestamp())

    def _add_tag(self, tag: Optional[Union[str, 'MISPTag', Mapping]] = None, **kwargs):
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
            raise PyMISPInvalidFormat(f"The tag is in an invalid format (can be either string, MISPTag, or an expanded dict): {tag}")
        if misp_tag not in self.tags:  # type: ignore
            self.Tag.append(misp_tag)
            self.edited = True
        return misp_tag

    def _set_tags(self, tags: List['MISPTag']):
        """Set a list of prepared MISPTag."""
        if all(isinstance(x, MISPTag) for x in tags):
            self.Tag = tags
        else:
            raise PyMISPInvalidFormat('All the attributes have to be of type MISPTag.')

    def __eq__(self, other) -> bool:
        if isinstance(other, AbstractMISP):
            return self.to_dict() == other.to_dict()
        elif isinstance(other, dict):
            return self.to_dict() == other
        else:
            return False

    def __repr__(self) -> str:
        return '<{self.__class__.__name__} - please define me>'.format(self=self)


class MISPTag(AbstractMISP):

    _fields_for_feed: set = {'name', 'colour'}

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name: str
        self.exportable: bool

    def from_dict(self, **kwargs):
        if kwargs.get('Tag'):
            kwargs = kwargs.get('Tag')
        super().from_dict(**kwargs)

    def _set_default(self):
        if not hasattr(self, 'colour'):
            self.colour = '#ffffff'

    def _to_feed(self) -> Dict:
        if hasattr(self, 'exportable') and not self.exportable:
            return {}
        return super()._to_feed()

    def delete(self):
        self.deleted = True
        self.edited = True

    def __repr__(self) -> str:
        if hasattr(self, 'name'):
            return '<{self.__class__.__name__}(name={self.name})>'.format(self=self)
        return '<{self.__class__.__name__}(NotInitialized)>'.format(self=self)


if HAS_RAPIDJSON:
    def pymisp_json_default(obj: Union[AbstractMISP, datetime, date, Enum, UUID]) -> Union[Dict, str]:
        if isinstance(obj, AbstractMISP):
            return obj.jsonable()
        elif isinstance(obj, (datetime, date)):
            return obj.isoformat()
        elif isinstance(obj, Enum):
            return obj.value
        elif isinstance(obj, UUID):
            return str(obj)
else:
    def pymisp_json_default(obj: Union[AbstractMISP, datetime, date, Enum, UUID]) -> Union[Dict, str]:
        if isinstance(obj, AbstractMISP):
            return obj.jsonable()
        elif isinstance(obj, (datetime, date)):
            return obj.isoformat()
        elif isinstance(obj, Enum):
            return obj.value
        elif isinstance(obj, UUID):
            return str(obj)
