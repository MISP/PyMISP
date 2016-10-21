#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import time
import json
from json import JSONEncoder
import os
try:
    from dateutil.parser import parse
except ImportError:
    pass

try:
    import jsonschema
except ImportError:
    pass

from .exceptions import PyMISPError, NewEventError, NewAttributeError

# Least dirty way to support python 2 and 3
try:
    warnings.warn("You're using python 2, it is strongly recommended to use python >=3.3")
    basestring
except NameError:
    basestring = str


class MISPAttribute(object):

    def __init__(self, describe_types):
        self.categories = describe_types['categories']
        self.types = describe_types['types']
        self.category_type_mapping = describe_types['category_type_mappings']
        self.sane_default = describe_types['sane_defaults']
        self._reinitialize_attribute()

    def _reinitialize_attribute(self):
        # Default values
        self.category = None
        self.type = None
        self.value = None
        self.to_ids = False
        self.comment = ''
        self.distribution = 5

        # other possible values
        self.id = None
        self.uuid = None
        self.timestamp = None
        self.sharing_group_id = None
        self.deleted = None
        self.SharingGroup = []
        self.ShadowAttribute = []

    def set_all_values(self, **kwargs):
        if kwargs.get('type') and kwargs.get('category'):
            if kwargs['type'] not in self.category_type_mapping[kwargs['category']]:
                raise NewAttributeError('{} and {} is an invalid combinaison, type for this category has to be in {}'.capitalizeformat(self.type, self.category, (', '.join(self.category_type_mapping[self.category]))))
        # Required
        if kwargs.get('type'):
            self.type = kwargs['type']
            if self.type not in self.types:
                raise NewAttributeError('{} is invalid, type has to be in {}'.format(self.type, (', '.join(self.types))))
        else:
            raise NewAttributeError('The type of the attribute is required.')

        type_defaults = self.sane_default[self.type]

        if kwargs.get('value'):
            self.value = kwargs['value']
        else:
            raise NewAttributeError('The value of the attribute is required.')

        # Default values
        if kwargs.get('category'):
            self.category = kwargs['category']
            if self.category not in self.categories:
                raise NewAttributeError('{} is invalid, category has to be in {}'.format(self.category, (', '.join(self.categories))))
        else:
            self.category = type_defaults['default_category']

        if kwargs.get('to_ids'):
            self.to_ids = kwargs['to_ids']
            if not isinstance(self.to_ids, bool):
                raise NewAttributeError('{} is invalid, to_ids has to be True or False'.format(self.to_ids))
        else:
            self.to_ids = bool(int(type_defaults['to_ids']))
        if kwargs.get('comment'):
            self.comment = kwargs['comment']
        if kwargs.get('distribution'):
            self.distribution = int(kwargs['distribution'])
            if self.distribution not in [0, 1, 2, 3, 5]:
                raise NewAttributeError('{} is invalid, the distribution has to be in 0, 1, 2, 3, 5'.format(self.distribution))

        # other possible values
        if kwargs.get('id'):
            self.id = int(kwargs['id'])
        if kwargs.get('uuid'):
            self.uuid = kwargs['uuid']
        if kwargs.get('timestamp'):
            self.timestamp = datetime.datetime.fromtimestamp(int(kwargs['timestamp']))
        if kwargs.get('sharing_group_id'):
            self.sharing_group_id = int(kwargs['sharing_group_id'])
        if kwargs.get('deleted'):
            self.deleted = kwargs['deleted']
        if kwargs.get('SharingGroup'):
            self.SharingGroup = kwargs['SharingGroup']
        if kwargs.get('ShadowAttribute'):
            self.ShadowAttribute = kwargs['ShadowAttribute']

    def _json(self):
        to_return = {'type': self.type, 'category': self.category, 'to_ids': self.to_ids,
                     'distribution': self.distribution, 'value': self.value,
                     'comment': self.comment}
        if self.sharing_group_id:
            to_return['sharing_group_id'] = self.sharing_group_id
        to_return = _int_to_str(to_return)
        return to_return

    def _json_full(self):
        to_return = self._json()
        if self.id:
            to_return['id'] = self.id
        if self.uuid:
            to_return['uuid'] = self.uuid
        if self.timestamp:
            to_return['timestamp'] = int(time.mktime(self.timestamp.timetuple()))
        if self.deleted is not None:
            to_return['deleted'] = self.deleted
        if self.ShadowAttribute:
            to_return['ShadowAttribute'] = self.ShadowAttribute
        if self.SharingGroup:
            to_return['SharingGroup'] = self.SharingGroup
        to_return = _int_to_str(to_return)
        return to_return


class EncodeUpdate(JSONEncoder):
    def default(self, obj):
        try:
            return obj._json()
        except AttributeError:
            return JSONEncoder.default(self, obj)


class EncodeFull(JSONEncoder):
    def default(self, obj):
        try:
            return obj._json_full()
        except AttributeError:
            return JSONEncoder.default(self, obj)


def _int_to_str(d):
    # transform all integer back to string
    for k, v in d.items():
        if isinstance(v, int) and not isinstance(v, bool):
            d[k] = str(v)
    return d


class MISPEvent(object):

    def __init__(self, describe_types=None):
        self.ressources_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'data')
        self.json_schema = json.load(open(os.path.join(self.ressources_path, 'schema.json'), 'r'))
        self.json_schema_lax = json.load(open(os.path.join(self.ressources_path, 'schema-lax.json'), 'r'))
        if not describe_types:
            t = json.load(open(os.path.join(self.ressources_path, 'describeTypes.json'), 'r'))
            describe_types = t['result']
        self.describe_types = describe_types
        self.categories = describe_types['categories']
        self.types = describe_types['types']
        self.category_type_mapping = describe_types['category_type_mappings']
        self.sane_default = describe_types['sane_defaults']
        self.new = True
        self.dump_full = False

        self._reinitialize_event()

    def _reinitialize_event(self):
        # Default values for a valid event to send to a MISP instance
        self.distribution = 3
        self.threat_level_id = 2
        self.analysis = 0
        self.info = None
        self.published = False
        self.date = datetime.date.today()
        self.attributes = []

        # All other keys
        self.id = None
        self.orgc_id = None
        self.org_id = None
        self.uuid = None
        self.attribute_count = None
        self.timestamp = None
        self.proposal_email_lock = None
        self.locked = None
        self.publish_timestamp = None
        self.sharing_group_id = None
        self.Org = None
        self.Orgc = None
        self.ShadowAttribute = []
        self.RelatedEvent = []
        self.Tag = []

    def load(self, json_event):
        self.new = False
        self.dump_full = True
        if isinstance(json_event, basestring) and os.path.exists(json_event):
            # NOTE: is it a good idea? (possible security issue if an untrusted user call this method)
            json_event = open(json_event, 'r')
        if hasattr(json_event, 'read'):
            # python2 and python3 compatible to find if we have a file
            json_event = json_event.read()
        if isinstance(json_event, basestring):
            json_event = json.loads(json_event)
        if json_event.get('response'):
            event = json_event.get('response')[0]
        else:
            event = json_event
        if not event:
            raise PyMISPError('Invalid event')
        # Invalid event created by MISP up to 2.4.52 (attribute_count is none instead of '0')
        if event.get('Event') and event.get('Event').get('attribute_count') is None:
            event['Event']['attribute_count'] = '0'
        jsonschema.validate(event, self.json_schema_lax)
        e = event.get('Event')
        self._reinitialize_event()
        self.set_all_values(**e)

    def set_all_values(self, **kwargs):
        # Required value
        if kwargs.get('info'):
            self.info = kwargs['info']
        else:
            raise NewAttributeError('The info field of the new event is required.')

        # Default values for a valid event to send to a MISP instance
        if kwargs.get('distribution') is not None:
            self.distribution = int(kwargs['distribution'])
            if self.distribution not in [0, 1, 2, 3]:
                raise NewEventError('{} is invalid, the distribution has to be in 0, 1, 2, 3'.format(self.distribution))
        if kwargs.get('threat_level_id') is not None:
            self.threat_level_id = int(kwargs['threat_level_id'])
            if self.threat_level_id not in [1, 2, 3, 4]:
                raise NewEventError('{} is invalid, the threat_level has to be in 1, 2, 3, 4'.format(self.threat_level_id))
        if kwargs.get('analysis') is not None:
            self.analysis = int(kwargs['analysis'])
            if self.analysis not in [0, 1, 2]:
                raise NewEventError('{} is invalid, the analysis has to be in 0, 1, 2'.format(self.analysis))
        if kwargs.get('published') is not None:
            self.publish()
        if kwargs.get('date'):
            if isinstance(kwargs['date'], basestring) or isinstance(kwargs['date'], unicode):
                self.date = parse(kwargs['date']).date()
            elif isinstance(kwargs['date'], datetime.datetime):
                self.date = kwargs['date'].date()
            elif isinstance(kwargs['date'], datetime.date):
                self.date = kwargs['date']
            else:
                raise NewEventError('Invalid format for the date: {} - {}'.format(kwargs['date'], type(kwargs['date'])))
        if kwargs.get('Attribute'):
            for a in kwargs['Attribute']:
                attribute = MISPAttribute(self.describe_types)
                attribute.set_all_values(**a)
                self.attributes.append(attribute)

        # All other keys
        if kwargs.get('id'):
            self.id = int(kwargs['id'])
        if kwargs.get('orgc_id'):
            self.orgc_id = int(kwargs['orgc_id'])
        if kwargs.get('org_id'):
            self.org_id = int(kwargs['org_id'])
        if kwargs.get('uuid'):
            self.uuid = kwargs['uuid']
        if kwargs.get('attribute_count'):
            self.attribute_count = int(kwargs['attribute_count'])
        if kwargs.get('timestamp'):
            self.timestamp = datetime.datetime.fromtimestamp(int(kwargs['timestamp']))
        if kwargs.get('proposal_email_lock'):
            self.proposal_email_lock = kwargs['proposal_email_lock']
        if kwargs.get('locked'):
            self.locked = kwargs['locked']
        if kwargs.get('publish_timestamp'):
            self.publish_timestamp = datetime.datetime.fromtimestamp(int(kwargs['publish_timestamp']))
        if kwargs.get('sharing_group_id'):
            self.sharing_group_id = int(kwargs['sharing_group_id'])
        if kwargs.get('Org'):
            self.Org = kwargs['Org']
        if kwargs.get('Orgc'):
            self.Orgc = kwargs['Orgc']
        if kwargs.get('ShadowAttribute'):
            self.ShadowAttribute = kwargs['ShadowAttribute']
        if kwargs.get('RelatedEvent'):
            self.RelatedEvent = kwargs['RelatedEvent']
        if kwargs.get('Tag'):
            self.Tag = kwargs['Tag']

    def _json(self):
        to_return = {'Event': {}}
        to_return['Event'] = {'distribution': self.distribution, 'info': self.info,
                              'date': self.date.isoformat(), 'published': self.published,
                              'threat_level_id': self.threat_level_id,
                              'analysis': self.analysis, 'Attribute': []}
        if self.id:
            to_return['Event']['id'] = self.id
        if self.orgc_id:
            to_return['Event']['orgc_id'] = self.orgc_id
        if self.org_id:
            to_return['Event']['org_id'] = self.org_id
        if self.uuid:
            to_return['Event']['uuid'] = self.uuid
        if self.sharing_group_id:
            to_return['Event']['sharing_group_id'] = self.sharing_group_id
        if self.Tag:
            to_return['Event']['Tag'] = self.Tag
        to_return['Event'] = _int_to_str(to_return['Event'])
        if self.attributes:
            to_return['Event']['Attribute'] = [a._json() for a in self.attributes]
        jsonschema.validate(to_return, self.json_schema)
        return to_return

    def _json_full(self):
        to_return = self._json()
        if self.locked is not None:
            to_return['Event']['locked'] = self.locked
        if self.attribute_count is not None:
            to_return['Event']['attribute_count'] = self.attribute_count
        if self.RelatedEvent:
            to_return['Event']['RelatedEvent'] = self.RelatedEvent
        if self.Org:
            to_return['Event']['Org'] = self.Org
        if self.Orgc:
            to_return['Event']['Orgc'] = self.Orgc
        if self.ShadowAttribute:
            to_return['Event']['ShadowAttribute'] = self.ShadowAttribute
        if self.proposal_email_lock is not None:
            to_return['Event']['proposal_email_lock'] = self.proposal_email_lock
        if self.locked is not None:
            to_return['Event']['locked'] = self.locked
        if self.publish_timestamp:
            to_return['Event']['publish_timestamp'] = int(time.mktime(self.publish_timestamp.timetuple()))
        if self.timestamp:
            to_return['Event']['timestamp'] = int(time.mktime(self.timestamp.timetuple()))
        to_return['Event'] = _int_to_str(to_return['Event'])
        if self.attributes:
            to_return['Event']['Attribute'] = [a._json_full() for a in self.attributes]
        jsonschema.validate(to_return, self.json_schema)
        return to_return

    def publish(self):
        self.published = True

    def unpublish(self):
        self.published = False

    def add_attribute(self, type, value, **kwargs):
        attribute = MISPAttribute(self.describe_types)
        attribute.set_all_values(type=type, value=value, **kwargs)
        self.attributes.append(attribute)
