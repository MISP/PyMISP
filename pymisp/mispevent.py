#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import time
import json

from .exceptions import PyMISPError, NewEventError, NewAttributeError


class MISPAttribute(object):

    def __init__(self, categories, types, category_type_mapping):
        self.categories = categories
        self.types = types
        self.category_type_mapping = category_type_mapping
        self.new = True

        # Default values
        self.category = None
        self.type = None
        self.value = None
        self.to_ids = False
        self.comment = ''
        self.distribution = 5

    def set_values(self, type_value, value, category, to_ids, comment, distribution):
        self._validate(type_value, value, category, to_ids, comment, distribution)
        self.type = type_value
        self.value = value
        self.category = category
        self.to_ids = to_ids
        self.comment = comment
        self.distribution = distribution

    def set_values_existing_attribute(self, attribute_id, uuid, timestamp, sharing_group_id, deleted, SharingGroup, ShadowAttribute):
        self.new = False
        self.id = int(attribute_id)
        self.uuid = uuid
        self.timestamp = datetime.datetime.fromtimestamp(timestamp)
        self.sharing_group_id = int(sharing_group_id)
        self.deleted = deleted
        self.SharingGroup = SharingGroup
        self.ShadowAttribute = ShadowAttribute

    def _validate(self, type_value, value, category, to_ids, comment, distribution):
        if category not in self.categories:
            raise NewAttributeError('{} is invalid, category has to be in {}'.format(category, (', '.join(self.categories))))
        if type_value not in self.types:
            raise NewAttributeError('{} is invalid, type_value has to be in {}'.format(type_value, (', '.join(self.types))))
        if type_value not in self.category_type_mapping[category]:
            raise NewAttributeError('{} and {} is an invalid combinaison, type_value for this category has to be in {}'.capitalizeformat(type_value, category, (', '.join(self.category_type_mapping[category]))))
        if to_ids not in [True, False]:
            raise NewAttributeError('{} is invalid, to_ids has to be True or False'.format(to_ids))
        if distribution not in [0, 1, 2, 3, 5]:
            raise NewAttributeError('{} is invalid, the distribution has to be in 0, 1, 2, 3, 5'.format(distribution))

    def dump(self):
        to_return = {'type': self.type, 'category': self.category, 'to_ids': self.to_ids,
                     'distribution': self.distribution, 'value': self.value,
                     'comment': self.comment}
        if not self.new:
            to_return.update(
                {'id': self.id, 'uuid': self.uuid,
                 'timestamp': int(time.mktime(self.timestamp.timetuple())),
                 'sharing_group_id': self.sharing_group_id, 'deleted': self.deleted,
                 'SharingGroup': self.SharingGroup, 'ShadowAttribute': self.ShadowAttribute})
        return to_return


class MISPEvent(object):

    def __init__(self, describe_types):
        self.categories = describe_types['categories']
        self.types = describe_types['types']
        self.category_type_mapping = describe_types['category_type_mappings']
        self.sane_default = describe_types['sane_defaults']
        self.new = True
        self.dump_full = False

        # Default values
        self.distribution = 3
        self.threat_level_id = 2
        self.analysis = 0
        self.info = ''
        self.published = False
        self.date = datetime.date.today()
        self.attributes = []

    def _validate(self, distribution, threat_level_id, analysis):
        if distribution not in [0, 1, 2, 3]:
            raise NewEventError('{} is invalid, the distribution has to be in 0, 1, 2, 3'.format(distribution))
        if threat_level_id not in [1, 2, 3, 4]:
            raise NewEventError('{} is invalid, the threat_level has to be in 1, 2, 3, 4'.format(threat_level_id))
        if analysis not in [0, 1, 2]:
            raise NewEventError('{} is invalid, the analysis has to be in 0, 1, 2'.format(analysis))

    def load(self, json_event):
        self.new = False
        self.dump_full = True
        loaded = json.loads(json_event)
        if loaded.get('response'):
            e = loaded.get('response')[0].get('Event')
        else:
            e = loaded.get('Event')
        if not e:
            raise PyMISPError('Invalid event')
        try:
            date = datetime.date(*map(int, e['date'].split('-')))
        except:
            raise NewEventError('{} is an invalid date.'.format(e['date']))
        self.set_values(e['info'], int(e['distribution']), int(e['threat_level_id']), int(e['analysis']), date)
        if e['published']:
            self.publish()
        self.set_values_existing_event(
            e['id'], e['orgc_id'], e['org_id'], e['uuid'],
            e['attribute_count'], e['proposal_email_lock'], e['locked'],
            e['publish_timestamp'], e['sharing_group_id'], e['Org'], e['Orgc'],
            e['ShadowAttribute'], e['RelatedEvent'])
        self.attributes = []
        for a in e['Attribute']:
            attribute = MISPAttribute(self.categories, self.types, self.category_type_mapping)
            attribute.set_values(a['type'], a['value'], a['category'], a['to_ids'],
                                 a['comment'], int(a['distribution']))
            attribute.set_values_existing_attribute(a['id'], a['uuid'], a['timestamp'],
                                                    a['sharing_group_id'], a['deleted'],
                                                    a['SharingGroup'], a['ShadowAttribute'])
            self.attributes.append(attribute)

    def dump(self):
        to_return = {'Event': {}}
        to_return['Event'] = {'distribution': self.distribution, 'info': self.info,
                              'date': self.date.isoformat(), 'published': self.published,
                              'threat_level_id': self.threat_level_id,
                              'analysis': self.analysis, 'Attribute': []}
        if not self.new:
            to_return['Event'].update(
                {'id': self.id, 'orgc_id': self.orgc_id, 'org_id': self.org_id,
                 'uuid': self.uuid, 'sharing_group_id': self.sharing_group_id})
        if self.dump_full:
            to_return['Event'].update(
                {'locked': self.locked, 'attribute_count': self.attribute_count,
                 'RelatedEvent': self.RelatedEvent, 'Orgc': self.Orgc,
                 'ShadowAttribute': self.ShadowAttribute, 'Org': self.Org,
                 'proposal_email_lock': self.proposal_email_lock,
                 'publish_timestamp': int(time.mktime(self.publish_timestamp.timetuple()))})
        to_return['Event']['Attribute'] = [a.dump() for a in self.attributes]
        return json.dumps(to_return)

    def set_values(self, info, distribution=3, threat_level_id=2, analysis=0, date=None):
        self._validate(distribution, threat_level_id, analysis)
        self.info = info
        self.distribution = distribution
        self.threat_level_id = threat_level_id
        self.analysis = analysis
        if not date:
            self.date = datetime.date.today()
        else:
            self.date = date

    def set_values_existing_event(self, event_id, orgc_id, org_id, uuid, attribute_count,
                                  proposal_email_lock, locked, publish_timestamp,
                                  sharing_group_id, Org, Orgc, ShadowAttribute,
                                  RelatedEvent):
        self.id = int(event_id)
        self.orgc_id = int(orgc_id)
        self.org_id = int(org_id)
        self.uuid = uuid
        self.attribute_count = int(attribute_count)
        self.proposal_email_lock = proposal_email_lock
        self.locked = locked
        self.publish_timestamp = datetime.datetime.fromtimestamp(publish_timestamp)
        self.sharing_group_id = int(sharing_group_id)
        self.Org = Org
        self.Orgc = Orgc
        self.ShadowAttribute = ShadowAttribute
        self.RelatedEvent = RelatedEvent

    def publish(self):
        self.publish = True

    def unpublish(self):
        self.publish = False

    def prepare_for_update(self):
        self.unpublish()
        self.dump_full = False

    def add_attribute(self, type_value, value, **kwargs):
        if not self.sane_default.get(type_value):
            raise NewAttributeError("{} is an invalid type. Can only be one of the following: {}".format(type_value, ', '.join(self.types)))
        defaults = self.sane_default[type_value]
        if kwargs.get('category'):
            category = kwargs.get('category')
        else:
            category = defaults['default_category']
        if kwargs.get('to_ids'):
            to_ids = bool(int(kwargs.get('to_ids')))
        else:
            to_ids = bool(int(defaults['to_ids']))
        if kwargs.get('comment'):
            comment = kwargs.get('comment')
        else:
            comment = None
        if kwargs.get('distribution'):
            distribution = int(kwargs.get('distribution'))
        else:
            distribution = 5
        attribute = MISPAttribute(self.categories, self.types, self.category_type_mapping)
        attribute.set_values(type_value, value, category, to_ids, comment, distribution)
        self.attributes.append(attribute)
