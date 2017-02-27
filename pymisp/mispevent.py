#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import time
import json
from json import JSONEncoder
import os
import warnings
import base64
from io import BytesIO
from zipfile import ZipFile
import hashlib

try:
    from dateutil.parser import parse
except ImportError:
    pass

try:
    import jsonschema
except ImportError:
    pass

try:
    # pyme renamed to gpg the 2016-10-28
    import gpg
    from gpg.constants.sig import mode
    has_pyme = True
except ImportError:
    try:
        # pyme renamed to gpg the 2016-10-28
        import pyme as gpg
        from pyme.constants.sig import mode
        has_pyme = True
    except ImportError:
        has_pyme = False

from .exceptions import PyMISPError, NewEventError, NewAttributeError

# Least dirty way to support python 2 and 3
try:
    basestring
    unicode
    warnings.warn("You're using python 2, it is strongly recommended to use python >=3.4")
except NameError:
    basestring = str
    unicode = str


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
        self.data = None
        self.encrypt = False
        self.id = None
        self.uuid = None
        self.timestamp = None
        self.sharing_group_id = None
        self.deleted = None
        self.sig = None
        self.SharingGroup = []
        self.ShadowAttribute = []
        self.disable_correlation = False
        self.RelatedAttribute = []
        self.Tag = []

    def _serialize(self):
        return '{type}{category}{to_ids}{uuid}{timestamp}{comment}{deleted}{value}'.format(
            type=self.type, category=self.category, to_ids=self.to_ids, uuid=self.uuid, timestamp=self.timestamp,
            comment=self.comment, deleted=self.deleted, value=self.value).encode()

    def sign(self, gpg_uid, passphrase=None):
        if not has_pyme:
            raise PyMISPError('pyme is required, please install: pip install --pre pyme3. You will also need libgpg-error-dev and libgpgme11-dev.')
        to_sign = self._serialize()
        with gpg.Context() as c:
            keys = list(c.keylist(gpg_uid))
            c.signers = keys[:1]
            if passphrase:
                c.set_passphrase_cb(lambda *args: passphrase)
            signed, _ = c.sign(to_sign, mode=mode.DETACH)
            self.sig = base64.b64encode(signed).decode()

    def delete(self):
        self.deleted = True

    def add_tag(self, tag):
        self.Tag.append({'name': tag})

    def verify(self, gpg_uid):
        if not has_pyme:
            raise PyMISPError('pyme is required, please install: pip install --pre pyme3. You will also need libgpg-error-dev and libgpgme11-dev.')
        signed_data = self._serialize()
        with gpg.Context() as c:
            keys = list(c.keylist(gpg_uid))
            try:
                c.verify(signed_data, signature=base64.b64decode(self.sig), verify=keys[:1])
                return {self.uuid: True}
            except:
                return {self.uuid: False}

    def set_all_values(self, **kwargs):
        if kwargs.get('type') and kwargs.get('category'):
            if kwargs['type'] not in self.category_type_mapping[kwargs['category']]:
                raise NewAttributeError('{} and {} is an invalid combinaison, type for this category has to be in {}'.format(kwargs.get('type'), kwargs.get('category'), (', '.join(self.category_type_mapping[kwargs['category']]))))
        # Required
        if kwargs.get('type'):
            self.type = kwargs['type']
            if self.type not in self.types:
                raise NewAttributeError('{} is invalid, type has to be in {}'.format(self.type, (', '.join(self.types))))
        elif not self.type:
            raise NewAttributeError('The type of the attribute is required.')

        type_defaults = self.sane_default[self.type]

        if kwargs.get('value'):
            self.value = kwargs['value']
        elif not self.value:
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
        if kwargs.get('distribution') is not None:
            self.distribution = int(kwargs['distribution'])
            if self.distribution not in [0, 1, 2, 3, 4, 5]:
                raise NewAttributeError('{} is invalid, the distribution has to be in 0, 1, 2, 3, 4, 5'.format(self.distribution))

        # other possible values
        if kwargs.get('data'):
            self.data = kwargs['data']
            self._load_data()
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
        if kwargs.get('sig'):
            self.sig = kwargs['sig']
        if kwargs.get('Tag'):
            self.Tag = [t for t in kwargs['Tag'] if t]

        # If the user wants to disable correlation, let them. Defaults to False.
        self.disable_correlation = kwargs.get("disable_correlation", False)

    def _prepare_new_malware_sample(self):
        if '|' in self.value:
            # Get the filename, ignore the md5, because humans.
            self.malware_filename, md5 = self.value.split('|')
        else:
            # Assuming the user only passed the filename
            self.malware_filename = self.value
        m = hashlib.md5()
        m.update(self.data.getvalue())
        md5 = m.hexdigest()
        self.value = '{}|{}'.format(self.malware_filename, md5)
        self.malware_binary = self.data
        self.encrypt = True

    def _load_data(self):
        if not isinstance(self.data, BytesIO):
            self.data = BytesIO(base64.b64decode(self.data))
        if self.type == 'malware-sample':
            try:
                with ZipFile(self.data) as f:
                    for name in f.namelist():
                        if name.endswith('.txt'):
                            with f.open(name, pwd=b'infected') as unpacked:
                                self.malware_filename = unpacked.read().decode()
                        else:
                            with f.open(name, pwd=b'infected') as unpacked:
                                self.malware_binary = BytesIO(unpacked.read())
            except:
                # not a encrypted zip file, assuming it is a new malware sample
                self._prepare_new_malware_sample()

    def _json(self):
        to_return = {'type': self.type, 'category': self.category, 'to_ids': self.to_ids,
                     'distribution': self.distribution, 'value': self.value,
                     'comment': self.comment, 'disable_correlation': self.disable_correlation}
        if self.uuid:
            to_return['uuid'] = self.uuid
        if self.sig:
            to_return['sig'] = self.sig
        if self.sharing_group_id:
            to_return['sharing_group_id'] = self.sharing_group_id
        if self.Tag:
            to_return['Tag'] = self.Tag
        if self.data:
            to_return['data'] = base64.b64encode(self.data.getvalue()).decode()
            if self.encrypt:
                to_return['entrypt'] = self.encrypt
        to_return = _int_to_str(to_return)
        return to_return

    def _json_full(self):
        to_return = self._json()
        if self.id:
            to_return['id'] = self.id
        if self.timestamp:
            # Should never be set on an update, MISP will automatically set it to now
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
        with open(os.path.join(self.ressources_path, 'schema.json'), 'r') as f:
            self.json_schema = json.load(f)
        with open(os.path.join(self.ressources_path, 'schema-lax.json'), 'r') as f:
            self.json_schema_lax = json.load(f)
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
        self.sig = None
        self.global_sig = None
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
        self.Galaxy = None

    def _serialize(self):
        return '{date}{threat_level_id}{info}{uuid}{analysis}{timestamp}'.format(
            date=self.date, threat_level_id=self.threat_level_id, info=self.info,
            uuid=self.uuid, analysis=self.analysis, timestamp=self.timestamp).encode()

    def _serialize_sigs(self):
        all_sigs = self.sig
        for a in self.attributes:
            all_sigs += a.sig
        return all_sigs.encode()

    def sign(self, gpg_uid, passphrase=None):
        if not has_pyme:
            raise PyMISPError('pyme is required, please install: pip install --pre pyme3. You will also need libgpg-error-dev and libgpgme11-dev.')
        to_sign = self._serialize()
        with gpg.Context() as c:
            keys = list(c.keylist(gpg_uid))
            c.signers = keys[:1]
            if passphrase:
                c.set_passphrase_cb(lambda *args: passphrase)
            signed, _ = c.sign(to_sign, mode=mode.DETACH)
            self.sig = base64.b64encode(signed).decode()
        for a in self.attributes:
            a.sign(gpg_uid, passphrase)
        to_sign_global = self._serialize_sigs()
        with gpg.Context() as c:
            keys = list(c.keylist(gpg_uid))
            c.signers = keys[:1]
            if passphrase:
                c.set_passphrase_cb(lambda *args: passphrase)
            signed, _ = c.sign(to_sign_global, mode=mode.DETACH)
            self.global_sig = base64.b64encode(signed).decode()

    def verify(self, gpg_uid):
        if not has_pyme:
            raise PyMISPError('pyme is required, please install: pip install --pre pyme3. You will also need libgpg-error-dev and libgpgme11-dev.')
        to_return = {}
        signed_data = self._serialize()
        with gpg.Context() as c:
            keys = list(c.keylist(gpg_uid))
            try:
                c.verify(signed_data, signature=base64.b64decode(self.sig), verify=keys[:1])
                to_return[self.uuid] = True
            except:
                to_return[self.uuid] = False
        for a in self.attributes:
            to_return.update(a.verify(gpg_uid))
        to_verify_global = self._serialize_sigs()
        with gpg.Context() as c:
            keys = list(c.keylist(gpg_uid))
            try:
                c.verify(to_verify_global, signature=base64.b64decode(self.global_sig), verify=keys[:1])
                to_return['global'] = True
            except:
                to_return['global'] = False
        return to_return

    def load_file(self, event_path):
        if not os.path.exists(event_path):
            raise PyMISPError('Invalid path, unable to load the event.')
        with open(event_path, 'r') as f:
            self.load(f)

    def load(self, json_event):
        self.new = False
        self.dump_full = True
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

    def set_date(self, date, ignore_invalid=False):
        if isinstance(date, basestring) or isinstance(date, unicode):
            self.date = parse(date).date()
        elif isinstance(date, datetime.datetime):
            self.date = date.date()
        elif isinstance(date, datetime.date):
            self.date = date
        else:
            if ignore_invalid:
                self.date = datetime.date.today()
            else:
                raise NewEventError('Invalid format for the date: {} - {}'.format(date, type(date)))

    def set_all_values(self, **kwargs):
        # Required value
        if kwargs.get('info'):
            self.info = kwargs['info']
        elif not self.info:
            raise NewAttributeError('The info field of the new event is required.')

        # Default values for a valid event to send to a MISP instance
        if kwargs.get('distribution') is not None:
            self.distribution = int(kwargs['distribution'])
            if self.distribution not in [0, 1, 2, 3, 4]:
                raise NewEventError('{} is invalid, the distribution has to be in 0, 1, 2, 3, 4'.format(self.distribution))
        if kwargs.get('threat_level_id') is not None:
            self.threat_level_id = int(kwargs['threat_level_id'])
            if self.threat_level_id not in [1, 2, 3, 4]:
                raise NewEventError('{} is invalid, the threat_level has to be in 1, 2, 3, 4'.format(self.threat_level_id))
        if kwargs.get('analysis') is not None:
            self.analysis = int(kwargs['analysis'])
            if self.analysis not in [0, 1, 2]:
                raise NewEventError('{} is invalid, the analysis has to be in 0, 1, 2'.format(self.analysis))
        if kwargs.get('published') is not None:
            self.unpublish()
        if kwargs.get("published") == True:
            self.publish()
        if kwargs.get('date'):
            self.set_date(kwargs['date'])
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
            self.RelatedEvent = []
            for rel_event in kwargs['RelatedEvent']:
                sub_event = MISPEvent()
                sub_event.load(rel_event)
                self.RelatedEvent.append(sub_event)
        if kwargs.get('Galaxy'):
            self.Galaxy = kwargs['Galaxy']
        if kwargs.get('Tag'):
            self.Tag = [t for t in kwargs['Tag'] if t]
        if kwargs.get('sig'):
            self.sig = kwargs['sig']
        if kwargs.get('global_sig'):
            self.global_sig = kwargs['global_sig']

    def _json(self):
        to_return = {'Event': {}}
        to_return['Event'] = {'distribution': self.distribution, 'info': self.info,
                              'date': self.date.isoformat(), 'published': self.published,
                              'threat_level_id': self.threat_level_id,
                              'analysis': self.analysis, 'Attribute': []}
        if self.sig:
            to_return['Event']['sig'] = self.sig
        if self.global_sig:
            to_return['Event']['global_sig'] = self.global_sig
        if self.uuid:
            to_return['Event']['uuid'] = self.uuid
        if self.Tag:
            to_return['Event']['Tag'] = self.Tag
        if self.Orgc:
            to_return['Event']['Orgc'] = self.Orgc
        if self.Galaxy:
            to_return['Event']['Galaxy'] = self.Galaxy
        if self.sharing_group_id:
            to_return['Event']['sharing_group_id'] = self.sharing_group_id
        to_return['Event'] = _int_to_str(to_return['Event'])
        if self.attributes:
            to_return['Event']['Attribute'] = [a._json() for a in self.attributes]
        jsonschema.validate(to_return, self.json_schema)
        return to_return

    def _json_full(self):
        to_return = self._json()
        if self.id:
            to_return['Event']['id'] = self.id
        if self.orgc_id:
            to_return['Event']['orgc_id'] = self.orgc_id
        if self.org_id:
            to_return['Event']['org_id'] = self.org_id
        if self.locked is not None:
            to_return['Event']['locked'] = self.locked
        if self.attribute_count is not None:
            to_return['Event']['attribute_count'] = self.attribute_count
        if self.RelatedEvent:
            to_return['Event']['RelatedEvent'] = []
            for rel_event in self.RelatedEvent:
                to_return['Event']['RelatedEvent'].append(rel_event._json_full())
        if self.Org:
            to_return['Event']['Org'] = self.Org
        if self.sharing_group_id:
            to_return['Event']['sharing_group_id'] = self.sharing_group_id
        if self.ShadowAttribute:
            to_return['Event']['ShadowAttribute'] = self.ShadowAttribute
        if self.proposal_email_lock is not None:
            to_return['Event']['proposal_email_lock'] = self.proposal_email_lock
        if self.locked is not None:
            to_return['Event']['locked'] = self.locked
        if self.publish_timestamp:
            to_return['Event']['publish_timestamp'] = int(time.mktime(self.publish_timestamp.timetuple()))
        if self.timestamp:
            # Should never be set on an update, MISP will automatically set it to now
            to_return['Event']['timestamp'] = int(time.mktime(self.timestamp.timetuple()))
        to_return['Event'] = _int_to_str(to_return['Event'])
        if self.attributes:
            to_return['Event']['Attribute'] = [a._json_full() for a in self.attributes]
        jsonschema.validate(to_return, self.json_schema)
        return to_return

    def add_tag(self, tag):
        self.Tag.append({'name': tag})

    def add_attribute_tag(self, tag, attribute_identifier):
        attribute = None
        for a in self.attributes:
            if a.id == attribute_identifier or a.uuid == attribute_identifier or attribute_identifier in a.value:
                a.add_tag(tag)
                attribute = a
        if not attribute:
            raise Exception('No attribute with identifier {} found.'.format(attribute_identifier))
        return attribute

    def publish(self):
        self.published = True

    def unpublish(self):
        self.published = False

    def delete_attribute(self, attribute_id):
        found = False
        for a in self.attributes:
            if a.id == attribute_id or a.uuid == attribute_id:
                a.delete()
                found = True
                break
        if not found:
            raise Exception('No attribute with UUID/ID {} found.'.format(attribute_id))

    def add_attribute(self, type, value, **kwargs):
        attribute = MISPAttribute(self.describe_types)
        attribute.set_all_values(type=type, value=value, **kwargs)
        self.attributes.append(attribute)
