# -*- coding: utf-8 -*-

import datetime
import json
import os
import base64
from io import BytesIO
from zipfile import ZipFile
import sys
import uuid
from collections import defaultdict
import logging
import hashlib

from deprecated import deprecated

from .abstract import AbstractMISP
from .exceptions import UnknownMISPObjectTemplate, InvalidMISPObject, PyMISPError, NewEventError, NewAttributeError


logger = logging.getLogger('pymisp')

if sys.version_info < (3, 0):
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


if (3, 0) <= sys.version_info < (3, 6):
    OLD_PY3 = True
else:
    OLD_PY3 = False

if sys.version_info >= (3, 6):
    from pathlib import Path

try:
    from dateutil.parser import parse
except ImportError:
    logger.exception("Cannot import dateutil")

try:
    import jsonschema
except ImportError:
    logger.exception("Cannot import jsonschema")

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

# Least dirty way to support python 2 and 3
try:
    basestring
    unicode
except NameError:
    basestring = str
    unicode = str


def _int_to_str(d):
    # transform all integer back to string
    for k, v in d.items():
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            d[k] = str(v)
    return d


def make_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    if not value:  # None, 0, '', {}, []
        return False

    if isinstance(value, str):
        if value == '0':
            return False
        return True
    else:
        raise PyMISPError('Unable to convert {} to a boolean.'.format(value))


class MISPAttribute(AbstractMISP):
    _fields_for_feed = {'uuid', 'value', 'category', 'type', 'comment', 'data',
                        'timestamp', 'to_ids', 'object_relation', 'disable_correlation'}

    def __init__(self, describe_types=None, strict=False):
        """Represents an Attribute
            :describe_type: Use it is you want to overwrite the defualt describeTypes.json file (you don't)
            :strict: If false, fallback to sane defaults for the attribute type if the ones passed by the user are incorrect
        """
        super(MISPAttribute, self).__init__()
        if describe_types:
            self.describe_types = describe_types
        self.__categories = self.describe_types['categories']
        self.__category_type_mapping = self.describe_types['category_type_mappings']
        self.__sane_default = self.describe_types['sane_defaults']
        self.__strict = strict
        self._data = None
        self.uuid = str(uuid.uuid4())
        self.ShadowAttribute = []
        self.Sighting = []

    def hash_values(self, algorithm='sha512'):
        """Compute the hash of every values for fast lookups"""
        if algorithm not in hashlib.algorithms_available:
            raise PyMISPError('The algorithm {} is not available for hashing.'.format(algorithm))
        if '|' in self.type or self.type == 'malware-sample':
            hashes = []
            for v in self.value.split('|'):
                h = hashlib.new(algorithm)
                h.update(v.encode("utf-8"))
                hashes.append(h.hexdigest())
            return hashes
        else:
            h = hashlib.new(algorithm)
            to_encode = self.value
            if not isinstance(to_encode, str):
                to_encode = str(to_encode)
            h.update(to_encode.encode("utf-8"))
            return [h.hexdigest()]

    def _to_feed(self):
        to_return = super(MISPAttribute, self)._to_feed()
        if self.data:
            to_return['data'] = base64.b64encode(self.data.getvalue()).decode()
        if self.tags:
            to_return['Tag'] = list(filter(None, [tag._to_feed() for tag in self.tags]))
        return to_return

    @property
    def known_types(self):
        """Returns a list of all the known MISP attributes types"""
        return self.describe_types['types']

    @property
    def malware_binary(self):
        """Returns a BytesIO of the malware (if the attribute has one, obvs)."""
        if hasattr(self, '_malware_binary'):
            return self._malware_binary
        return None

    @property
    def shadow_attributes(self):
        return self.ShadowAttribute

    @shadow_attributes.setter
    def shadow_attributes(self, shadow_attributes):
        """Set a list of prepared MISPShadowAttribute."""
        if all(isinstance(x, MISPShadowAttribute) for x in shadow_attributes):
            self.ShadowAttribute = shadow_attributes
        else:
            raise PyMISPError('All the attributes have to be of type MISPShadowAttribute.')

    @property
    def sightings(self):
        return self.Sighting

    @sightings.setter
    def sightings(self, sightings):
        """Set a list of prepared MISPShadowAttribute."""
        if all(isinstance(x, MISPSighting) for x in sightings):
            self.Sighting = sightings
        else:
            raise PyMISPError('All the attributes have to be of type MISPSighting.')

    def delete(self):
        """Mark the attribute as deleted (soft delete)"""
        self.deleted = True

    def add_proposal(self, shadow_attribute=None, **kwargs):
        """Alias for add_shadow_attribute"""
        return self.add_shadow_attribute(shadow_attribute, **kwargs)

    def add_shadow_attribute(self, shadow_attribute=None, **kwargs):
        """Add a shadow attribute to the attribute (by name or a MISPShadowAttribute object)"""
        if isinstance(shadow_attribute, MISPShadowAttribute):
            misp_shadow_attribute = shadow_attribute
        elif isinstance(shadow_attribute, dict):
            misp_shadow_attribute = MISPShadowAttribute()
            misp_shadow_attribute.from_dict(**shadow_attribute)
        elif kwargs:
            misp_shadow_attribute = MISPShadowAttribute()
            misp_shadow_attribute.from_dict(**kwargs)
        else:
            raise PyMISPError("The shadow_attribute is in an invalid format (can be either string, MISPShadowAttribute, or an expanded dict): {}".format(shadow_attribute))
        self.shadow_attributes.append(misp_shadow_attribute)
        self.edited = True
        return misp_shadow_attribute

    def add_sighting(self, sighting=None, **kwargs):
        """Add a sighting to the attribute (by name or a MISPSighting object)"""
        if isinstance(sighting, MISPSighting):
            misp_sighting = sighting
        elif isinstance(sighting, dict):
            misp_sighting = MISPSighting()
            misp_sighting.from_dict(**sighting)
        elif kwargs:
            misp_sighting = MISPSighting()
            misp_sighting.from_dict(**kwargs)
        else:
            raise PyMISPError("The sighting is in an invalid format (can be either string, MISPShadowAttribute, or an expanded dict): {}".format(sighting))
        self.sightings.append(misp_sighting)
        self.edited = True
        return misp_sighting

    def from_dict(self, **kwargs):
        if 'Attribute' in kwargs:
            kwargs = kwargs['Attribute']
        if kwargs.get('type') and kwargs.get('category'):
            if kwargs['type'] not in self.__category_type_mapping[kwargs['category']]:
                if self.__strict:
                    raise NewAttributeError('{} and {} is an invalid combination, type for this category has to be in {}'.format(
                        kwargs.get('type'), kwargs.get('category'), (', '.join(self.__category_type_mapping[kwargs['category']]))))
                else:
                    kwargs.pop('category', None)

        self.type = kwargs.pop('type', None)  # Required
        if self.type is None:
            raise NewAttributeError('The type of the attribute is required.')
        if self.type not in self.known_types:
            raise NewAttributeError('{} is invalid, type has to be in {}'.format(self.type, (', '.join(self.known_types))))

        type_defaults = self.__sane_default[self.type]

        self.value = kwargs.pop('value', None)
        if self.value is None:
            raise NewAttributeError('The value of the attribute is required.')
        if self.type == 'datetime' and isinstance(self.value, str):
            try:
                if '.' in self.value:
                    self.value = datetime.datetime.strptime(self.value, "%Y-%m-%dT%H:%M:%S.%f")
                else:
                    self.value = datetime.datetime.strptime(self.value, "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                # Slower, but if the other ones fail, that's a good fallback
                self.value = parse(self.value)

        # Default values
        self.category = kwargs.pop('category', type_defaults['default_category'])
        if self.category is None:
            # In case the category key is passed, but None
            self.category = type_defaults['default_category']
        if self.category not in self.__categories:
            raise NewAttributeError('{} is invalid, category has to be in {}'.format(self.category, (', '.join(self.__categories))))

        self.to_ids = kwargs.pop('to_ids', bool(int(type_defaults['to_ids'])))
        if self.to_ids is None:
            self.to_ids = bool(int(type_defaults['to_ids']))
        else:
            self.to_ids = make_bool(self.to_ids)

        if not isinstance(self.to_ids, bool):
            raise NewAttributeError('{} is invalid, to_ids has to be True or False'.format(self.to_ids))

        self.distribution = kwargs.pop('distribution', None)
        if self.distribution is not None:
            self.distribution = int(self.distribution)
            if self.distribution not in [0, 1, 2, 3, 4, 5]:
                raise NewAttributeError('{} is invalid, the distribution has to be in 0, 1, 2, 3, 4, 5'.format(self.distribution))

        # other possible values
        if kwargs.get('data'):
            self.data = kwargs.pop('data')
        if kwargs.get('id'):
            self.id = int(kwargs.pop('id'))
        if kwargs.get('event_id'):
            self.event_id = int(kwargs.pop('event_id'))
        if kwargs.get('timestamp'):
            ts = kwargs.pop('timestamp')
            if isinstance(ts, datetime.datetime):
                self.timestamp = ts
            elif sys.version_info >= (3, 3):
                self.timestamp = datetime.datetime.fromtimestamp(int(ts), datetime.timezone.utc)
            else:
                self.timestamp = datetime.datetime.fromtimestamp(int(ts), UTC())
        if kwargs.get('sharing_group_id'):
            self.sharing_group_id = int(kwargs.pop('sharing_group_id'))

        if self.distribution == 4:
            # The distribution is set to sharing group, a sharing_group_id is required.
            if not hasattr(self, 'sharing_group_id'):
                raise NewAttributeError('If the distribution is set to sharing group, a sharing group ID is required.')
            elif not self.sharing_group_id:
                # Cannot be None or 0 either.
                raise NewAttributeError('If the distribution is set to sharing group, a sharing group ID is required (cannot be {}).'.format(self.sharing_group_id))

        if kwargs.get('Tag'):
            [self.add_tag(tag) for tag in kwargs.pop('Tag')]
        if kwargs.get('Sighting'):
            [self.add_sighting(sighting) for sighting in kwargs.pop('Sighting')]
        if kwargs.get('ShadowAttribute'):
            [self.add_shadow_attribute(s_attr) for s_attr in kwargs.pop('ShadowAttribute')]

        # If the user wants to disable correlation, let them. Defaults to False.
        self.disable_correlation = kwargs.pop("disable_correlation", False)
        if self.disable_correlation is None:
            self.disable_correlation = False

        super(MISPAttribute, self).from_dict(**kwargs)

    def to_dict(self):
        to_return = super(MISPAttribute, self).to_dict()
        if self.data:
            to_return['data'] = base64.b64encode(self.data.getvalue()).decode()
        return to_return

    def _prepare_new_malware_sample(self):
        if '|' in self.value:
            # Get the filename, ignore the md5, because humans.
            self.malware_filename, md5 = self.value.split('|')
        else:
            # Assuming the user only passed the filename
            self.malware_filename = self.value
        # m = hashlib.md5()
        # m.update(self.data.getvalue())
        self.value = self.malware_filename
        # md5 = m.hexdigest()
        # self.value = '{}|{}'.format(self.malware_filename, md5)
        self._malware_binary = self.data
        self.encrypt = True

    def __is_misp_encrypted_file(self, f):
        files_list = f.namelist()
        if len(files_list) != 2:
            return False
        md5_from_filename = ''
        md5_from_file = ''
        for name in files_list:
            if name.endswith('.filename.txt'):
                md5_from_filename = name.replace('.filename.txt', '')
            else:
                md5_from_file = name
        if not md5_from_filename or not md5_from_file or md5_from_filename != md5_from_file:
            return False
        return True

    @property
    def data(self):
        return self._data if self._data else None

    @data.setter
    def data(self, data):
        if sys.version_info <= (3, ):
            if isinstance(data, unicode):
                self._data = BytesIO(base64.b64decode(data.encode()))
        if sys.version_info >= (3, 6):
            if isinstance(data, Path):
                with data.open('rb') as f:
                    self._data = BytesIO(f.read())
        if isinstance(data, (str, bytes)):
            self._data = BytesIO(base64.b64decode(data))
        elif isinstance(data, BytesIO):
            self._data = data
        if self.type == 'malware-sample':
            try:
                with ZipFile(self.data) as f:
                    if not self.__is_misp_encrypted_file(f):
                        raise PyMISPError('Not an existing malware sample')
                    for name in f.namelist():
                        if name.endswith('.filename.txt'):
                            with f.open(name, pwd=b'infected') as unpacked:
                                self.malware_filename = unpacked.read().decode().strip()
                        else:
                            with f.open(name, pwd=b'infected') as unpacked:
                                self._malware_binary = BytesIO(unpacked.read())
            except Exception:
                # not a encrypted zip file, assuming it is a new malware sample
                self._prepare_new_malware_sample()

    def __repr__(self):
        if hasattr(self, 'value'):
            return '<{self.__class__.__name__}(type={self.type}, value={self.value})'.format(self=self)
        return '<{self.__class__.__name__}(NotInitialized)'.format(self=self)

    def verify(self, gpg_uid):  # pragma: no cover
        # Not used
        if not has_pyme:
            raise PyMISPError('pyme is required, please install: pip install --pre pyme3. You will also need libgpg-error-dev and libgpgme11-dev.')
        signed_data = self._serialize()
        with gpg.Context() as c:
            keys = list(c.keylist(gpg_uid))
            try:
                c.verify(signed_data, signature=base64.b64decode(self.sig), verify=keys[:1])
                return {self.uuid: True}
            except Exception:
                return {self.uuid: False}

    def _serialize(self):  # pragma: no cover
        # Not used
        return '{type}{category}{to_ids}{uuid}{timestamp}{comment}{deleted}{value}'.format(
            type=self.type, category=self.category, to_ids=self.to_ids, uuid=self.uuid, timestamp=self.timestamp,
            comment=self.comment, deleted=self.deleted, value=self.value).encode()

    def sign(self, gpg_uid, passphrase=None):  # pragma: no cover
        # Not used
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

    @deprecated(reason="Use self.known_types instead. Removal date: 2020-01-01.")
    def get_known_types(self):  # pragma: no cover
        return self.known_types

    @deprecated(reason="Use self.malware_binary instead. Removal date: 2020-01-01.")
    def get_malware_binary(self):  # pragma: no cover
        return self.malware_binary

    @deprecated(reason="Use self.to_dict() instead. Removal date: 2020-01-01.")
    def _json(self):  # pragma: no cover
        return self.to_dict()

    @deprecated(reason="Use self.to_dict() instead. Removal date: 2020-01-01.")
    def _json_full(self):  # pragma: no cover
        return self.to_dict()

    @deprecated(reason="Use self.from_dict(**kwargs) instead. Removal date: 2020-01-01.")
    def set_all_values(self, **kwargs):  # pragma: no cover
        self.from_dict(**kwargs)


class MISPEvent(AbstractMISP):

    _fields_for_feed = {'uuid', 'info', 'threat_level_id', 'analysis', 'timestamp',
                        'publish_timestamp', 'published', 'date', 'extends_uuid'}

    def __init__(self, describe_types=None, strict_validation=False, **kwargs):
        super(MISPEvent, self).__init__(**kwargs)
        if strict_validation:
            schema_file = 'schema.json'
        else:
            schema_file = 'schema-lax.json'
        if sys.version_info >= (3, 4):
            self.__json_schema = self._load_json(self.resources_path / schema_file)
        else:
            self.__json_schema = self._load_json(os.path.join(self.resources_path, schema_file))
        if describe_types:
            # This variable is used in add_attribute in order to avoid duplicating the structure
            self.describe_types = describe_types

        self.Attribute = []
        self.Object = []
        self.RelatedEvent = []
        self.ShadowAttribute = []

    def _set_default(self):
        """There are a few keys that could be set by default"""
        if not hasattr(self, 'uuid'):
            self.uuid = str(uuid.uuid4())
        if not hasattr(self, 'date'):
            self.set_date(datetime.date.today())
        if not hasattr(self, 'timestamp'):
            self.timestamp = datetime.datetime.timestamp(datetime.datetime.now())
        if not hasattr(self, 'analysis'):
            # analysis: 0 means initial, 1 ongoing, 2 completed
            self.analysis = 2
        if not hasattr(self, 'threat_level_id'):
            # threat_level_id 4 means undefined. Tags are recommended.
            self.threat_level_id = 4

    @property
    def manifest(self):
        required = ['info', 'Orgc']
        for r in required:
            if not hasattr(self, r):
                raise PyMISPError('The field {} is required to generate the event manifest.')

        self._set_default()

        return {
            self.uuid: {
                'Orgc': self.Orgc._to_feed(),
                'Tag': list(filter(None, [tag._to_feed() for tag in self.tags])),
                'info': self.info,
                'date': self.date.isoformat(),
                'analysis': self.analysis,
                'threat_level_id': self.threat_level_id,
                'timestamp': self._datetime_to_timestamp(self.timestamp)
            }
        }

    def attributes_hashes(self, algorithm='sha512'):
        to_return = []
        for attribute in self.attributes:
            to_return += attribute.hash_values(algorithm)
        for obj in self.objects:
            for attribute in obj.attributes:
                to_return += attribute.hash_values(algorithm)
        return to_return

    def to_feed(self, valid_distributions=[0, 1, 2, 3, 4, 5], with_meta=False):
        """ Generate a json output for MISP Feed.
        Notes:
            * valid_distributions only makes sense if the distribution key is set (i.e. the event is exported from a MISP instance)
        """
        required = ['info', 'Orgc']
        for r in required:
            if not hasattr(self, r):
                raise PyMISPError('The field {} is required to generate the event feed output.')

        if (hasattr(self, 'distribution')
                and self.distribution is not None
                and int(self.distribution) not in valid_distributions):
            return

        self._set_default()

        to_return = super(MISPEvent, self)._to_feed()
        if with_meta:
            to_return['_hashes'] = []
            to_return['_manifest'] = self.manifest

        to_return['Orgc'] = self.Orgc._to_feed()
        to_return['Tag'] = list(filter(None, [tag._to_feed() for tag in self.tags]))
        if self.attributes:
            to_return['Attribute'] = []
            for attribute in self.attributes:
                if (valid_distributions and attribute.get('distribution') is not None and attribute.distribution not in valid_distributions):
                    continue
                to_return['Attribute'].append(attribute._to_feed())
                if with_meta:
                    to_return['_hashes'] += attribute.hash_values('md5')

        if self.objects:
            to_return['Object'] = []
            for obj in self.objects:
                if (valid_distributions and obj.get('distribution') is not None and obj.distribution not in valid_distributions):
                    continue
                obj_to_attach = obj._to_feed()
                obj_to_attach['Attribute'] = []
                for attribute in obj.attributes:
                    if (valid_distributions and attribute.get('distribution') is not None and attribute.distribution not in valid_distributions):
                        continue
                    obj_to_attach['Attribute'].append(attribute._to_feed())
                    if with_meta:
                        to_return['_hashes'] += attribute.hash_values('md5')
                to_return['Object'].append(obj_to_attach)

        return to_return

    @property
    def known_types(self):
        return self.describe_types['types']

    @property
    def org(self):
        return self.Org

    @property
    def orgc(self):
        return self.Orgc

    @orgc.setter
    def orgc(self, orgc):
        if isinstance(orgc, MISPOrganisation):
            self.Orgc = orgc
        else:
            raise PyMISPError('Orgc must be of type MISPOrganisation.')

    @property
    def attributes(self):
        return self.Attribute

    @attributes.setter
    def attributes(self, attributes):
        if all(isinstance(x, MISPAttribute) for x in attributes):
            self.Attribute = attributes
        else:
            raise PyMISPError('All the attributes have to be of type MISPAttribute.')

    @property
    def shadow_attributes(self):
        return self.ShadowAttribute

    @shadow_attributes.setter
    def shadow_attributes(self, shadow_attributes):
        if all(isinstance(x, MISPShadowAttribute) for x in shadow_attributes):
            self.ShadowAttribute = shadow_attributes
        else:
            raise PyMISPError('All the attributes have to be of type MISPShadowAttribute.')

    @property
    def related_events(self):
        return self.RelatedEvent

    @property
    def objects(self):
        return self.Object

    @objects.setter
    def objects(self, objects):
        if all(isinstance(x, MISPObject) for x in objects):
            self.Object = objects
        else:
            raise PyMISPError('All the attributes have to be of type MISPObject.')

    def load_file(self, event_path):
        """Load a JSON dump from a file on the disk"""
        if not os.path.exists(event_path):
            raise PyMISPError('Invalid path, unable to load the event.')
        with open(event_path, 'rb') as f:
            self.load(f)

    def load(self, json_event, validate=False):
        """Load a JSON dump from a pseudo file or a JSON string"""
        if hasattr(json_event, 'read'):
            # python2 and python3 compatible to find if we have a file
            json_event = json_event.read()
        if isinstance(json_event, (basestring, bytes)):
            if OLD_PY3 and isinstance(json_event, bytes):
                json_event = json_event.decode()
            json_event = json.loads(json_event)
        if json_event.get('response'):
            event = json_event.get('response')[0]
        else:
            event = json_event
        if not event:
            raise PyMISPError('Invalid event')
        self.from_dict(**event)
        if validate:
            jsonschema.validate(json.loads(self.to_json()), self.__json_schema)

    def set_date(self, date, ignore_invalid=False):
        """Set a date for the event (string, datetime, or date object)"""
        if isinstance(date, basestring) or isinstance(date, unicode):
            self.date = parse(date).date()
        elif isinstance(date, int):
            self.date = datetime.datetime.utcfromtimestamp(date).date()
        elif isinstance(date, datetime.datetime):
            self.date = date.date()
        elif isinstance(date, datetime.date):
            self.date = date
        else:
            if ignore_invalid:
                self.date = datetime.date.today()
            else:
                raise NewEventError('Invalid format for the date: {} - {}'.format(date, type(date)))

    def from_dict(self, **kwargs):
        if 'Event' in kwargs:
            kwargs = kwargs['Event']
        # Required value
        self.info = kwargs.pop('info', None)
        if self.info is None:
            raise NewEventError('The info field of the new event is required.')

        # Default values for a valid event to send to a MISP instance
        self.distribution = kwargs.pop('distribution', None)
        if self.distribution is not None:
            self.distribution = int(self.distribution)
            if self.distribution not in [0, 1, 2, 3, 4]:
                raise NewEventError('{} is invalid, the distribution has to be in 0, 1, 2, 3, 4'.format(self.distribution))

        if kwargs.get('threat_level_id') is not None:
            self.threat_level_id = int(kwargs.pop('threat_level_id'))
            if self.threat_level_id not in [1, 2, 3, 4]:
                raise NewEventError('{} is invalid, the threat_level has to be in 1, 2, 3, 4'.format(self.threat_level_id))

        if kwargs.get('analysis') is not None:
            self.analysis = int(kwargs.pop('analysis'))
            if self.analysis not in [0, 1, 2]:
                raise NewEventError('{} is invalid, the analysis has to be in 0, 1, 2'.format(self.analysis))

        self.published = kwargs.pop('published', None)
        if self.published is True:
            self.publish()
        else:
            self.unpublish()

        if kwargs.get('date'):
            self.set_date(kwargs.pop('date'))
        if kwargs.get('Attribute'):
            [self.add_attribute(**a) for a in kwargs.pop('Attribute')]

        # All other keys
        if kwargs.get('id'):
            self.id = int(kwargs.pop('id'))
        if kwargs.get('orgc_id'):
            self.orgc_id = int(kwargs.pop('orgc_id'))
        if kwargs.get('org_id'):
            self.org_id = int(kwargs.pop('org_id'))
        if kwargs.get('timestamp'):
            if sys.version_info >= (3, 3):
                self.timestamp = datetime.datetime.fromtimestamp(int(kwargs.pop('timestamp')), datetime.timezone.utc)
            else:
                self.timestamp = datetime.datetime.fromtimestamp(int(kwargs.pop('timestamp')), UTC())
        if kwargs.get('publish_timestamp'):
            if sys.version_info >= (3, 3):
                self.publish_timestamp = datetime.datetime.fromtimestamp(int(kwargs.pop('publish_timestamp')), datetime.timezone.utc)
            else:
                self.publish_timestamp = datetime.datetime.fromtimestamp(int(kwargs.pop('publish_timestamp')), UTC())
        if kwargs.get('sharing_group_id'):
            self.sharing_group_id = int(kwargs.pop('sharing_group_id'))
        if kwargs.get('RelatedEvent'):
            for rel_event in kwargs.pop('RelatedEvent'):
                sub_event = MISPEvent()
                sub_event.load(rel_event)
                self.RelatedEvent.append({'Event': sub_event})
        if kwargs.get('Tag'):
            [self.add_tag(tag) for tag in kwargs.pop('Tag')]
        if kwargs.get('Object'):
            [self.add_object(obj) for obj in kwargs.pop('Object')]
        if kwargs.get('Org'):
            self.Org = MISPOrganisation()
            self.Org.from_dict(**kwargs.pop('Org'))
        if kwargs.get('Orgc'):
            self.Orgc = MISPOrganisation()
            self.Orgc.from_dict(**kwargs.pop('Orgc'))

        super(MISPEvent, self).from_dict(**kwargs)

    def to_dict(self):
        to_return = super(MISPEvent, self).to_dict()

        if to_return.get('date'):
            if isinstance(self.date, datetime.datetime):
                self.date = self.date.date()
            to_return['date'] = self.date.isoformat()
        if to_return.get('publish_timestamp'):
            to_return['publish_timestamp'] = self._datetime_to_timestamp(self.publish_timestamp)

        return to_return

    def add_proposal(self, shadow_attribute=None, **kwargs):
        """Alias for add_shadow_attribute"""
        return self.add_shadow_attribute(shadow_attribute, **kwargs)

    def add_shadow_attribute(self, shadow_attribute=None, **kwargs):
        """Add a tag to the attribute (by name or a MISPTag object)"""
        if isinstance(shadow_attribute, MISPShadowAttribute):
            misp_shadow_attribute = shadow_attribute
        elif isinstance(shadow_attribute, dict):
            misp_shadow_attribute = MISPShadowAttribute()
            misp_shadow_attribute.from_dict(**shadow_attribute)
        elif kwargs:
            misp_shadow_attribute = MISPShadowAttribute()
            misp_shadow_attribute.from_dict(**kwargs)
        else:
            raise PyMISPError("The shadow_attribute is in an invalid format (can be either string, MISPShadowAttribute, or an expanded dict): {}".format(shadow_attribute))
        self.shadow_attributes.append(misp_shadow_attribute)
        self.edited = True
        return misp_shadow_attribute

    def get_attribute_tag(self, attribute_identifier):
        """Return the tags associated to an attribute or an object attribute.
           :attribute_identifier: can be an ID, UUID, or the value.
        """
        tags = []
        for a in self.attributes + [attribute for o in self.objects for attribute in o.attributes]:
            if ((hasattr(a, 'id') and a.id == attribute_identifier)
                    or (hasattr(a, 'uuid') and a.uuid == attribute_identifier)
                    or (hasattr(a, 'value') and attribute_identifier == a.value
                        or attribute_identifier in a.value.split('|'))):
                tags += a.tags
        return tags

    def add_attribute_tag(self, tag, attribute_identifier):
        """Add a tag to an existing attribute, raise an Exception if the attribute doesn't exists.
            :tag: Tag name as a string, MISPTag instance, or dictionary
            :attribute_identifier: can be an ID, UUID, or the value.
        """
        attributes = []
        for a in self.attributes + [attribute for o in self.objects for attribute in o.attributes]:
            if ((hasattr(a, 'id') and a.id == attribute_identifier)
                    or (hasattr(a, 'uuid') and a.uuid == attribute_identifier)
                    or (hasattr(a, 'value') and attribute_identifier == a.value
                        or attribute_identifier in a.value.split('|'))):
                a.add_tag(tag)
                attributes.append(a)

        if not attributes:
            raise PyMISPError('No attribute with identifier {} found.'.format(attribute_identifier))
        self.edited = True
        return attributes

    def publish(self):
        """Mark the attribute as published"""
        self.published = True

    def unpublish(self):
        """Mark the attribute as un-published (set publish flag to false)"""
        self.published = False

    def delete_attribute(self, attribute_id):
        """Delete an attribute, you can search by ID or UUID"""
        found = False
        for a in self.attributes:
            if ((hasattr(a, 'id') and a.id == attribute_id)
                    or (hasattr(a, 'uuid') and a.uuid == attribute_id)):
                a.delete()
                found = True
                break
        if not found:
            raise PyMISPError('No attribute with UUID/ID {} found.'.format(attribute_id))

    def add_attribute(self, type, value, **kwargs):
        """Add an attribute. type and value are required but you can pass all
        other parameters supported by MISPAttribute"""
        attr_list = []
        if isinstance(value, list):
            attr_list = [self.add_attribute(type=type, value=a, **kwargs) for a in value]
        else:
            attribute = MISPAttribute(describe_types=self.describe_types)
            attribute.from_dict(type=type, value=value, **kwargs)
            self.attributes.append(attribute)
        self.edited = True
        if attr_list:
            return attr_list
        return attribute

    def get_object_by_id(self, object_id):
        """Get an object by ID (the ID is the one set by the server when creating the new object)"""
        for obj in self.objects:
            if hasattr(obj, 'id') and int(obj.id) == int(object_id):
                return obj
        raise InvalidMISPObject('Object with {} does not exist in this event'.format(object_id))

    def get_object_by_uuid(self, object_uuid):
        """Get an object by UUID (UUID is set by the server when creating the new object)"""
        for obj in self.objects:
            if hasattr(obj, 'uuid') and obj.uuid == object_uuid:
                return obj
        raise InvalidMISPObject('Object with {} does not exist in this event'.format(object_uuid))

    def get_objects_by_name(self, object_name):
        """Get an object by UUID (UUID is set by the server when creating the new object)"""
        objects = []
        for obj in self.objects:
            if hasattr(obj, 'uuid') and obj.name == object_name:
                objects.append(obj)
        return objects

    def add_object(self, obj=None, **kwargs):
        """Add an object to the Event, either by passing a MISPObject, or a dictionary"""
        if isinstance(obj, MISPObject):
            misp_obj = obj
        elif isinstance(obj, dict):
            misp_obj = MISPObject(name=obj.pop('name'), strict=obj.pop('strict', False),
                                  default_attributes_parameters=obj.pop('default_attributes_parameters', {}),
                                  **obj)
            misp_obj.from_dict(**obj)
        elif kwargs:
            misp_obj = MISPObject(name=kwargs.pop('name'), strict=kwargs.pop('strict', False),
                                  default_attributes_parameters=kwargs.pop('default_attributes_parameters', {}),
                                  **kwargs)
            misp_obj.from_dict(**kwargs)
        else:
            raise InvalidMISPObject("An object to add to an existing Event needs to be either a MISPObject, or a plain python dictionary")
        self.Object.append(misp_obj)
        self.edited = True
        return misp_obj

    def run_expansions(self):
        if sys.version_info < (3, 6):
            raise PyMISPError("No, seriously, ain't gonna work with python <=3.6")
        for index, attribute in enumerate(self.attributes):
            if 'expand' not in attribute:
                continue
            # NOTE: Always make sure the attribute with the expand key is either completely removed,
            # of the key is deleted to avoid seeing it processed again on MISP side
            elif attribute.expand == 'binary':
                try:
                    from .tools import make_binary_objects
                except ImportError as e:
                    logger.info('Unable to load make_binary_objects: {}'.format(e))
                    continue
                file_object, bin_type_object, bin_section_objects = make_binary_objects(pseudofile=attribute.malware_binary, filename=attribute.malware_filename)
                self.add_object(file_object)
                if bin_type_object:
                    self.add_object(bin_type_object)
                if bin_section_objects:
                    for bin_section_object in bin_section_objects:
                        self.add_object(bin_section_object)
                self.attributes.pop(index)
            else:
                logger.warning('No expansions for this data type ({}). Open an issue if needed.'.format(attribute.type))

    def __repr__(self):
        if hasattr(self, 'info'):
            return '<{self.__class__.__name__}(info={self.info})'.format(self=self)
        return '<{self.__class__.__name__}(NotInitialized)'.format(self=self)

    def _serialize(self):  # pragma: no cover
        return '{date}{threat_level_id}{info}{uuid}{analysis}{timestamp}'.format(
            date=self.date, threat_level_id=self.threat_level_id, info=self.info,
            uuid=self.uuid, analysis=self.analysis, timestamp=self.timestamp).encode()

    def _serialize_sigs(self):  # pragma: no cover
        # Not used
        all_sigs = self.sig
        for a in self.attributes:
            all_sigs += a.sig
        return all_sigs.encode()

    def sign(self, gpg_uid, passphrase=None):  # pragma: no cover
        # Not used
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

    def verify(self, gpg_uid):  # pragma: no cover
        # Not used
        if not has_pyme:
            raise PyMISPError('pyme is required, please install: pip install --pre pyme3. You will also need libgpg-error-dev and libgpgme11-dev.')
        to_return = {}
        signed_data = self._serialize()
        with gpg.Context() as c:
            keys = list(c.keylist(gpg_uid))
            try:
                c.verify(signed_data, signature=base64.b64decode(self.sig), verify=keys[:1])
                to_return[self.uuid] = True
            except Exception:
                to_return[self.uuid] = False
        for a in self.attributes:
            to_return.update(a.verify(gpg_uid))
        to_verify_global = self._serialize_sigs()
        with gpg.Context() as c:
            keys = list(c.keylist(gpg_uid))
            try:
                c.verify(to_verify_global, signature=base64.b64decode(self.global_sig), verify=keys[:1])
                to_return['global'] = True
            except Exception:
                to_return['global'] = False
        return to_return

    @deprecated(reason="Use self.known_types instead. Removal date: 2020-01-01.")
    def get_known_types(self):  # pragma: no cover
        return self.known_types

    @deprecated(reason="Use self.from_dict(**kwargs) instead. Removal date: 2020-01-01.")
    def set_all_values(self, **kwargs):  # pragma: no cover
        self.from_dict(**kwargs)

    @deprecated(reason="Use self.to_dict() instead. Removal date: 2020-01-01.")
    def _json(self):  # pragma: no cover
        return self.to_dict()


class MISPObjectReference(AbstractMISP):

    _fields_for_feed = {'uuid', 'timestamp', 'relationship_type', 'comment',
                        'object_uuid', 'referenced_uuid'}

    def __init__(self):
        super(MISPObjectReference, self).__init__()

    def from_dict(self, **kwargs):
        if 'ObjectReference' in kwargs:
            kwargs = kwargs['ObjectReference']
        super(MISPObjectReference, self).from_dict(**kwargs)

    def __repr__(self):
        if hasattr(self, 'referenced_uuid') and hasattr(self, 'object_uuid'):
            return '<{self.__class__.__name__}(object_uuid={self.object_uuid}, referenced_uuid={self.referenced_uuid}, relationship_type={self.relationship_type})'.format(self=self)
        return '<{self.__class__.__name__}(NotInitialized)'.format(self=self)


class MISPObjectTemplate(AbstractMISP):

    def __init__(self):
        super(MISPObjectTemplate, self).__init__()

    def from_dict(self, **kwargs):
        if 'ObjectTemplate' in kwargs:
            kwargs = kwargs['ObjectTemplate']
        super(MISPObjectTemplate, self).from_dict(**kwargs)


class MISPUser(AbstractMISP):

    def __init__(self):
        super(MISPUser, self).__init__()

    def from_dict(self, **kwargs):
        if 'User' in kwargs:
            kwargs = kwargs['User']
        super(MISPUser, self).from_dict(**kwargs)
        if hasattr(self, 'password') and set(self.password) == set(['*']):
            self.password = None

    def __repr__(self):
        if hasattr(self, 'email'):
            return '<{self.__class__.__name__}(email={self.email})'.format(self=self)
        return '<{self.__class__.__name__}(NotInitialized)'.format(self=self)


class MISPOrganisation(AbstractMISP):

    _fields_for_feed = {'name', 'uuid'}

    def __init__(self):
        super(MISPOrganisation, self).__init__()

    def from_dict(self, **kwargs):
        if 'Organisation' in kwargs:
            kwargs = kwargs['Organisation']
        super(MISPOrganisation, self).from_dict(**kwargs)


class MISPFeed(AbstractMISP):

    def __init__(self):
        super(MISPFeed, self).__init__()

    def from_dict(self, **kwargs):
        if 'Feed' in kwargs:
            kwargs = kwargs['Feed']
        super(MISPFeed, self).from_dict(**kwargs)


class MISPWarninglist(AbstractMISP):

    def __init__(self):
        super(MISPWarninglist, self).__init__()

    def from_dict(self, **kwargs):
        if 'Warninglist' in kwargs:
            kwargs = kwargs['Warninglist']
        super(MISPWarninglist, self).from_dict(**kwargs)


class MISPTaxonomy(AbstractMISP):

    def __init__(self):
        super(MISPTaxonomy, self).__init__()

    def from_dict(self, **kwargs):
        if 'Taxonomy' in kwargs:
            kwargs = kwargs['Taxonomy']
        super(MISPTaxonomy, self).from_dict(**kwargs)


class MISPGalaxy(AbstractMISP):

    def __init__(self):
        super(MISPGalaxy, self).__init__()

    def from_dict(self, **kwargs):
        if 'Galaxy' in kwargs:
            kwargs = kwargs['Galaxy']
        super(MISPGalaxy, self).from_dict(**kwargs)


class MISPNoticelist(AbstractMISP):

    def __init__(self):
        super(MISPNoticelist, self).__init__()

    def from_dict(self, **kwargs):
        if 'Noticelist' in kwargs:
            kwargs = kwargs['Noticelist']
        super(MISPNoticelist, self).from_dict(**kwargs)


class MISPRole(AbstractMISP):

    def __init__(self):
        super(MISPRole, self).__init__()

    def from_dict(self, **kwargs):
        if 'Role' in kwargs:
            kwargs = kwargs['Role']
        super(MISPRole, self).from_dict(**kwargs)


class MISPServer(AbstractMISP):

    def __init__(self):
        super(MISPServer, self).__init__()

    def from_dict(self, **kwargs):
        if 'Server' in kwargs:
            kwargs = kwargs['Server']
        super(MISPServer, self).from_dict(**kwargs)


class MISPSharingGroup(AbstractMISP):

    def __init__(self):
        super(MISPSharingGroup, self).__init__()

    def from_dict(self, **kwargs):
        if 'SharingGroup' in kwargs:
            kwargs = kwargs['SharingGroup']
        super(MISPSharingGroup, self).from_dict(**kwargs)


class MISPLog(AbstractMISP):

    def __init__(self):
        super(MISPLog, self).__init__()

    def from_dict(self, **kwargs):
        if 'Log' in kwargs:
            kwargs = kwargs['Log']
        super(MISPLog, self).from_dict(**kwargs)

    def __repr__(self):
        return '<{self.__class__.__name__}({self.model}, {self.action}, {self.title})'.format(self=self)


class MISPEventDelegation(AbstractMISP):

    def __init__(self):
        super(MISPEventDelegation, self).__init__()

    def from_dict(self, **kwargs):
        if 'EventDelegation' in kwargs:
            kwargs = kwargs['EventDelegation']
        super(MISPEventDelegation, self).from_dict(**kwargs)

    def __repr__(self):
        return '<{self.__class__.__name__}(org_id={self.org_id}, requester_org_id={self.requester_org_id}, {self.event_id})'.format(self=self)


class MISPSighting(AbstractMISP):

    def __init__(self):
        super(MISPSighting, self).__init__()

    def from_dict(self, **kwargs):
        """Initialize the MISPSighting from a dictionary
        :value: Value of the attribute the sighting is related too. Pushing this object
                will update the sighting count of each attriutes with thifs value on the instance
        :uuid: UUID of the attribute to update
        :id: ID of the attriute to update
        :source: Source of the sighting
        :type: Type of the sighting
        :timestamp: Timestamp associated to the sighting
        """
        if 'Sighting' in kwargs:
            kwargs = kwargs['Sighting']
        super(MISPSighting, self).from_dict(**kwargs)

    def __repr__(self):
        if hasattr(self, 'value'):
            return '<{self.__class__.__name__}(value={self.value})'.format(self=self)
        if hasattr(self, 'id'):
            return '<{self.__class__.__name__}(id={self.id})'.format(self=self)
        if hasattr(self, 'uuid'):
            return '<{self.__class__.__name__}(uuid={self.uuid})'.format(self=self)
        return '<{self.__class__.__name__}(NotInitialized)'.format(self=self)


class MISPObjectAttribute(MISPAttribute):

    def __init__(self, definition):
        super(MISPObjectAttribute, self).__init__()
        self._definition = definition

    def from_dict(self, object_relation, value, **kwargs):
        self.object_relation = object_relation
        self.value = value
        if 'Attribute' in kwargs:
            kwargs = kwargs['Attribute']
        # Initialize the new MISPAttribute
        # Get the misp attribute type from the definition
        self.type = kwargs.pop('type', None)
        if self.type is None:
            self.type = self._definition.get('misp-attribute')
        if 'category' not in kwargs and 'categories' in self._definition:
            # Get first category in the list from the object template as default
            self.category = self._definition['categories'][0]
        self.disable_correlation = kwargs.pop('disable_correlation', None)
        if self.disable_correlation is None:
            # The correlation can be disabled by default in the object definition.
            # Use this value if it isn't overloaded by the object
            self.disable_correlation = self._definition.get('disable_correlation')
        self.to_ids = kwargs.pop('to_ids', None)
        if self.to_ids is None:
            # Same for the to_ids flag
            self.to_ids = self._definition.get('to_ids')
        if not self.type:
            raise NewAttributeError("The type of the attribute is required. Is the object template missing?")
        super(MISPObjectAttribute, self).from_dict(**dict(self, **kwargs))
        # FIXME New syntax python3 only, keep for later.
        # super(MISPObjectAttribute, self).from_dict(**{**self, **kwargs})

    def __repr__(self):
        if hasattr(self, 'value'):
            return '<{self.__class__.__name__}(object_relation={self.object_relation}, value={self.value})'.format(self=self)
        return '<{self.__class__.__name__}(NotInitialized)'.format(self=self)


class MISPShadowAttribute(AbstractMISP):

    def __init__(self):
        super(MISPShadowAttribute, self).__init__()

    def from_dict(self, **kwargs):
        if 'ShadowAttribute' in kwargs:
            kwargs = kwargs['ShadowAttribute']
        super(MISPShadowAttribute, self).from_dict(**kwargs)

    def __repr__(self):
        if hasattr(self, 'value'):
            return '<{self.__class__.__name__}(type={self.type}, value={self.value})'.format(self=self)
        return '<{self.__class__.__name__}(NotInitialized)'.format(self=self)


class MISPCommunity(AbstractMISP):

    def __init__(self):
        super(MISPCommunity, self).__init__()

    def from_dict(self, **kwargs):
        if 'Community' in kwargs:
            kwargs = kwargs['Community']
        super(MISPCommunity, self).from_dict(**kwargs)

    def __repr__(self):
        return '<{self.__class__.__name__}(name={self.name}, uuid={self.uuid})'.format(self=self)


class MISPUserSetting(AbstractMISP):

    def __init__(self):
        super(MISPUserSetting, self).__init__()

    def from_dict(self, **kwargs):
        if 'UserSetting' in kwargs:
            kwargs = kwargs['UserSetting']
        super(MISPUserSetting, self).from_dict(**kwargs)

    def __repr__(self):
        return '<{self.__class__.__name__}(name={self.setting}'.format(self=self)


class MISPObject(AbstractMISP):

    _fields_for_feed = {'name', 'meta-category', 'description', 'template_uuid',
                        'template_version', 'uuid', 'timestamp', 'distribution',
                        'sharing_group_id', 'comment'}

    def __init__(self, name, strict=False, standalone=False, default_attributes_parameters={}, **kwargs):
        ''' Master class representing a generic MISP object
        :name: Name of the object

        :strict: Enforce validation with the object templates

        :standalone: The object will be pushed as directly on MISP, not as a part of an event.
            In this case the ObjectReference needs to be pushed manually and cannot be in the JSON dump.

        :default_attributes_parameters: Used as template for the attributes if they are not overwritten in add_attribute

        :misp_objects_path_custom: Path to custom object templates
        '''
        super(MISPObject, self).__init__(**kwargs)
        self._strict = strict
        self.name = name
        self._known_template = False

        self._set_template(kwargs.get('misp_objects_path_custom'))

        self.uuid = str(uuid.uuid4())
        self.__fast_attribute_access = defaultdict(list)  # Hashtable object_relation: [attributes]
        self.ObjectReference = []
        self.Attribute = []
        if isinstance(default_attributes_parameters, MISPAttribute):
            # Just make sure we're not modifying an existing MISPAttribute
            self._default_attributes_parameters = default_attributes_parameters.to_dict()
        else:
            self._default_attributes_parameters = default_attributes_parameters
        if self._default_attributes_parameters:
            # Let's clean that up
            self._default_attributes_parameters.pop('value', None)  # duh
            self._default_attributes_parameters.pop('uuid', None)  # duh
            self._default_attributes_parameters.pop('id', None)  # duh
            self._default_attributes_parameters.pop('object_id', None)  # duh
            self._default_attributes_parameters.pop('type', None)  # depends on the value
            self._default_attributes_parameters.pop('object_relation', None)  # depends on the value
            self._default_attributes_parameters.pop('disable_correlation', None)  # depends on the value
            self._default_attributes_parameters.pop('to_ids', None)  # depends on the value
            self._default_attributes_parameters.pop('deleted', None)  # doesn't make sense to pre-set it
            self._default_attributes_parameters.pop('data', None)  # in case the original in a sample or an attachment

            # Those values are set for the current object, if they exist, but not pop'd because they are still useful for the attributes
            self.distribution = self._default_attributes_parameters.get('distribution', 5)
            self.sharing_group_id = self._default_attributes_parameters.get('sharing_group_id', 0)
        else:
            self.distribution = 5  # Default to inherit
            self.sharing_group_id = 0
        self._standalone = standalone
        if self._standalone:
            # Mark as non_jsonable because we need to add the references manually after the object(s) have been created
            self.update_not_jsonable('ObjectReference')

    def _load_template_path(self, template_path):
        self._definition = self._load_json(template_path)
        if not self._definition:
            return False
        setattr(self, 'meta-category', self._definition['meta-category'])
        self.template_uuid = self._definition['uuid']
        self.description = self._definition['description']
        self.template_version = self._definition['version']
        return True

    def _to_feed(self):
        to_return = super(MISPObject, self)._to_feed()
        if self.references:
            to_return['ObjectReference'] = [reference._to_feed() for reference in self.references]
        return to_return

    def force_misp_objects_path_custom(self, misp_objects_path_custom, object_name=None):
        if object_name:
            self.name = object_name
        self._set_template(misp_objects_path_custom)

    def _set_template(self, misp_objects_path_custom=None):
        if misp_objects_path_custom:
            # If misp_objects_path_custom is given, and an object with the given name exists, use that.
            self.misp_objects_path = misp_objects_path_custom

        # Try to get the template
        if sys.version_info >= (3, 4):
            self._known_template = self._load_template_path(self.misp_objects_path / self.name / 'definition.json')
        else:
            self._known_template = self._load_template_path(os.path.join(self.misp_objects_path, self.name, 'definition.json'))

        if not self._known_template and self._strict:
            raise UnknownMISPObjectTemplate('{} is unknown in the MISP object directory.'.format(self.name))
        else:
            # Then we have no meta-category, template_uuid, description and template_version
            pass

    @property
    def disable_validation(self):
        self._strict = False

    @property
    def attributes(self):
        return self.Attribute

    @attributes.setter
    def attributes(self, attributes):
        if all(isinstance(x, MISPObjectAttribute) for x in attributes):
            self.Attribute = attributes
            self.__fast_attribute_access = defaultdict(list)
        else:
            raise PyMISPError('All the attributes have to be of type MISPObjectAttribute.')

    @property
    def references(self):
        return self.ObjectReference

    @references.setter
    def references(self, references):
        if all(isinstance(x, MISPObjectReference) for x in references):
            self.ObjectReference = references
        else:
            raise PyMISPError('All the attributes have to be of type MISPObjectReference.')

    def from_dict(self, **kwargs):
        if 'Object' in kwargs:
            kwargs = kwargs['Object']
        if self._known_template:
            if kwargs.get('template_uuid') and kwargs['template_uuid'] != self.template_uuid:
                if self._strict:
                    raise UnknownMISPObjectTemplate('UUID of the object is different from the one of the template.')
                else:
                    self._known_template = False
            if kwargs.get('template_version') and int(kwargs['template_version']) != self.template_version:
                if self._strict:
                    raise UnknownMISPObjectTemplate('Version of the object ({}) is different from the one of the template ({}).'.format(kwargs['template_version'], self.template_version))
                else:
                    self._known_template = False

        if 'distribution' in kwargs and kwargs['distribution'] is not None:
            self.distribution = kwargs.pop('distribution')
            self.distribution = int(self.distribution)
            if self.distribution not in [0, 1, 2, 3, 4, 5]:
                raise NewAttributeError('{} is invalid, the distribution has to be in 0, 1, 2, 3, 4, 5'.format(self.distribution))

        if kwargs.get('timestamp'):
            ts = kwargs.pop('timestamp')
            if isinstance(ts, datetime.datetime):
                self.timestamp = ts
            elif sys.version_info >= (3, 3):
                self.timestamp = datetime.datetime.fromtimestamp(int(ts), datetime.timezone.utc)
            else:
                self.timestamp = datetime.datetime.fromtimestamp(int(ts), UTC())
        if kwargs.get('Attribute'):
            [self.add_attribute(**a) for a in kwargs.pop('Attribute')]
        if kwargs.get('ObjectReference'):
            [self.add_reference(**r) for r in kwargs.pop('ObjectReference')]

        # Not supported yet - https://github.com/MISP/PyMISP/issues/168
        # if kwargs.get('Tag'):
        #    for tag in kwargs.pop('Tag'):
        #        self.add_tag(tag)

        super(MISPObject, self).from_dict(**kwargs)

    def add_reference(self, referenced_uuid, relationship_type, comment=None, **kwargs):
        """Add a link (uuid) to an other object"""
        if isinstance(referenced_uuid, AbstractMISP):
            # Allow to pass an object or an attribute instead of its UUID
            referenced_uuid = referenced_uuid.uuid
        if kwargs.get('object_uuid'):
            # Load existing object
            object_uuid = kwargs.pop('object_uuid')
        else:
            # New reference
            object_uuid = self.uuid
        reference = MISPObjectReference()
        reference.from_dict(object_uuid=object_uuid, referenced_uuid=referenced_uuid,
                            relationship_type=relationship_type, comment=comment, **kwargs)
        self.ObjectReference.append(reference)
        self.edited = True

    def get_attributes_by_relation(self, object_relation):
        '''Returns the list of attributes with the given object relation in the object'''
        return self._fast_attribute_access.get(object_relation, [])

    @property
    def _fast_attribute_access(self):
        if not self.__fast_attribute_access:
            for a in self.attributes:
                self.__fast_attribute_access[a.object_relation].append(a)
        return self.__fast_attribute_access

    def has_attributes_by_relation(self, list_of_relations):
        '''True if all the relations in the list are defined in the object'''
        return all(relation in self._fast_attribute_access for relation in list_of_relations)

    def add_attribute(self, object_relation, simple_value=None, **value):
        """Add an attribute. object_relation is required and the value key is a
        dictionary with all the keys supported by MISPAttribute"""
        if simple_value is not None:  # /!\ The value *can* be 0
            value = {'value': simple_value}
        if value.get('value') in [None, '']:
            logger.warning("The value of the attribute you're trying to add is None or empty string, skipping it. Object relation: {}".format(object_relation))
            return None
        if self._known_template:
            if object_relation in self._definition['attributes']:
                attribute = MISPObjectAttribute(self._definition['attributes'][object_relation])
            else:
                # Woopsie, this object_relation is unknown, no sane defaults for you.
                logger.warning("The template ({}) doesn't have the object_relation ({}) you're trying to add.".format(self.name, object_relation))
                attribute = MISPObjectAttribute({})
        else:
            attribute = MISPObjectAttribute({})
        # Overwrite the parameters of self._default_attributes_parameters with the ones of value
        attribute.from_dict(object_relation=object_relation, **dict(self._default_attributes_parameters, **value))
        # FIXME New syntax python3 only, keep for later.
        # attribute.from_dict(object_relation=object_relation, **{**self._default_attributes_parameters, **value})
        self.__fast_attribute_access[object_relation].append(attribute)
        self.Attribute.append(attribute)
        self.edited = True
        return attribute

    def add_attributes(self, object_relation, *attributes):
        '''Add multiple attributes with the same object_relation.
        Helper for object_relation when multiple is True in the template.
        It is the same as calling multiple times add_attribute with the same object_relation.
        '''
        to_return = []
        for attribute in attributes:
            if isinstance(attribute, dict):
                a = self.add_attribute(object_relation, **attribute)
            else:
                a = self.add_attribute(object_relation, value=attribute)
            to_return.append(a)
        return to_return

    def to_dict(self, strict=False):
        if strict or self._strict and self._known_template:
            self._validate()
        return super(MISPObject, self).to_dict()

    def to_json(self, strict=False, sort_keys=False, indent=None):
        if strict or self._strict and self._known_template:
            self._validate()
        return super(MISPObject, self).to_json(sort_keys=sort_keys, indent=indent)

    def _validate(self):
        """Make sure the object we're creating has the required fields"""
        if self._definition.get('required'):
            required_missing = set(self._definition.get('required')) - set(self._fast_attribute_access.keys())
            if required_missing:
                raise InvalidMISPObject('{} are required.'.format(required_missing))
        if self._definition.get('requiredOneOf'):
            if not set(self._definition['requiredOneOf']) & set(self._fast_attribute_access.keys()):
                # We ecpect at least one of the object_relation in requiredOneOf, and it isn't the case
                raise InvalidMISPObject('At least one of the following attributes is required: {}'.format(', '.join(self._definition['requiredOneOf'])))
        for rel, attrs in self._fast_attribute_access.items():
            if len(attrs) == 1:
                # object_relation's here only once, everything's cool, moving on
                continue
            if not self._definition['attributes'][rel].get('multiple'):
                # object_relation's here more than once, but it isn't allowed in the template.
                raise InvalidMISPObject('Multiple occurrences of {} is not allowed'.format(rel))
        return True

    def __repr__(self):
        if hasattr(self, 'name'):
            return '<{self.__class__.__name__}(name={self.name})'.format(self=self)
        return '<{self.__class__.__name__}(NotInitialized)'.format(self=self)
