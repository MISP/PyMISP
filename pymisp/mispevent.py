
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

from . import deprecated
from .abstract import AbstractMISP
from .exceptions import UnknownMISPObjectTemplate, InvalidMISPObject, PyMISPError, NewEventError, NewAttributeError

import six  # Remove that import when discarding python2 support.

import logging
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


if (3, 0) <= sys.version_info < (3, 6):
    OLD_PY3 = True
else:
    OLD_PY3 = False


try:
    from dateutil.parser import parse
except ImportError:
    logger.exception("Cannot import dateutil")
    pass

try:
    import jsonschema
except ImportError:
    logger.exception("Cannot import jsonschema")
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


class MISPAttribute(AbstractMISP):

    def __init__(self, describe_types=None, strict=False):
        """Represents an Attribute
            :describe_type: Use it is you want to overwrite the defualt describeTypes.json file (you don't)
            :strict: If false, fallback to sane defaults for the attribute type if the ones passed by the user are incorrect
        """
        super(MISPAttribute, self).__init__()
        if not describe_types:
            ressources_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'data')
            with open(os.path.join(ressources_path, 'describeTypes.json'), 'rb') as f:
                if OLD_PY3:
                    t = json.loads(f.read().decode())
                else:
                    t = json.load(f)
            describe_types = t['result']
        self.__categories = describe_types['categories']
        self._types = describe_types['types']
        self.__category_type_mapping = describe_types['category_type_mappings']
        self.__sane_default = describe_types['sane_defaults']
        self.__strict = strict
        self.uuid = str(uuid.uuid4())
        self.ShadowAttribute = []

    @property
    def known_types(self):
        """Returns a list of all the known MISP attributes types"""
        return self._types

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

    def delete(self):
        """Mark the attribute as deleted (soft delete)"""
        self.deleted = True

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

    def from_dict(self, **kwargs):
        if kwargs.get('Attribute'):
            kwargs = kwargs.get('Attribute')
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
            raise NewAttributeError('{} is invalid, type has to be in {}'.format(self.type, (', '.join(self._types))))

        type_defaults = self.__sane_default[self.type]

        self.value = kwargs.pop('value', None)
        if self.value is None:
            raise NewAttributeError('The value of the attribute is required.')

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
            self._load_data()
        if kwargs.get('id'):
            self.id = int(kwargs.pop('id'))
        if kwargs.get('event_id'):
            self.event_id = int(kwargs.pop('event_id'))
        if kwargs.get('timestamp'):
            if sys.version_info >= (3, 3):
                self.timestamp = datetime.datetime.fromtimestamp(int(kwargs.pop('timestamp')), datetime.timezone.utc)
            else:
                self.timestamp = datetime.datetime.fromtimestamp(int(kwargs.pop('timestamp')), UTC())
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
            for tag in kwargs.pop('Tag'):
                self.add_tag(tag)
        if kwargs.get('ShadowAttribute'):
            for s_attr in kwargs.pop('ShadowAttribute'):
                self.add_shadow_attribute(s_attr)

        # If the user wants to disable correlation, let them. Defaults to False.
        self.disable_correlation = kwargs.pop("disable_correlation", False)
        if self.disable_correlation is None:
            self.disable_correlation = False

        super(MISPAttribute, self).from_dict(**kwargs)

    def to_dict(self):
        to_return = super(MISPAttribute, self).to_dict()
        if to_return.get('data'):
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

    def _load_data(self):
        if not isinstance(self.data, BytesIO):
            self.data = BytesIO(base64.b64decode(self.data))
        if self.type == 'malware-sample':
            try:
                with ZipFile(self.data) as f:
                    if not self.__is_misp_encrypted_file(f):
                        raise Exception('Not an existing malware sample')
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

    @deprecated
    def get_known_types(self):  # pragma: no cover
        return self.known_types

    @deprecated
    def get_malware_binary(self):  # pragma: no cover
        return self.malware_binary

    @deprecated
    def _json(self):  # pragma: no cover
        return self.to_dict()

    @deprecated
    def _json_full(self):  # pragma: no cover
        return self.to_dict()

    @deprecated
    def set_all_values(self, **kwargs):  # pragma: no cover
        self.from_dict(**kwargs)


class MISPEvent(AbstractMISP):

    def __init__(self, describe_types=None, strict_validation=False, **kwargs):
        super(MISPEvent, self).__init__(**kwargs)
        ressources_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'data')
        if strict_validation:
            with open(os.path.join(ressources_path, 'schema.json'), 'rb') as f:
                if OLD_PY3:
                    self.__json_schema = json.loads(f.read().decode())
                else:
                    self.__json_schema = json.load(f)
        else:
            with open(os.path.join(ressources_path, 'schema-lax.json'), 'rb') as f:
                if OLD_PY3:
                    self.__json_schema = json.loads(f.read().decode())
                else:
                    self.__json_schema = json.load(f)
        if not describe_types:
            with open(os.path.join(ressources_path, 'describeTypes.json'), 'rb') as f:
                if OLD_PY3:
                    t = json.loads(f.read().decode())
                else:
                    t = json.load(f)
            describe_types = t['result']

        self._types = describe_types['types']
        self.Attribute = []
        self.Object = []
        self.RelatedEvent = []
        self.ShadowAttribute = []

    @property
    def known_types(self):
        return self._types

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
        # Invalid event created by MISP up to 2.4.52 (attribute_count is none instead of '0')
        if (event.get('Event') and
                'attribute_count' in event.get('Event') and
                event.get('Event').get('attribute_count') is None):
            event['Event']['attribute_count'] = '0'
        self.from_dict(**event['Event'])
        if validate:
            jsonschema.validate(json.loads(self.to_json()), self.__json_schema)

    def set_date(self, date, ignore_invalid=False):
        """Set a date for the event (string, datetime, or date object)"""
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

    def from_dict(self, **kwargs):
        # Required value
        self.info = kwargs.pop('info', None)
        if self.info is None:
            raise NewAttributeError('The info field of the new event is required.')

        # Default values for a valid event to send to a MISP instance
        self.distribution = kwargs.pop('distribution', None)
        if self.distribution is not None:
            self.distribution = int(self.distribution)
            if self.distribution not in [0, 1, 2, 3, 4]:
                raise NewAttributeError('{} is invalid, the distribution has to be in 0, 1, 2, 3, 4'.format(self.distribution))

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
            for a in kwargs.pop('Attribute'):
                self.add_attribute(**a)

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
                self.RelatedEvent.append(sub_event)
        if kwargs.get('Tag'):
            for tag in kwargs.pop('Tag'):
                self.add_tag(tag)
        if kwargs.get('Object'):
            for obj in kwargs.pop('Object'):
                self.add_object(obj)
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

        return {'Event': _int_to_str(to_return)}

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
        '''Return the tags associated to an attribute or an object attribute.
           :attribute_identifier: can be an ID, UUID, or the value.
        '''
        tags = []
        for a in self.attributes + [attribute for o in self.objects for attribute in o.attributes]:
            if ((hasattr(a, 'id') and a.id == attribute_identifier) or
                (hasattr(a, 'uuid') and a.uuid == attribute_identifier) or
                (hasattr(a, 'value') and attribute_identifier == a.value or
                 attribute_identifier in a.value.split('|'))):
                tags += a.tags
        return tags

    def add_attribute_tag(self, tag, attribute_identifier):
        '''Add a tag to an existing attribute, raise an Exception if the attribute doesn't exists.
            :tag: Tag name as a string, MISPTag instance, or dictionary
            :attribute_identifier: can be an ID, UUID, or the value.
        '''
        attributes = []
        for a in self.attributes + [attribute for o in self.objects for attribute in o.attributes]:
            if ((hasattr(a, 'id') and a.id == attribute_identifier) or
                (hasattr(a, 'uuid') and a.uuid == attribute_identifier) or
                (hasattr(a, 'value') and attribute_identifier == a.value or
                 attribute_identifier in a.value.split('|'))):
                a.add_tag(tag)
                attributes.append(a)

        if not attributes:
            raise Exception('No attribute with identifier {} found.'.format(attribute_identifier))
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
            if ((hasattr(a, 'id') and a.id == attribute_id) or
                    (hasattr(a, 'uuid') and a.uuid == attribute_id)):
                a.delete()
                found = True
                break
        if not found:
            raise Exception('No attribute with UUID/ID {} found.'.format(attribute_id))

    def add_attribute(self, type, value, **kwargs):
        """Add an attribute. type and value are required but you can pass all
        other parameters supported by MISPAttribute"""
        attr_list = []
        if isinstance(value, list):
            attr_list = [self.add_attribute(type=type, value=a, **kwargs) for a in value]
        else:
            attribute = MISPAttribute()
            attribute.from_dict(type=type, value=value, **kwargs)
            self.attributes.append(attribute)
        self.edited = True
        if attr_list:
            return attr_list
        else:
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

    def __repr__(self):
        if hasattr(self, 'info'):
            return '<{self.__class__.__name__}(info={self.info})'.format(self=self)
        return '<{self.__class__.__name__}(NotInitialized)'.format(self=self)

    def _serialize(self):
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

    @deprecated
    def get_known_types(self):  # pragma: no cover
        return self.known_types

    @deprecated
    def set_all_values(self, **kwargs):  # pragma: no cover
        self.from_dict(**kwargs)

    @deprecated
    def _json(self):  # pragma: no cover
        return self.to_dict()


class MISPObjectReference(AbstractMISP):

    def __init__(self):
        super(MISPObjectReference, self).__init__()

    def from_dict(self, object_uuid, referenced_uuid, relationship_type, comment=None, **kwargs):
        self.object_uuid = object_uuid
        self.referenced_uuid = referenced_uuid
        self.relationship_type = relationship_type
        self.comment = comment
        super(MISPObjectReference, self).from_dict(**kwargs)

    def __repr__(self):
        if hasattr(self, 'referenced_uuid'):
            return '<{self.__class__.__name__}(object_uuid={self.object_uuid}, referenced_uuid={self.referenced_uuid}, relationship_type={self.relationship_type})'.format(self=self)
        return '<{self.__class__.__name__}(NotInitialized)'.format(self=self)


class MISPUser(AbstractMISP):

    def __init__(self):
        super(MISPUser, self).__init__()

    def from_dict(self, **kwargs):
        if kwargs.get('User'):
            kwargs = kwargs.get('User')
        super(MISPUser, self).from_dict(**kwargs)


class MISPOrganisation(AbstractMISP):

    def __init__(self):
        super(MISPOrganisation, self).__init__()

    def from_dict(self, **kwargs):
        if kwargs.get('Organisation'):
            kwargs = kwargs.get('Organisation')
        super(MISPOrganisation, self).from_dict(**kwargs)


class MISPFeed(AbstractMISP):

    def __init__(self):
        super(MISPFeed, self).__init__()


class MISPLog(AbstractMISP):

    def __init__(self):
        super(MISPLog, self).__init__()

    def __repr__(self):
        return '<{self.__class__.__name__}({self.model}, {self.action}, {self.title})'.format(self=self)


class MISPSighting(AbstractMISP):

    def __init__(self):
        super(MISPSighting, self).__init__()

    def from_dict(self, value=None, uuid=None, id=None, source=None, type=None, timestamp=None, **kwargs):
        """Initialize the MISPSighting from a dictionary
        :value: Value of the attribute the sighting is related too. Pushing this object
                will update the sighting count of each attriutes with thifs value on the instance
        :uuid: UUID of the attribute to update
        :id: ID of the attriute to update
        :source: Source of the sighting
        :type: Type of the sighting
        :timestamp: Timestamp associated to the sighting
        """
        self.value = value
        self.uuid = uuid
        self.id = id
        self.source = source
        self.type = type
        self.timestamp = timestamp
        super(MISPSighting, self).from_dict(**kwargs)

    def __repr__(self):
        if hasattr(self, 'value'):
            return '<{self.__class__.__name__}(value={self.value})'.format(self=self)
        if hasattr(self, 'id'):
            return '<{self.__class__.__name__}(value={self.id})'.format(self=self)
        if hasattr(self, 'uuid'):
            return '<{self.__class__.__name__}(value={self.uuid})'.format(self=self)
        return '<{self.__class__.__name__}(NotInitialized)'.format(self=self)


class MISPObjectAttribute(MISPAttribute):

    def __init__(self, definition):
        super(MISPObjectAttribute, self).__init__()
        self._definition = definition

    def from_dict(self, object_relation, value, **kwargs):
        self.object_relation = object_relation
        self.value = value
        # Initialize the new MISPAttribute
        # Get the misp attribute type from the definition
        self.type = kwargs.pop('type', None)
        if self.type is None:
            self.type = self._definition.get('misp-attribute')
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

    def __repr__(self):
        if hasattr(self, 'value'):
            return '<{self.__class__.__name__}(object_relation={self.object_relation}, value={self.value})'.format(self=self)
        return '<{self.__class__.__name__}(NotInitialized)'.format(self=self)


class MISPShadowAttribute(MISPAttribute):

    def __init__(self):
        super(MISPShadowAttribute, self).__init__()


class MISPObject(AbstractMISP):

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
        misp_objects_path = os.path.join(
            os.path.abspath(os.path.dirname(sys.modules['pymisp'].__file__)),
            'data', 'misp-objects', 'objects')
        misp_objects_path_custom = kwargs.get('misp_objects_path_custom')
        if misp_objects_path_custom and os.path.exists(os.path.join(misp_objects_path_custom, self.name, 'definition.json')):
            # Use the local object path by default if provided (allows to overwrite a default template)
            template_path = os.path.join(misp_objects_path_custom, self.name, 'definition.json')
            self._known_template = True
        elif os.path.exists(os.path.join(misp_objects_path, self.name, 'definition.json')):
            template_path = os.path.join(misp_objects_path, self.name, 'definition.json')
            self._known_template = True
        else:
            if self._strict:
                raise UnknownMISPObjectTemplate('{} is unknown in the MISP object directory.'.format(self.name))
            else:
                self._known_template = False
        if self._known_template:
            with open(template_path, 'rb') as f:
                if OLD_PY3:
                    self._definition = json.loads(f.read().decode())
                else:
                    self._definition = json.load(f)
            setattr(self, 'meta-category', self._definition['meta-category'])
            self.template_uuid = self._definition['uuid']
            self.description = self._definition['description']
            self.template_version = self._definition['version']
        else:
            # Then we have no meta-category, template_uuid, description and template_version
            pass
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
            if sys.version_info >= (3, 3):
                self.timestamp = datetime.datetime.fromtimestamp(int(kwargs.pop('timestamp')), datetime.timezone.utc)
            else:
                self.timestamp = datetime.datetime.fromtimestamp(int(kwargs.pop('timestamp')), UTC())
        if kwargs.get('Attribute'):
            for a in kwargs.pop('Attribute'):
                self.add_attribute(**a)
        if kwargs.get('ObjectReference'):
            for r in kwargs.pop('ObjectReference'):
                self.add_reference(**r)

        # Not supported yet - https://github.com/MISP/PyMISP/issues/168
        # if kwargs.get('Tag'):
        #    for tag in kwargs.pop('Tag'):
        #        self.add_tag(tag)

        super(MISPObject, self).from_dict(**kwargs)

    def add_reference(self, referenced_uuid, relationship_type, comment=None, **kwargs):
        """Add a link (uuid) to an other object"""
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

    def add_attribute(self, object_relation, **value):
        """Add an attribute. object_relation is required and the value key is a
        dictionary with all the keys supported by MISPAttribute"""
        if value.get('value') is None:
            return None
        if self._known_template:
            if self._definition['attributes'].get(object_relation):
                attribute = MISPObjectAttribute(self._definition['attributes'][object_relation])
            else:
                # Woopsie, this object_relation is unknown, no sane defaults for you.
                logger.warning("The template ({}) doesn't have the object_relation ({}) you're trying to add.".format(self.name, object_relation))
                attribute = MISPObjectAttribute({})
        else:
            attribute = MISPObjectAttribute({})
        # Overwrite the parameters of self._default_attributes_parameters with the ones of value
        attribute.from_dict(object_relation=object_relation, **dict(self._default_attributes_parameters, **value))
        self.__fast_attribute_access[object_relation].append(attribute)
        self.Attribute.append(attribute)
        self.edited = True
        return attribute

    def to_dict(self, strict=False):
        if strict or self._strict and self._known_template:
            self._validate()
        return super(MISPObject, self).to_dict()

    def to_json(self, strict=False):
        if strict or self._strict and self._known_template:
            self._validate()
        return super(MISPObject, self).to_json()

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
