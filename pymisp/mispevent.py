
# -*- coding: utf-8 -*-

import datetime
import time
import json
import os
import base64
from io import BytesIO
from zipfile import ZipFile
import hashlib
import sys
import uuid
from collections import Counter

from .abstract import AbstractMISP
from .exceptions import UnknownMISPObjectTemplate, InvalidMISPObject, PyMISPError, NewEventError, NewAttributeError

import six  # Remove that import when discarding python2 support.

import logging
logger = logging.getLogger('pymisp')


if six.PY2:
    logger.warning("You're using python 2, it is strongly recommended to use python >=3.5")

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

    def __init__(self, describe_types=None):
        if not describe_types:
            ressources_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'data')
            with open(os.path.join(ressources_path, 'describeTypes.json'), 'r') as f:
                t = json.load(f)
            describe_types = t['result']
        self.__categories = describe_types['categories']
        self._types = describe_types['types']
        self.__category_type_mapping = describe_types['category_type_mappings']
        self.__sane_default = describe_types['sane_defaults']
        self.Tag = []

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
        self.event_id = None
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

    def get_known_types(self):
        return self._types

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
            except Exception:
                return {self.uuid: False}

    def set_all_values(self, **kwargs):
        # to be deprecated
        self.from_dict(**kwargs)

    def from_dict(self, **kwargs):
        if kwargs.get('type') and kwargs.get('category'):
            if kwargs['type'] not in self.__category_type_mapping[kwargs['category']]:
                raise NewAttributeError('{} and {} is an invalid combination, type for this category has to be in {}'.format(
                    kwargs.get('type'), kwargs.get('category'), (', '.join(self.__category_type_mapping[kwargs['category']]))))
        # Required
        self.type = kwargs.pop('type', None)
        if self.type is None:
            raise NewAttributeError('The type of the attribute is required.')
        if self.type not in self.get_known_types():
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
            self.timestamp = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=int(kwargs.pop('timestamp')))
        if kwargs.get('sharing_group_id'):
            self.sharing_group_id = int(kwargs.pop('sharing_group_id'))
        if kwargs.get('Tag'):
            self.Tag = [t for t in kwargs.pop('Tag', []) if t]

        # If the user wants to disable correlation, let them. Defaults to False.
        self.disable_correlation = kwargs.pop("disable_correlation", False)
        if self.disable_correlation is None:
            self.disable_correlation = False

        for k, v in kwargs.items():
            setattr(self, k, v)

    def _prepare_new_malware_sample(self):
        if '|' in self.value:
            # Get the filename, ignore the md5, because humans.
            self.malware_filename, md5 = self.value.split('|')
        else:
            # Assuming the user only passed the filename
            self.malware_filename = self.value
        m = hashlib.md5()
        m.update(self.data.getvalue())
        self.value = self.malware_filename
        md5 = m.hexdigest()
        self.value = '{}|{}'.format(self.malware_filename, md5)
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

    def get_malware_binary(self):
        if hasattr(self, '_malware_binary'):
            return self._malware_binary
        return None

    def _json(self):
        # DEPRECATED
        return self.to_dict()

    def _json_full(self):
        # DEPRECATED
        return self.to_dict()

    def to_dict(self, with_timestamp=False):
        to_return = {}
        for attribute in self.properties():
            val = getattr(self, attribute, None)
            if val in [None, []]:
                continue

            if attribute == 'data':
                to_return['data'] = base64.b64encode(self.data.getvalue()).decode()
            elif attribute == 'timestamp':
                if with_timestamp:
                    to_return['timestamp'] = int(time.mktime(self.timestamp.timetuple()))
            else:
                to_return[attribute] = val
        to_return = _int_to_str(to_return)
        return to_return


class MISPEvent(AbstractMISP):

    def __init__(self, describe_types=None, strict_validation=False):
        ressources_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'data')
        if strict_validation:
            with open(os.path.join(ressources_path, 'schema.json'), 'r') as f:
                self.__json_schema = json.load(f)
        else:
            with open(os.path.join(ressources_path, 'schema-lax.json'), 'r') as f:
                self.__json_schema = json.load(f)
        if not describe_types:
            with open(os.path.join(ressources_path, 'describeTypes.json'), 'r') as f:
                t = json.load(f)
            describe_types = t['result']

        self._types = describe_types['types']
        self.attributes = []
        self.Tag = []

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
        self.Object = None

    def get_known_types(self):
        return self._types

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

    def load_file(self, event_path):
        if not os.path.exists(event_path):
            raise PyMISPError('Invalid path, unable to load the event.')
        with open(event_path, 'r') as f:
            self.load(f)

    def load(self, json_event):
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
        jsonschema.validate(event, self.__json_schema)
        e = event.get('Event')
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
        # to be deprecated
        self.from_dict(**kwargs)

    def from_dict(self, **kwargs):
        # Required value
        self.info = kwargs.pop('info', None)
        if not self.info:
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
                attribute = MISPAttribute()
                attribute.set_all_values(**a)
                if not hasattr(self, 'attributes'):
                    self.attributes = []
                self.attributes.append(attribute)

        # All other keys
        if kwargs.get('id'):
            self.id = int(kwargs.pop('id'))
        if kwargs.get('orgc_id'):
            self.orgc_id = int(kwargs.pop('orgc_id'))
        if kwargs.get('org_id'):
            self.org_id = int(kwargs.pop('org_id'))
        if kwargs.get('timestamp'):
            self.timestamp = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=int(kwargs.pop('timestamp')))
        if kwargs.get('publish_timestamp'):
            self.publish_timestamp = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=int(kwargs.pop('publish_timestamp')))
        if kwargs.get('sharing_group_id'):
            self.sharing_group_id = int(kwargs.pop('sharing_group_id'))
        if kwargs.get('RelatedEvent'):
            self.RelatedEvent = []
            for rel_event in kwargs.pop('RelatedEvent'):
                sub_event = MISPEvent()
                sub_event.load(rel_event)
                self.RelatedEvent.append(sub_event)
        if kwargs.get('Tag'):
            self.Tag = [t for t in kwargs.pop('Tag', []) if t]
        if kwargs.get('Object'):
            self.Object = []
            for obj in kwargs.pop('Object'):
                tmp_object = MISPObject(obj['name'])
                tmp_object.from_dict(**obj)
                self.Object.append(tmp_object)

        for k, v in kwargs.items():
            setattr(self, k, v)

    def _json(self):
        # DEPTECATED
        return self.to_dict()

    def to_dict(self, with_timestamp=False):
        to_return = super(MISPEvent, self).to_dict()
        if to_return.get('date'):
            to_return['date'] = self.date.isoformat()
        if to_return.get('attributes'):
            attributes = to_return.pop('attributes')
            to_return['Attribute'] = [attribute.to_dict(with_timestamp) for attribute in attributes]
        if to_return.get('RelatedEvent'):
            to_return['RelatedEvent'] = [rel_event.to_dict() for rel_event in self.RelatedEvent]
        if with_timestamp and to_return.get('timestamp'):
            to_return['timestamp'] = int(time.mktime(self.timestamp.timetuple()))
        else:
            to_return.pop('timestamp', None)
        if with_timestamp and to_return.get('publish_timestamp'):
            to_return['publish_timestamp'] = int(time.mktime(self.publish_timestamp.timetuple()))
        else:
            to_return.pop('publish_timestamp', None)
        to_return = _int_to_str(to_return)
        to_return = {'Event': to_return}
        jsonschema.validate(to_return, self.__json_schema)
        return to_return

    def add_tag(self, tag):
        self.Tag.append({'name': tag})

    def add_attribute_tag(self, tag, attribute_identifier):
        attributes = []
        for a in self.attributes:
            if ((hasattr(a, 'id') and a.id == attribute_identifier) or
                (hasattr(a, 'uuid') and a.uuid == attribute_identifier) or
                (hasattr(a, 'value') and attribute_identifier == a.value or
                 attribute_identifier in a.value.split('|'))):
                a.add_tag(tag)
                attributes.append(a)
        if not attributes:
            raise Exception('No attribute with identifier {} found.'.format(attribute_identifier))
        return attributes

    def publish(self):
        self.published = True

    def unpublish(self):
        self.published = False

    def delete_attribute(self, attribute_id):
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
        attribute = MISPAttribute()
        if isinstance(value, list):
            for a in value:
                self.add_attribute(type, a, **kwargs)
        else:
            attribute.set_all_values(type=type, value=value, **kwargs)
            if not hasattr(self, 'attributes'):
                self.attributes = []
            self.attributes.append(attribute)


class MISPObjectReference(AbstractMISP):

    def __init__(self):
        super(MISPObjectReference, self).__init__()

    def from_dict(self, object_uuid, referenced_uuid, relationship_type, comment=None, **kwargs):
        self.object_uuid = object_uuid
        self.referenced_uuid = referenced_uuid
        self.relationship_type = relationship_type
        self.comment = comment
        for k, v in kwargs.items():
            setattr(self, k, v)


class MISPObjectAttribute(MISPAttribute):

    def __init__(self, definition):
        super(MISPObjectAttribute, self).__init__()
        self.__definition = definition

    def from_dict(self, object_relation, value, **kwargs):
        self.object_relation = object_relation
        self.value = value
        # Initialize the new MISPAttribute
        # Get the misp attribute type from the definition
        self.type = kwargs.pop('type', None)
        if self.type is None:
            self.type = self.__definition.get('misp-attribute')
        self.disable_correlation = kwargs.pop('disable_correlation', None)
        if self.disable_correlation is None:
            # The correlation can be disabled by default in the object definition.
            # Use this value if it isn't overloaded by the object
            self.disable_correlation = self.__definition.get('disable_correlation')
        self.to_ids = kwargs.pop('to_ids', None)
        if self.to_ids is None:
            # Same for the to_ids flag
            self.to_ids = self.__definition.get('to_ids')
        kwargs.update(**self)
        super(MISPObjectAttribute, self).from_dict(**kwargs)


class MISPObject(AbstractMISP):

    def __init__(self, name, strict=False):
        super(MISPObject, self).__init__()
        self.__strict = strict
        self.name = name
        self.__misp_objects_path = os.path.join(
            os.path.abspath(os.path.dirname(sys.modules['pymisp'].__file__)),
            'data', 'misp-objects', 'objects')
        if os.path.exists(os.path.join(self.__misp_objects_path, self.name, 'definition.json')):
            self.__known_template = True
        else:
            if self.__strict:
                raise UnknownMISPObjectTemplate('{} is unknown in the MISP object directory.'.format(self.name))
            else:
                self.__known_template = False
        if self.__known_template:
            with open(os.path.join(self.__misp_objects_path, self.name, 'definition.json'), 'r') as f:
                self.__definition = json.load(f)
            setattr(self, 'meta-category', self.__definition['meta-category'])
            self.template_uuid = self.__definition['uuid']
            self.description = self.__definition['description']
            self.template_version = self.__definition['version']
        else:
            # FIXME We need to set something for meta-category, template_uuid, description and template_version
            pass
        self.uuid = str(uuid.uuid4())
        self.Attribute = []
        self.ObjectReference = []

    def from_dict(self, **kwargs):
        if self.__known_template:
            if kwargs.get('template_uuid') and kwargs['template_uuid'] != self.template_uuid:
                if self.__strict:
                    raise UnknownMISPObjectTemplate('UUID of the object is different from the one of the template.')
                else:
                    self.__known_template = False
            if kwargs.get('template_version') and int(kwargs['template_version']) != self.template_version:
                if self.__strict:
                    raise UnknownMISPObjectTemplate('Version of the object ({}) is different from the one of the template ({}).'.format(kwargs['template_version'], self.template_version))
                else:
                    self.__known_template = False

        for key, value in kwargs.items():
            if key == 'Attribute':
                for v in value:
                    self.add_attribute(**v)
            elif key == 'ObjectReference':
                for v in value:
                    self.add_reference(**v)
            else:
                setattr(self, key, value)

    def to_dict(self, strict=False):
        if strict or self.__strict and self.__known_template:
            self._validate()
        return super(MISPObject, self).to_dict()

    def to_json(self, strict=False):
        if strict or self.__strict and self.__known_template:
            self._validate()
        return super(MISPObject, self).to_json()

    def _validate(self):
        """Make sure the object we're creating has the required fields"""
        all_object_relations = []
        for a in self.Attribute:
            all_object_relations.append(a.object_relation)
        count_relations = dict(Counter(all_object_relations))
        for key, counter in count_relations.items():
            if counter == 1:
                continue
            if not self.__definition['attributes'][key].get('multiple'):
                raise InvalidMISPObject('Multiple occurrences of {} is not allowed'.format(key))
        all_attribute_names = set(count_relations.keys())
        if self.__definition.get('requiredOneOf'):
            if not set(self.__definition['requiredOneOf']) & all_attribute_names:
                raise InvalidMISPObject('At least one of the following attributes is required: {}'.format(', '.join(self.__definition['requiredOneOf'])))
        if self.__definition.get('required'):
            for r in self.__definition.get('required'):
                if r not in all_attribute_names:
                    raise InvalidMISPObject('{} is required'.format(r))
        return True

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

    def add_attribute(self, object_relation, **value):
        if value.get('value') is None:
            return None
        if self.__known_template:
            if self.__definition['attributes'].get(object_relation):
                attribute = MISPObjectAttribute(self.__definition['attributes'][object_relation])
            else:
                # Woopsie, this object_relation is unknown, no sane defaults for you.
                attribute = MISPObjectAttribute({})
        else:
            attribute = MISPObjectAttribute({})
        attribute.from_dict(object_relation, **value)
        self.Attribute.append(attribute)
        return attribute
