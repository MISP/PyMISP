#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import os
import json
import sys
import uuid
from collections import Counter

from .abstract import AbstractMISP
from .exceptions import UnknownMISPObjectTemplate, InvalidMISPObject
import six  # Remove that import when discarding python2 support.


if six.PY2:
    import warnings
    warnings.warn("You're using python 2, it is strongly recommended to use python >=3.5")


class MISPObjectReference(AbstractMISP):

    attributes = ['source_uuid', 'destination_uuid', 'relationship_type', 'comment', 'uuid', 'deleted']

    def __init__(self):
        super(MISPObjectReference, self).__init__()

    def from_dict(self, source_uuid, destination_uuid, relationship_type, comment=None, **kwargs):
        self.source_uuid = source_uuid
        self.destination_uuid = destination_uuid
        self.relationship_type = relationship_type
        self.comment = comment
        for k, v in kwargs:
            setattr(self, k, v)


class MISPObjectAttribute(AbstractMISP):

    # This list is very limited and hardcoded to fit the current needs (file/pe/pesection creation): MISPAttriute will follow the
    # same spec and just add one attribute: object_relation
    attributes = ['object_relation', 'value', 'type', 'category', 'disable_correlation', 'to_ids',
                  'data', 'encrypt', 'distribution', 'comment', 'uuid', 'event_id']

    def __init__(self, definition):
        super(MISPObjectAttribute, self).__init__()
        self.definition = definition

    def from_dict(self, object_relation, value, **kwargs):
        from .mispevent import MISPAttribute
        self.object_relation = object_relation
        self.value = value
        # Initialize the new MISPAttribute
        # Get the misp attribute type from the definition
        self.type = kwargs.pop('type', None)
        if self.type is None:
            self.type = self.definition.get('misp-attribute')
        self.disable_correlation = kwargs.pop('disable_correlation', None)
        if self.disable_correlation is None:
            # The correlation can be disabled by default in the object definition.
            # Use this value if it isn't overloaded by the object
            self.disable_correlation = self.definition.get('disable_correlation')
        self.to_ids = kwargs.pop('to_ids', None)
        if self.to_ids is None:
            # Same for the to_ids flag
            self.to_ids = self.definition.get('to_ids')
        # FIXME: dirty hack until all the classes are ported to the new format but we get the default values
        # Initialise rest of the values
        for k, v in kwargs.items():
            setattr(self, k, v)
        temp_attribute = MISPAttribute()
        temp_attribute.set_all_values(**self)
        # Update default values
        for k, v in temp_attribute.to_dict().items():
            setattr(self, k, v)


class MISPObject(AbstractMISP):

    attributes = ['name', 'meta-category', 'uuid', 'description', 'template_version', 'template_uuid', 'Attribute']

    def __init__(self, name, strict=True):
        super(MISPObject, self).__init__()
        self.strict = strict
        self.name = name
        self.misp_objects_path = os.path.join(
            os.path.abspath(os.path.dirname(sys.modules['pymisp'].__file__)),
            'data', 'misp-objects', 'objects')
        if os.path.exists(os.path.join(self.misp_objects_path, self.name, 'definition.json')):
            self.known_template = True
        else:
            if self.strict:
                raise UnknownMISPObjectTemplate('{} is unknown in the MISP object directory.')
            else:
                self.known_template = False
        if self.known_template:
            with open(os.path.join(self.misp_objects_path, self.name, 'definition.json'), 'r') as f:
                self.definition = json.load(f)
            setattr(self, 'meta-category', self.definition['meta-category'])
            self.template_uuid = self.definition['uuid']
            self.description = self.definition['description']
            self.template_version = self.definition['version']
        else:
            # FIXME We need to set something for meta-category, template_uuid, description and template_version
            pass
        self.uuid = str(uuid.uuid4())
        self.Attribute = []
        self.ObjectReference = []

    def from_dict(self, **kwargs):
        if self.known_template:
            if kwargs.get('template_uuid') and kwargs['template_uuid'] != self.template_uuid:
                if self.strict:
                    raise UnknownMISPObjectTemplate('UUID of the object is different from the one of the template.')
                else:
                    self.known_template = False
            if kwargs.get('template_version') and int(kwargs['template_version']) != self.template_version:
                if self.strict:
                    raise UnknownMISPObjectTemplate('Version of the object ({}) is different from the one of the template ({}).'.format(kwargs['template_version'], self.template_version))
                else:
                    self.known_template = False

        for key, value in kwargs.items():
            if key == 'Attribute':
                for v in value:
                    self.add_attribute(**v)
            elif key == 'ObjectReference':
                for v in value:
                    self.add_reference(**v)
            else:
                setattr(self, key, value)

    def to_dict(self, strict=True):
        if strict or self.strict and self.known_template:
            self._validate()
        return super(MISPObject, self).to_dict()

    def to_json(self, strict=True):
        if strict or self.strict and self.known_template:
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
            if not self.definition['attributes'][key].get('multiple'):
                raise InvalidMISPObject('Multiple occurrences of {} is not allowed'.format(key))
        all_attribute_names = set(count_relations.keys())
        if self.definition.get('requiredOneOf'):
            if not set(self.definition['requiredOneOf']) & all_attribute_names:
                raise InvalidMISPObject('At least one of the following attributes is required: {}'.format(', '.join(self.definition['requiredOneOf'])))
        if self.definition.get('required'):
            for r in self.definition.get('required'):
                if r not in all_attribute_names:
                    raise InvalidMISPObject('{} is required'.format(r))
        return True

    def add_reference(self, destination_uuid, relationship_type, comment=None, **kwargs):
        """Add a link (uuid) to an other object"""
        if kwargs.get('source_uuid'):
            # Load existing object
            source_uuid = kwargs.get('source_uuid')
        else:
            # New reference
            source_uuid = self.uuid
        reference = MISPObjectReference()
        reference.from_dict(source_uuid=source_uuid, destination_uuid=destination_uuid,
                            relationship_type=relationship_type, comment=comment, **kwargs)
        self.ObjectReference.append(reference)

    def add_attribute(self, object_relation, **value):
        if value.get('value') is None:
            return None
        if self.known_template:
            attribute = MISPObjectAttribute(self.definition['attributes'][object_relation])
        else:
            attribute = MISPObjectAttribute({})
        attribute.from_dict(object_relation, **value)
        self.Attribute.append(attribute)
        return attribute


@six.add_metaclass(abc.ABCMeta)   # Remove that line when discarding python2 support.
# Python3 way: class MISPObjectGenerator(metaclass=abc.ABCMeta):
class AbstractMISPObjectGenerator(MISPObject):

    @abc.abstractmethod
    def generate_attributes(self):
        """Contains the logic where all the values of the object are gathered"""
        pass
