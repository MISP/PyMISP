#!/usr/bin/env python
# -*- coding: utf-8 -*-

from collections import Counter
from pymisp import MISPEvent, MISPAttribute, AbstractMISP
import os
import json
import uuid
import abc
import sys
import six  # Remove that import when discarding python2 support.


class MISPObjectException(Exception):
    pass


class InvalidMISPObject(MISPObjectException):
    """Exception raised when an object doesn't contains the required field(s)"""
    pass


if six.PY2:
    import warnings
    warnings.warn("You're using python 2, it is strongly recommended to use python >=3.5")


class MISPObjectReference(AbstractMISP):

    attributes = ['source_uuid', 'destination_uuid', 'relationship_type', 'comment']

    def __init__(self, source_uuid, destination_uuid, relationship_type, comment=None):
        self.source_uuid = source_uuid
        self.destination_uuid = destination_uuid
        self.relationship_type = relationship_type
        self.comment = comment


class MISPObjectAttribute(AbstractMISP):

    # This list is very limited and hardcoded to fit the current needs (file/pe/pesection creation): MISPAttriute will follow the
    # same spec and just add one attribute: object_relation
    attributes = ['object_relation', 'value', 'type', 'category', 'disable_correlation', 'to_ids',
                  'data', 'encrypt', 'distribution', 'comment']

    def __init__(self, definition, object_relation, value, **kwargs):
        self.object_relation = object_relation
        self.value = value
        # Initialize the new MISPAttribute
        # Get the misp attribute type from the definition
        self.type = kwargs.pop('type', None)
        if self.type is None:
            self.type = definition['misp-attribute']
        self.disable_correlation = kwargs.pop('disable_correlation', None)
        if self.disable_correlation is None:
            # The correlation can be disabled by default in the object definition.
            # Use this value if it isn't overloaded by the object
            self.disable_correlation = definition.get('disable_correlation')
        self.to_ids = kwargs.pop('to_ids', None)
        if self.to_ids is None:
            # Same for the to_ids flag
            self.to_ids = definition.get('to_ids')
        # Initialise rest of the values
        for k, v in kwargs.items():
            self[k] = v
        # FIXME: dirty hack until all the classes are ported to the new format but we get the default values
        temp_attribute = MISPAttribute()
        temp_attribute.set_all_values(**self)
        # Update default values
        self.from_dict(**temp_attribute.to_dict())


class MISPObjectGenerator(AbstractMISP):

    attributes = ['name', 'meta-category', 'uuid', 'description', 'version', 'Attribute']

    def __init__(self, template_dir):
        """This class is used to fill a new MISP object with the default values defined in the object template
            * template is the path to the template within the misp-object repository
            * misp_objects_path is the path to the misp-object repository
        """
        self.misp_objects_path = os.path.join(
            os.path.abspath(os.path.dirname(sys.modules['pymisp'].__file__)),
            'data', 'misp-objects', 'objects')
        with open(os.path.join(self.misp_objects_path, template_dir, 'definition.json'), 'r') as f:
            self.definition = json.load(f)
        self.misp_event = MISPEvent()
        self.name = self.definition['name']
        setattr(self, 'meta-category', self.definition['meta-category'])
        self.template_uuid = self.definition['uuid']
        self.description = self.definition['description']
        self.version = self.definition['version']
        self.uuid = str(uuid.uuid4())
        self.Attribute = []
        self.references = []

    def _create_attribute(self, object_type, **value):
        if value.get('value') is None:
            return None
        attribute = MISPObjectAttribute(self.definition['attributes'][object_type], object_type, **value)
        self.Attribute.append(attribute)
        return attribute

    def to_dict(self, strict=True):
        if strict:
            self._validate()
        return super(MISPObjectGenerator, self).to_dict()

    def to_json(self, strict=True):
        if strict:
            self._validate()
        return super(MISPObjectGenerator, self).to_json()

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

    def add_reference(self, destination_uuid, relationship_type, comment=None):
        """Add a link (uuid) to an other object"""
        self.references.append(MISPObjectReference(self.uuid, destination_uuid, relationship_type, comment))

    @abc.abstractmethod
    def generate_attributes(self):
        """Contains the logic where all the values of the object are gathered"""
        pass
