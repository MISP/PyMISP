#!/usr/bin/env python
# -*- coding: utf-8 -*-

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
    warnings.warn("You're using python 2, it is strongly recommended to use python >=3.4")


class MISPObjectReference(AbstractMISP):

    attributes = ['uuid', 'relationship_type', 'comment']

    def __init__(self, uuid, relationship_type, comment=None):
        self['uuid'] = uuid
        self['relationship_type'] = relationship_type
        self['comment'] = comment


class MISPObjectGenerator(AbstractMISP):

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
        self.attributes = self.definition['attributes'].keys()
        self.misp_event = MISPEvent()
        self.uuid = str(uuid.uuid4())
        self.references = []

    def _create_attribute(self, object_type, **value):
        if value.get('value') is None:
            return None
        # Initialize the new MISPAttribute
        # Get the misp attribute type from the definition
        value['type'] = self.definition['attributes'][object_type]['misp-attribute']
        if value.get('disable_correlation') is None:
            # The correlation can be disabled by default in the object definition.
            # Use this value if it isn't overloaded by the object
            value['disable_correlation'] = self.definition['attributes'][object_type].get('disable_correlation')
        if value.get('to_ids') is None:
            # Same for the to_ids flag
            value['to_ids'] = self.definition['attributes'][object_type].get('to_ids')
        # Set all the values in the MISP attribute
        attribute = MISPAttribute(self.misp_event.describe_types)
        attribute.set_all_values(**value)
        self[object_type] = attribute

    def dump(self, strict=True):
        """Create a new object with the values gathered by the sub-class, use the default values from the template if needed"""
        if strict:
            self._validate()
        # Create an empty object based om the object definition
        new_object = self.__new_empty_object(self.definition)
        for object_type, attribute in self.items():
            # Add all the values as MISPAttributes to the current object
            if attribute.value is None:
                continue
            # Finalize the actual MISP Object
            new_object['Attribute'].append({'object_relation': object_type, **attribute._json()})
        return new_object, [r.to_dict() for r in self.references]

    def _validate(self):
        """Make sure the object we're creating has the required fields"""
        all_attribute_names = set(self.keys())
        if self.definition.get('requiredOneOf'):
            if not set(self.definition['requiredOneOf']) & all_attribute_names:
                raise InvalidMISPObject('At least one of the following attributes is required: {}'.format(', '.join(self.definition['requiredOneOf'])))
        if self.definition.get('required'):
            for r in self.definition.get('required'):
                if r not in all_attribute_names:
                    raise InvalidMISPObject('{} is required is required'.format(r))
        return True

    def add_reference(self, uuid, relationship_type, comment=None):
        """Add a link (uuid) to an other object"""
        self.references.append(MISPObjectReference(uuid, relationship_type, comment))

    def __new_empty_object(self, object_definiton):
        """Create a new empty object out of the template"""
        return {'name': object_definiton['name'], 'meta-category': object_definiton['meta-category'],
                'uuid': self.uuid, 'description': object_definiton['description'],
                'version': object_definiton['version'], 'Attribute': []}

    @abc.abstractmethod
    def generate_attributes(self):
        """Contains the logic where all the values of the object are gathered"""
        pass
