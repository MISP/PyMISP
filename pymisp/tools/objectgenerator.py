#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import MISPEvent, MISPAttribute
import os
import json
import uuid
import abc
import sys
import six


class MISPObjectException(Exception):
    pass


class InvalidMISPObject(MISPObjectException):
    """Exception raised when an object doesn't contains the required field(s)"""
    pass


if six.PY2:
    import warnings
    warnings.warn("You're using python 2, it is strongly recommended to use python >=3.4")


@six.add_metaclass(abc.ABCMeta)   # Remove that line when discarding python2 support.
# Python3 way: class MISPObjectGenerator(metaclass=abc.ABCMeta):
class MISPObjectGenerator():

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
        self.uuid = str(uuid.uuid4())
        self.links = []

    def _fill_object(self, values, strict=True):
        """Create a new object with the values gathered by the sub-class, use the default values from the template if needed"""
        if strict:
            self._validate(values)
        # Create an empty object based om the object definition
        new_object = self.__new_empty_object(self.definition)
        if self.links:
            # Set the links to other objects
            new_object["ObjectReference"] = []
            for link in self.links:
                uuid, comment = link
                new_object['ObjectReference'].append({'referenced_object_uuid': uuid, 'comment': comment})
        for object_type, value in values.items():
            # Add all the values as MISPAttributes to the current object
            if value.get('value') is None:
                continue
            # Initialize the new MISPAttribute
            attribute = MISPAttribute(self.misp_event.describe_types)
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
            attribute.set_all_values(**value)
            # Finalize the actual MISP Object
            new_object['ObjectAttribute'].append({'type': object_type, 'Attribute': attribute._json()})
        return new_object

    def _validate(self, dump):
        """Make sure the object we're creating has the required fields"""
        all_attribute_names = set(dump.keys())
        if self.definition.get('requiredOneOf'):
            if not set(self.definition['requiredOneOf']) & all_attribute_names:
                raise InvalidMISPObject('At least one of the following attributes is required: {}'.format(', '.join(self.definition['requiredOneOf'])))
        if self.definition.get('required'):
            for r in self.definition.get('required'):
                if r not in all_attribute_names:
                    raise InvalidMISPObject('{} is required is required'.format(r))
        return True

    def add_link(self, uuid, comment=None):
        """Add a link (uuid) to an other object"""
        self.links.append((uuid, comment))

    def __new_empty_object(self, object_definiton):
        """Create a new empty object out of the template"""
        return {'name': object_definiton['name'], 'meta-category': object_definiton['meta-category'],
                'uuid': self.uuid, 'description': object_definiton['description'],
                'version': object_definiton['version'], 'ObjectAttribute': []}

    @abc.abstractmethod
    def generate_attributes(self):
        """Contains the logic where all the values of the object are gathered"""
        pass

    @abc.abstractmethod
    def dump(self):
        """This method normalize the attributes to add to the object.
        It returns an python dictionary where the key is the type defined in the object,
        and the value the value of the MISP Attribute"""
        pass
