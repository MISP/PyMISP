#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .abstractgenerator import AbstractMISPObjectGenerator


class GenericObjectGenerator(AbstractMISPObjectGenerator):

    def generate_attributes(self, attributes):
        for attribute in attributes:
            for object_relation, value in attribute.items():
                if isinstance(value, dict):
                    self.add_attribute(object_relation, **value)
                else:
                    # In this case, we need a valid template, as all the other parameters will be pre-set.
                    self.add_attribute(object_relation, value=value)
