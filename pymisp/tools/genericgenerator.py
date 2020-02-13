#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .abstractgenerator import AbstractMISPObjectGenerator
from typing import List


class GenericObjectGenerator(AbstractMISPObjectGenerator):

    # FIXME: this method is different from the master one, and that's probably not a good idea.
    def generate_attributes(self, attributes: List[dict]):  # type: ignore
        """Generates MISPObjectAttributes from a list of dictionaries.
        Each entry if the list must be in one of the two following formats:
        * {<object_relation>: <value>}
        * {<object_relation>: {'value'=<value>, 'type'=<type>, <and any other key/value accepted by a MISPAttribute>]}

        Note: Any missing parameter will default to the pre-defined value from the Object template.
              If the object template isn't known by PyMISP, you *must* pass a type key/value, or it will fail.

        Example:
             [{'analysis_submitted_at': '2018-06-15T06:40:27'},
             {'threat_score': {value=95, to_ids=False}},
             {'permalink': 'https://panacea.threatgrid.com/mask/samples/2e445ef5389d8b'},
             {'heuristic_raw_score': 7.8385159793597}, {'heuristic_score': 96},
             {'original_filename': 'juice.exe'}, {'id':  '2e445ef5389d8b'}]
        """
        for attribute in attributes:
            for object_relation, value in attribute.items():
                if isinstance(value, dict):
                    self.add_attribute(object_relation, **value)
                else:
                    # In this case, we need a valid template, as all the other parameters will be pre-set.
                    self.add_attribute(object_relation, value=value)
