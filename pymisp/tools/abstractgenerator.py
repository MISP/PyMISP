#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import six
from .. import MISPObject


@six.add_metaclass(abc.ABCMeta)   # Remove that line when discarding python2 support.
# Python3 way: class MISPObjectGenerator(metaclass=abc.ABCMeta):
class AbstractMISPObjectGenerator(MISPObject):

    @abc.abstractmethod
    def generate_attributes(self):
        """Contains the logic where all the values of the object are gathered"""
        pass
