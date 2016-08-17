#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import requests_mock
import json

import pymisp
from pymisp import PyMISP


@requests_mock.Mocker()
class TestOffline(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        self.domain = 'http://misp.local/'
        self.key = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        self.event = {'Event': json.load(open('tests/misp_event.json', 'r'))}
        self.types = json.load(open('tests/describeTypes.json', 'r'))

    def initURI(self, m):
        m.register_uri('GET', self.domain + 'servers/getVersion', json={"version": pymisp.__version__[1:]})
        m.register_uri('GET', self.domain + 'attributes/describeTypes.json', json=self.types)
        m.register_uri('GET', self.domain + 'events/2', json=self.event)
        m.register_uri('POST', self.domain + 'events/2', json=self.event)
        m.register_uri('DELETE', self.domain + 'events/2', json={'message': 'Event deleted.'})
        m.register_uri('DELETE', self.domain + 'events/3', json={'errors': ['Invalid event'], 'message': 'Invalid event', 'name': 'Invalid event', 'url': '/events/3'})
        m.register_uri('DELETE', self.domain + 'attributes/2', json={'message': 'Attribute deleted.'})

    def test_getEvent(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key, debug=True)
        e1 = pymisp.get_event(2)
        e2 = pymisp.get(2)
        self.assertEqual(e1, e2)
        self.assertEqual(self.event, e2)

    def test_updateEvent(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key, debug=True)
        e0 = pymisp.update_event(2, json.dumps(self.event))
        e1 = pymisp.update_event(2, self.event)
        self.assertEqual(e0, e1)
        e2 = pymisp.update(e0)
        self.assertEqual(e1, e2)
        self.assertEqual(self.event, e2)

    def test_deleteEvent(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key, debug=True)
        d = pymisp.delete_event(2)
        self.assertEqual(d, {'message': 'Event deleted.'})
        d = pymisp.delete_event(3)
        self.assertEqual(d, {'errors': ['Invalid event'], 'message': 'Invalid event', 'name': 'Invalid event', 'url': '/events/3'})

    def test_deleteAttribute(self, m):
        # FIXME: https://github.com/MISP/MISP/issues/1449
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key, debug=True)
        d = pymisp.delete_attribute(2)
        self.assertEqual(d, {'message': 'Attribute deleted.'})

    def test_publish(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key, debug=True)
        e = pymisp.publish(self.event)
        pub = self.event
        pub['Event']['published'] = True
        self.assertEqual(e, pub)
        e = pymisp.publish(self.event)
        self.assertEqual(e, {'error': 'Already published'})
