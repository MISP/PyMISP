#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import requests_mock
import json

import pymisp as pm
from pymisp import PyMISP


@requests_mock.Mocker()
class TestOffline(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        self.domain = 'http://misp.local/'
        self.key = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        self.event = {'Event': json.load(open('tests/misp_event.json', 'r'))}
        self.types = json.load(open('tests/describeTypes.json', 'r'))
        self.sharing_groups = json.load(open('tests/sharing_groups.json', 'r'))
        self.auth_error_msg = {"name": "Authentication failed. Please make sure you pass the API key of an API enabled user along in the Authorization header.",
                               "message": "Authentication failed. Please make sure you pass the API key of an API enabled user along in the Authorization header.",
                               "url": "\/events\/1"}

    def initURI(self, m):
        m.register_uri('GET', self.domain + 'events/1', json=self.auth_error_msg, status_code=403)
        m.register_uri('GET', self.domain + 'servers/getVersion.json', json={"version": "2.4.50"})
        m.register_uri('GET', self.domain + 'sharing_groups/index.json', json=self.sharing_groups)
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

    def test_getVersions(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key, debug=True)
        api_version = pymisp.get_api_version()
        self.assertEqual(api_version, {'version': pm.__version__})
        server_version = pymisp.get_version()
        self.assertEqual(server_version, {"version": "2.4.50"})

    def test_getSharingGroups(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key, debug=True)
        sharing_groups = pymisp.get_sharing_groups()
        self.assertEqual(sharing_groups, self.sharing_groups['response'][0])

    def test_auth_error(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key, debug=True)
        error = pymisp.get(1)
        response = self.auth_error_msg
        response['errors'] = [response['message']]
        print(error)

if __name__ == '__main__':
    unittest.main()
