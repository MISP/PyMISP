#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests_mock
import json

from pymisp import PyMISP


@requests_mock.Mocker()
class TestOffline(object):

    def setUp(self):
        self.domain = 'http://misp.local/'
        self.key = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        self.event = json.load(open('tests/misp_event.json', 'r'))
        self.types = json.load(open('tests/describeTypes.json', 'r'))

    def initURI(self, m):
        m.register_uri('GET', self.domain + 'servers/getVersion', json={"version": "2.4.50"})
        m.register_uri('GET', self.domain + 'attributes/describeTypes.json', json=self.types)
        m.register_uri('GET', self.domain + 'events/2', json=self.event)

    def test_getEvent(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key, debug=True)
        e = pymisp.get_event(2)
        print(e)
