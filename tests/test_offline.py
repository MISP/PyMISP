#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import requests_mock
import json
import os

import pymisp as pm
from pymisp import PyMISP
# from pymisp import NewEventError
from pymisp import MISPEvent
from pymisp import EncodeUpdate
from pymisp import EncodeFull


@requests_mock.Mocker()
class TestOffline(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        self.domain = 'http://misp.local/'
        self.key = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        with open('tests/misp_event.json', 'r') as f:
            self.event = {'Event': json.load(f)}
        with open('tests/new_misp_event.json', 'r') as f:
            self.new_misp_event = {'Event': json.load(f)}
        self.ressources_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), '../pymisp/data')
        with open(os.path.join(self.ressources_path, 'describeTypes.json'), 'r') as f:
            self.types = json.load(f)
        with open('tests/sharing_groups.json', 'r') as f:
            self.sharing_groups = json.load(f)
        self.auth_error_msg = {"name": "Authentication failed. Please make sure you pass the API key of an API enabled user along in the Authorization header.",
                               "message": "Authentication failed. Please make sure you pass the API key of an API enabled user along in the Authorization header.",
                               "url": "\/events\/1"}
        with open('tests/search_index_result.json', 'r') as f:
            self.search_index_result = json.load(f)

    def initURI(self, m):
        m.register_uri('GET', self.domain + 'events/1', json=self.auth_error_msg, status_code=403)
        m.register_uri('GET', self.domain + 'servers/getVersion.json', json={"version": "2.4.62"})
        m.register_uri('GET', self.domain + 'servers/getPyMISPVersion.json', json={"version": "2.4.62"})
        m.register_uri('GET', self.domain + 'sharing_groups.json', json=self.sharing_groups)
        m.register_uri('GET', self.domain + 'attributes/describeTypes.json', json=self.types)
        m.register_uri('GET', self.domain + 'events/2', json=self.event)
        m.register_uri('POST', self.domain + 'events/5758ebf5-c898-48e6-9fe9-5665c0a83866', json=self.event)
        m.register_uri('DELETE', self.domain + 'events/2', json={'message': 'Event deleted.'})
        m.register_uri('DELETE', self.domain + 'events/3', json={'errors': ['Invalid event'], 'message': 'Invalid event', 'name': 'Invalid event', 'url': '/events/3'})
        m.register_uri('DELETE', self.domain + 'attributes/2', json={'message': 'Attribute deleted.'})
        m.register_uri('GET', self.domain + 'events/index/searchtag:1', json=self.search_index_result)
        m.register_uri('GET', self.domain + 'events/index/searchtag:ecsirt:malicious-code=%22ransomware%22', json=self.search_index_result)

    def test_getEvent(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        e1 = pymisp.get_event(2)
        e2 = pymisp.get(2)
        self.assertEqual(e1, e2)
        self.assertEqual(self.event, e2)

    def test_updateEvent(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        e0 = pymisp.update_event('5758ebf5-c898-48e6-9fe9-5665c0a83866', json.dumps(self.event))
        e1 = pymisp.update_event('5758ebf5-c898-48e6-9fe9-5665c0a83866', self.event)
        self.assertEqual(e0, e1)
        e2 = pymisp.update(e0)
        self.assertEqual(e1, e2)
        self.assertEqual(self.event, e2)

    def test_deleteEvent(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        d = pymisp.delete_event(2)
        self.assertEqual(d, {'message': 'Event deleted.'})
        d = pymisp.delete_event(3)
        self.assertEqual(d, {'errors': ['Invalid event'], 'message': 'Invalid event', 'name': 'Invalid event', 'url': '/events/3'})

    def test_deleteAttribute(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        d = pymisp.delete_attribute(2)
        self.assertEqual(d, {'message': 'Attribute deleted.'})

    def test_publish(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        e = pymisp.publish(self.event)  # requests-mock always return the non-published event
        pub = self.event
        pub['Event']['published'] = True
        # self.assertEqual(e, pub) FIXME: broken test, not-published event returned
        e = pymisp.publish(self.event)
        self.assertEqual(e, {'error': 'Already published'})

    def test_getVersions(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        api_version = pymisp.get_api_version()
        self.assertEqual(api_version, {'version': pm.__version__})
        server_version = pymisp.get_version()
        self.assertEqual(server_version, {"version": "2.4.62"})

    def test_getSharingGroups(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        sharing_groups = pymisp.get_sharing_groups()
        self.assertEqual(sharing_groups[0], self.sharing_groups['response'][0])

    def test_auth_error(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        error = pymisp.get(1)
        response = self.auth_error_msg
        response['errors'] = [response['message']]
        self.assertEqual(error, response)

    def test_newEvent(self, m):
        error_empty_info = {'message': 'The event could not be saved.', 'name': 'Add event failed.', 'errors': {'Event': {'info': ['Info cannot be empty.']}}, 'url': '/events/add'}
        error_empty_info_flatten = {u'message': u'The event could not be saved.', u'name': u'Add event failed.', u'errors': [u"Error in info: Info cannot be empty."], u'url': u'/events/add'}
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        m.register_uri('POST', self.domain + 'events', json=error_empty_info)
        # TODO Add test exception if info field isn't set
        response = pymisp.new_event(0, 1, 0, 'Foo')
        self.assertEqual(response, error_empty_info_flatten)
        m.register_uri('POST', self.domain + 'events', json=self.new_misp_event)
        response = pymisp.new_event(0, 1, 0, "This is a test.", '2016-08-26', False)
        self.assertEqual(response, self.new_misp_event)

    def test_eventObject(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        misp_event = MISPEvent(pymisp.describe_types)
        with open('tests/57c4445b-c548-4654-af0b-4be3950d210f.json', 'r') as f:
            misp_event.load(f.read())
        json.dumps(misp_event, cls=EncodeUpdate)
        json.dumps(misp_event, cls=EncodeFull)

    def test_searchIndexByTagId(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        response = pymisp.search_index(tag="1")
        self.assertEqual(response['response'], self.search_index_result)

    def test_searchIndexByTagName(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        response = pymisp.search_index(tag='ecsirt:malicious-code="ransomware"')
        self.assertEqual(response['response'], self.search_index_result)

    def test_addAttributes(self, m):
        class MockPyMISP(PyMISP):
            def _send_attributes(self, event, attributes, proposal=False):
                return len(attributes)
        self.initURI(m)
        p = MockPyMISP(self.domain, self.key)
        evt = p.get(1)
        self.assertEquals(3, p.add_hashes(evt, md5='68b329da9893e34099c7d8ad5cb9c940',
                          sha1='adc83b19e793491b1c6ea0fd8b46cd9f32e592fc',
                          sha256='01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
                          filename='foobar.exe'))
        self.assertEquals(3, p.add_hashes(evt, md5='68b329da9893e34099c7d8ad5cb9c940',
                          sha1='adc83b19e793491b1c6ea0fd8b46cd9f32e592fc',
                          sha256='01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b'))
        p.av_detection_link(evt, 'https://foocorp.com')
        p.add_detection_name(evt, 'WATERMELON')
        p.add_filename(evt, 'foobar.exe')
        p.add_regkey(evt, 'HKLM\\Software\\Microsoft\\Outlook\\Addins\\foobar')
        p.add_regkey(evt, 'HKLM\\Software\\Microsoft\\Outlook\\Addins\\foobar', rvalue='foobar')
        regkeys = {
            'HKLM\\Software\\Microsoft\\Outlook\\Addins\\foo': None,
            'HKLM\\Software\\Microsoft\\Outlook\\Addins\\bar': 'baz',
            'HKLM\\Software\\Microsoft\\Outlook\\Addins\\bae': 0,
        }
        self.assertEqual(3, p.add_regkeys(evt, regkeys))
        p.add_pattern(evt, '.*foobar.*', in_memory=True)
        p.add_pattern(evt, '.*foobar.*', in_file=True)
        self.assertRaises(pm.PyMISPError, p.add_pattern, evt, '.*foobar.*', in_memory=False, in_file=False)
        p.add_pipe(evt, 'foo')
        p.add_pipe(evt, '\\.\\pipe\\foo')
        self.assertEquals(3, p.add_pipe(evt, ['foo', 'bar', 'baz']))
        self.assertEquals(3, p.add_pipe(evt, ['foo', 'bar', '\\.\\pipe\\baz']))
        p.add_mutex(evt, 'foo')
        self.assertEquals(1, p.add_mutex(evt, '\\BaseNamedObjects\\foo'))
        self.assertEquals(3, p.add_mutex(evt, ['foo', 'bar', 'baz']))
        self.assertEquals(3, p.add_mutex(evt, ['foo', 'bar', '\\BaseNamedObjects\\baz']))
        p.add_yara(evt, 'rule Foo {}')
        self.assertEquals(2, p.add_yara(evt, ['rule Foo {}', 'rule Bar {}']))
        p.add_ipdst(evt, '1.2.3.4')
        self.assertEquals(2, p.add_ipdst(evt, ['1.2.3.4', '5.6.7.8']))
        p.add_ipsrc(evt, '1.2.3.4')
        self.assertEquals(2, p.add_ipsrc(evt, ['1.2.3.4', '5.6.7.8']))
        p.add_hostname(evt, 'a.foobar.com')
        self.assertEquals(2, p.add_hostname(evt, ['a.foobar.com', 'a.foobaz.com']))
        p.add_domain(evt, 'foobar.com')
        self.assertEquals(2, p.add_domain(evt, ['foobar.com', 'foobaz.com']))
        p.add_domain_ip(evt, 'foo.com', '1.2.3.4')
        self.assertEquals(2, p.add_domain_ip(evt, 'foo.com', ['1.2.3.4', '5.6.7.8']))
        self.assertEquals(2, p.add_domains_ips(evt, {'foo.com': '1.2.3.4', 'bar.com': '4.5.6.7'}))
        p.add_url(evt, 'https://example.com')
        self.assertEquals(2, p.add_url(evt, ['https://example.com', 'http://foo.com']))
        p.add_useragent(evt, 'Mozilla')
        self.assertEquals(2, p.add_useragent(evt, ['Mozilla', 'Godzilla']))
        p.add_traffic_pattern(evt, 'blabla')
        p.add_snort(evt, 'blaba')
        p.add_net_other(evt, 'blabla')
        p.add_email_src(evt, 'foo@bar.com')
        p.add_email_dst(evt, 'foo@bar.com')
        p.add_email_subject(evt, 'you won the lottery')
        p.add_email_attachment(evt, 'foo.doc')
        p.add_target_email(evt, 'foo@bar.com')
        p.add_target_user(evt, 'foo')
        p.add_target_machine(evt, 'foobar')
        p.add_target_org(evt, 'foobar')
        p.add_target_location(evt, 'foobar')
        p.add_target_external(evt, 'foobar')
        p.add_threat_actor(evt, 'WATERMELON')
        p.add_internal_link(evt, 'foobar')
        p.add_internal_comment(evt, 'foobar')
        p.add_internal_text(evt, 'foobar')
        p.add_internal_other(evt, 'foobar')
        p.add_attachment(evt, "testFile", "Attacment added!")
if __name__ == '__main__':
    unittest.main()
