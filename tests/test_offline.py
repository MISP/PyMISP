#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import requests_mock
import json
import os
import six
import sys
from io import BytesIO

import pymisp as pm
from pymisp import PyMISP
# from pymisp import NewEventError
from pymisp import MISPEvent
from pymisp import MISPEncode

from pymisp.tools import make_binary_objects


class MockPyMISP(PyMISP):
    def _send_attributes(self, event, attributes, proposal=False):
        return attributes


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
        self.resources_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), '../pymisp/data')
        with open(os.path.join(self.resources_path, 'describeTypes.json'), 'r') as f:
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
        m.register_uri('GET', self.domain + 'attributes/delete/2', json={'message': 'Attribute deleted.'})
        m.register_uri('POST', self.domain + 'events/index', json=self.search_index_result)
        m.register_uri('POST', self.domain + 'attributes/edit/' + self.key, json={})
        m.register_uri('GET', self.domain + 'shadow_attributes/view/None', json={})
        m.register_uri('GET', self.domain + 'shadow_attributes/view/1', json={})
        m.register_uri('POST', self.domain + 'events/freeTextImport/1', json={})
        m.register_uri('POST', self.domain + 'attributes/restSearch', json={})
        m.register_uri('POST', self.domain + 'attributes/downloadSample', json={})
        m.register_uri('GET', self.domain + 'tags', json={'Tag': 'foo'})
        m.register_uri('POST', self.domain + 'events/upload_sample/1', json={})
        m.register_uri('POST', self.domain + 'tags/attachTagToObject', json={})
        m.register_uri('POST', self.domain + 'tags/removeTagFromObject', json={})

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
        print(sharing_groups)
        self.assertEqual(sharing_groups['response'][0], self.sharing_groups[0])

    def test_auth_error(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        error = pymisp.get(1)
        response = self.auth_error_msg
        response['errors'] = [response['message']]
        self.assertEqual(error, response)

    def test_newEvent(self, m):
        error_empty_info = {'message': 'The event could not be saved.',
                            'name': 'Add event failed.',
                            'errors': ['Error in info: Info cannot be empty.'],
                            'url': '/events/add'}
        error_empty_info_flatten = {u'message': u'The event could not be saved.',
                                    u'name': u'Add event failed.',
                                    u'errors': [u"Error in info: Info cannot be empty."],
                                    u'url': u'/events/add'}
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
        json.dumps(misp_event, cls=MISPEncode)

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

    def add_hashes(self, event, mock):
        """
            Regression tests for #174
        """
        hashes_fname = mock.add_hashes(event,
                                       md5='68b329da9893e34099c7d8ad5cb9c940',
                                       sha1='adc83b19e793491b1c6ea0fd8b46cd9f32e592fc',
                                       sha256='01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
                                       filename='foobar.exe')
        self.assertEqual(3, len(hashes_fname))
        for attr in hashes_fname:
            self.assertTrue(isinstance(attr, pm.mispevent.MISPAttribute))
            self.assertIn("filename|", attr["type"])

        hashes_only = mock.add_hashes(event, md5='68b329da9893e34099c7d8ad5cb9c940',
                                      sha1='adc83b19e793491b1c6ea0fd8b46cd9f32e592fc',
                                      sha256='01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b')
        self.assertEqual(3, len(hashes_only))
        for attr in hashes_only:
            self.assertTrue(isinstance(attr, pm.mispevent.MISPAttribute))
            self.assertNotIn("filename|", attr["type"])

    def add_regkeys(self, event, mock):
        regkeys = {
            'HKLM\\Software\\Microsoft\\Outlook\\Addins\\foo': None,
            'HKLM\\Software\\Microsoft\\Outlook\\Addins\\bar': 'baz',
            'HKLM\\Software\\Microsoft\\Outlook\\Addins\\bae': 0,
        }
        reg_attr = mock.add_regkeys(event, regkeys)
        self.assertEqual(3, len(reg_attr))
        for attr in reg_attr:
            self.assertTrue(isinstance(attr, pm.mispevent.MISPAttribute))
            self.assertIn("regkey", attr["type"])

        key = mock.add_regkey(event, 'HKLM\\Software\\Microsoft\\Outlook\\Addins\\foobar')
        self.assertEqual(len(key), 1)
        self.assertEqual(key[0]["type"], "regkey")

        key = mock.add_regkey(event, 'HKLM\\Software\\Microsoft\\Outlook\\Addins\\foobar', rvalue='foobar')
        self.assertEqual(len(key), 1)
        self.assertEqual(key[0]["type"], "regkey|value")
        self.assertIn("foobar|foobar", key[0]["value"])

    def test_addAttributes(self, m):
        self.initURI(m)
        p = MockPyMISP(self.domain, self.key)
        evt = p.get(1)

        self.add_hashes(evt, p)
        self.add_regkeys(evt, p)

        p.av_detection_link(evt, 'https://foocorp.com')
        p.add_detection_name(evt, 'WATERMELON')
        p.add_filename(evt, 'foobar.exe')
        p.add_pattern(evt, '.*foobar.*', in_memory=True)
        p.add_pattern(evt, '.*foobar.*', in_file=True)
        p.add_mutex(evt, 'foo')
        p.add_pipe(evt, 'foo')
        p.add_pipe(evt, '\\.\\pipe\\foo')

        self.assertRaises(pm.PyMISPError, p.add_pattern, evt, '.*foobar.*', in_memory=False, in_file=False)

        self.assertEqual(3, len(p.add_pipe(evt, ['foo', 'bar', 'baz'])))
        self.assertEqual(3, len(p.add_pipe(evt, ['foo', 'bar', '\\.\\pipe\\baz'])))

        self.assertEqual(1, len(p.add_mutex(evt, '\\BaseNamedObjects\\foo')))
        self.assertEqual(3, len(p.add_mutex(evt, ['foo', 'bar', 'baz'])))
        self.assertEqual(3, len(p.add_mutex(evt, ['foo', 'bar', '\\BaseNamedObjects\\baz'])))
        p.add_yara(evt, 'rule Foo {}')
        self.assertEqual(2, len(p.add_yara(evt, ['rule Foo {}', 'rule Bar {}'])))
        p.add_ipdst(evt, '1.2.3.4')
        self.assertEqual(2, len(p.add_ipdst(evt, ['1.2.3.4', '5.6.7.8'])))
        p.add_ipsrc(evt, '1.2.3.4')
        self.assertEqual(2, len(p.add_ipsrc(evt, ['1.2.3.4', '5.6.7.8'])))
        p.add_hostname(evt, 'a.foobar.com')
        self.assertEqual(2, len(p.add_hostname(evt, ['a.foobar.com', 'a.foobaz.com'])))
        p.add_domain(evt, 'foobar.com')
        self.assertEqual(2, len(p.add_domain(evt, ['foobar.com', 'foobaz.com'])))
        p.add_domain_ip(evt, 'foo.com', '1.2.3.4')
        self.assertEqual(2, len(p.add_domain_ip(evt, 'foo.com', ['1.2.3.4', '5.6.7.8'])))
        self.assertEqual(2, len(p.add_domains_ips(evt, {'foo.com': '1.2.3.4', 'bar.com': '4.5.6.7'})))

        p.add_url(evt, 'https://example.com')
        self.assertEqual(2, len(p.add_url(evt, ['https://example.com', 'http://foo.com'])))

        p.add_useragent(evt, 'Mozilla')
        self.assertEqual(2, len(p.add_useragent(evt, ['Mozilla', 'Godzilla'])))

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
        p.add_attachment(evt, "testFile")

    def make_objects(self, path=None, pseudofile=None, filename=None):
        to_return = {'objects': [], 'references': []}
        if path:
            fo, peo, seos = make_binary_objects(path)
        else:
            fo, peo, seos = make_binary_objects(pseudofile=pseudofile, filename=filename)

        if seos:
            for s in seos:
                for a in s.attributes:
                    del a.uuid
                to_return['objects'].append(s)
                if s.ObjectReference:
                    to_return['references'] += s.ObjectReference

        if peo:
            for a in peo.attributes:
                del a.uuid
            to_return['objects'].append(peo)
            if peo.ObjectReference:
                to_return['references'] += peo.ObjectReference

        if fo:
            for a in fo.attributes:
                del a.uuid
            to_return['objects'].append(fo)
            if fo.ObjectReference:
                to_return['references'] += fo.ObjectReference

        # Remove UUIDs for comparing the objects.
        for o in to_return['objects']:
            o.pop('uuid')
        for o in to_return['references']:
            o.pop('referenced_uuid')
            o.pop('object_uuid')
        return json.dumps(to_return, cls=MISPEncode)

    def test_objects_pseudofile(self, m):
        if six.PY2:
            return unittest.SkipTest()
        paths = ['cmd.exe', 'tmux', 'MachO-OSX-x64-ls']
        try:
            for path in paths:
                with open(os.path.join('tests', 'viper-test-files', 'test_files', path), 'rb') as f:
                    pseudo = BytesIO(f.read())
                    json_blob = self.make_objects(pseudofile=pseudo, filename=path)
                # Compare pseudo file / path
                filepath_blob = self.make_objects(os.path.join('tests', 'viper-test-files', 'test_files', path))
                self.assertEqual(json_blob, filepath_blob)
        except IOError:  # Can be replaced with FileNotFoundError when support for python 2 is dropped
            return unittest.SkipTest()
        print(json_blob)

    def test_objects(self, m):
        paths = ['cmd.exe', 'tmux', 'MachO-OSX-x64-ls']
        try:
            for path in paths:
                json_blob = self.make_objects(os.path.join('tests',
                                              'viper-test-files', 'test_files', path))
        except IOError:  # Can be replaced with FileNotFoundError when support for python 2 is dropped
            return unittest.SkipTest()
        print(json_blob)

    def test_describeTypes_sane_default(self, m):
        sane_default = self.types['result']['sane_defaults']
        self.assertEqual(sorted(sane_default.keys()), sorted(self.types['result']['types']))

    def test_describeTypes_categories(self, m):
        category_type_mappings = self.types['result']['category_type_mappings']
        self.assertEqual(sorted(category_type_mappings.keys()), sorted(self.types['result']['categories']))

    def test_describeTypes_types_in_categories(self, m):
        category_type_mappings = self.types['result']['category_type_mappings']
        for category, types in category_type_mappings.items():
                existing_types = [t for t in types if t in self.types['result']['types']]
                self.assertEqual(sorted(existing_types), sorted(types))

    def test_describeTypes_types_have_category(self, m):
        category_type_mappings = self.types['result']['category_type_mappings']
        all_types = set()
        for category, types in category_type_mappings.items():
            all_types.update(types)
        self.assertEqual(sorted(list(all_types)), sorted(self.types['result']['types']))

    def test_describeTypes_sane_default_valid_category(self, m):
        sane_default = self.types['result']['sane_defaults']
        categories = self.types['result']['categories']
        for t, sd in sane_default.items():
            self.assertTrue(sd['to_ids'] in [0, 1])
            self.assertTrue(sd['default_category'] in categories)

    def test_flatten_error_messages_singular(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        pymisp.get(1)
        response = self.auth_error_msg
        response['error'] = ['foo', 'bar', 'baz']
        messages = pymisp.flatten_error_messages(response)
        self.assertEqual(["foo", "bar", "baz"], messages)

    def test_flatten_error_messages_plural(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        error = pymisp.get(1)
        self.assertIn("Authentication failed", error["message"])
        response = self.auth_error_msg
        response['errors'] = {'foo': 42, 'bar': False, 'baz': ['oo', 'ka']}
        messages = pymisp.flatten_error_messages(response)
        self.assertEqual(set(['42 (foo)', 'False (bar)', 'oo', 'ka']), set(messages))

    def test_flatten_error_messages_nested(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        error = pymisp.get(1)
        self.assertIn("Authentication failed", error["message"])
        response = self.auth_error_msg
        response['errors'] = {
            'fo': {'o': 42}, 'ba': {'r': True}, 'b': {'a': ['z']}, 'd': {'e': {'e': ['p']}}}
        messages = pymisp.flatten_error_messages(response)
        self.assertEqual(set(['Error in o: 42', 'Error in r: True', 'Error in a: z', "Error in e: {'e': ['p']}"]), set(messages))

    def test_test_connection(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        self.assertTrue(pymisp.test_connection())

    def test_change_toids(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        self.assertEqual({}, pymisp.change_toids(self.key, 1))

    def test_change_toids_invalid(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        try:
            pymisp.change_toids(self.key, 42)
            self.assertFalse('Exception required for off domain value')
        except Exception:
            pass

    def test_proposal_view_default(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        self.assertEqual({}, pymisp.proposal_view())

    def test_proposal_view_event_1(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        self.assertEqual({}, pymisp.proposal_view(event_id=1))

    def test_proposal_view_event_overdetermined(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        self.assertTrue(pymisp.proposal_view(event_id=1, proposal_id=42).get('error') is not None)

    def test_freetext(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        self.assertEqual({}, pymisp.freetext(1, 'foo', adhereToWarninglists=True, distribution=42))

    def test_freetext_offdomain(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        try:
            pymisp.freetext(1, None, adhereToWarninglists='hard')
            self.assertFalse('Exception required for off domain value')
        except Exception:
            pass

    def test_get_yara(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        self.assertEqual((False, None), pymisp.get_yara(1))

    def test_download_samples(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        self.assertEqual((False, None), pymisp.download_samples())

    def test_sample_upload(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        pymisp.upload_sample("tmux", "tests/viper-test-files/test_files/tmux", 1)
        pymisp.upload_sample("tmux", "non_existing_file", 1)
        pymisp.upload_sample("tmux", b"binblob", 1)

    def test_get_all_tags(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        self.assertEqual({'Tag': 'foo'}, pymisp.get_all_tags())

    def test_tag_event(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        uuid = self.event["Event"]["uuid"]
        pymisp.tag(uuid, "foo")

        self.assertRaises(pm.PyMISPError, pymisp.tag, "test_uuid", "foo")
        self.assertRaises(pm.PyMISPError, pymisp.tag, uuid.replace("a", "z"), "foo")

    def test_untag_event(self, m):
        self.initURI(m)
        pymisp = PyMISP(self.domain, self.key)
        uuid = self.event["Event"]["uuid"]
        pymisp.untag(uuid, "foo")


if __name__ == '__main__':
    unittest.main()
