#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

from pymisp import PyMISP
from keys import url, key
import time

import unittest


class TestBasic(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        self.misp = PyMISP(url, key, True, 'json', True)

    def _clean_event(self, event):
        event['Event'].pop('orgc_id', None)
        event['Event'].pop('uuid', None)
        event['Event'].pop('sharing_group_id', None)
        event['Event'].pop('timestamp', None)
        event['Event'].pop('org_id', None)
        event['Event'].pop('date', None)
        event['Event'].pop('RelatedEvent', None)
        event['Event'].pop('publish_timestamp', None)
        if event['Event'].get('Attribute'):
            for a in event['Event'].get('Attribute'):
                a.pop('uuid', None)
                a.pop('event_id', None)
                a.pop('id', None)
                a.pop('timestamp', None)
        if event['Event'].get('Orgc'):
            event['Event']['Orgc'].pop('uuid', None)
            event['Event']['Orgc'].pop('id', None)
        if event['Event'].get('Org'):
            event['Event']['Org'].pop('uuid', None)
            event['Event']['Org'].pop('id', None)
        return event['Event'].pop('id', None)

    def new_event(self):
        event = self.misp.new_event(0, 1, 0, "This is a test")
        event_id = self._clean_event(event)
        to_check = {u'Event': {u'info': u'This is a test', u'locked': False,
                               u'attribute_count': None, 'disable_correlation': False, u'analysis': u'0',
                               u'ShadowAttribute': [], u'published': False,
                               u'distribution': u'0', u'Attribute': [], u'proposal_email_lock': False,
                               u'Org': {u'name': u'ORGNAME'},
                               u'Orgc': {u'name': u'ORGNAME'},
                               u'Galaxy': [],
                               u'threat_level_id': u'1'}}
        print(event)
        self.assertEqual(event, to_check, 'Failed at creating a new Event')
        return int(event_id)

    def add_hashes(self, eventid):
        r = self.misp.get_event(eventid)
        event = r.json()
        event = self.misp.add_hashes(event, 'Payload installation', 'dll_installer.dll', '0a209ac0de4ac033f31d6ba9191a8f7a', '1f0ae54ac3f10d533013f74f48849de4e65817a7', '003315b0aea2fcb9f77d29223dd8947d0e6792b3a0227e054be8eb2a11f443d9', 'Fanny modules', False, 2)
        self._clean_event(event)
        to_check = {u'Event': {u'info': u'This is a test', u'locked': False,
                               u'attribute_count': u'3', u'analysis': u'0',
                               u'ShadowAttribute': [], u'published': False, u'distribution': u'0',
                               u'Org': {u'name': u'ORGNAME'},
                               u'Orgc': {u'name': u'ORGNAME'},
                               u'Galaxy': [],
                               u'Attribute': [
                                   {u'category': u'Payload installation', u'comment': u'Fanny modules',
                                    u'to_ids': False, u'value': u'dll_installer.dll|0a209ac0de4ac033f31d6ba9191a8f7a',
                                    u'ShadowAttribute': [], u'distribution': u'2', u'type': u'filename|md5'},
                                   {u'category': u'Payload installation', u'comment': u'Fanny modules',
                                    u'to_ids': False, u'value': u'dll_installer.dll|1f0ae54ac3f10d533013f74f48849de4e65817a7',
                                    u'ShadowAttribute': [], u'distribution': u'2', u'type': u'filename|sha1'},
                                   {u'category': u'Payload installation', u'comment': u'Fanny modules',
                                    u'to_ids': False, u'value': u'dll_installer.dll|003315b0aea2fcb9f77d29223dd8947d0e6792b3a0227e054be8eb2a11f443d9',
                                    u'ShadowAttribute': [], u'distribution': u'2', u'type': u'filename|sha256'}],
                               u'proposal_email_lock': False, u'threat_level_id': u'1'}}
        self.assertEqual(event, to_check, 'Failed at adding hashes')

    def publish(self, eventid):
        r = self.misp.get_event(eventid)
        event = r.json()
        event = self.misp.publish(event)
        self._clean_event(event)
        to_check = {u'Event': {u'info': u'This is a test', u'locked': False,
                               u'attribute_count': u'3', u'analysis': u'0',
                               u'ShadowAttribute': [], u'published': True, u'distribution': u'0',
                               u'Org': {u'name': u'ORGNAME'},
                               u'Orgc': {u'name': u'ORGNAME'},
                               u'Galaxy': [],
                               u'Attribute': [
                                   {u'category': u'Payload installation', u'comment': u'Fanny modules',
                                    u'to_ids': False, u'value': u'dll_installer.dll|0a209ac0de4ac033f31d6ba9191a8f7a',
                                    u'ShadowAttribute': [], u'distribution': u'2', u'type': u'filename|md5'},
                                   {u'category': u'Payload installation', u'comment': u'Fanny modules',
                                    u'to_ids': False, u'value': u'dll_installer.dll|1f0ae54ac3f10d533013f74f48849de4e65817a7',
                                    u'ShadowAttribute': [], u'distribution': u'2', u'type': u'filename|sha1'},
                                   {u'category': u'Payload installation', u'comment': u'Fanny modules',
                                    u'to_ids': False, u'value': u'dll_installer.dll|003315b0aea2fcb9f77d29223dd8947d0e6792b3a0227e054be8eb2a11f443d9',
                                    u'ShadowAttribute': [], u'distribution': u'2', u'type': u'filename|sha256'}],
                               u'proposal_email_lock': False, u'threat_level_id': u'1'}}
        self.assertEqual(event, to_check, 'Failed at publishing event')

    def delete(self, eventid):
        event = self.misp.delete_event(eventid)
        print(event)

    def delete_attr(self, attrid):
        event = self.misp.delete_attribute(attrid)
        print(event)

    def get(self, eventid):
        event = self.misp.get_event(eventid)
        print(event)

    def get_stix(self, **kwargs):
        event = self.misp.get_stix(kwargs)
        print(event)

    def add(self):
        event = {u'Event': {u'info': u'This is a test', u'locked': False,
                            u'attribute_count': u'3', u'analysis': u'0',
                            u'ShadowAttribute': [], u'published': False, u'distribution': u'0',
                            u'Attribute': [
                                {u'category': u'Payload installation', u'comment': u'Fanny modules',
                                 u'to_ids': False, u'value': u'dll_installer.dll|0a209ac0de4ac033f31d6ba9191a8f7a',
                                 u'ShadowAttribute': [], u'distribution': u'2', u'type': u'filename|md5'},
                                {u'category': u'Payload installation', u'comment': u'Fanny modules',
                                 u'to_ids': False, u'value': u'dll_installer.dll|1f0ae54ac3f10d533013f74f48849de4e65817a7',
                                 u'ShadowAttribute': [], u'distribution': u'2', u'type': u'filename|sha1'},
                                {u'category': u'Payload installation', u'comment': u'Fanny modules',
                                 u'to_ids': False, u'value': u'dll_installer.dll|003315b0aea2fcb9f77d29223dd8947d0e6792b3a0227e054be8eb2a11f443d9',
                                 u'ShadowAttribute': [], u'distribution': u'2', u'type': u'filename|sha256'}],
                            u'proposal_email_lock': False, u'threat_level_id': u'1'}}
        event = self.misp.add_event(event)
        print(event)

    def test_create_event(self):
        eventid = self.new_event()
        time.sleep(1)
        self.delete(eventid)

    def test_get_event(self):
        eventid = self.new_event()
        time.sleep(1)
        self.get(eventid)
        time.sleep(1)
        self.delete(eventid)

    def test_add_event(self):
        self.add()
        time.sleep(1)
        self.delete(1)

    def test_del_attr(self):
        eventid = self.new_event()
        time.sleep(1)
        self.delete_attr(1)
        time.sleep(1)
        self.delete(eventid)

    def test_one_or_more(self):
        self.assertEqual(self.misp._one_or_more(1), (1,))
        self.assertEqual(self.misp._one_or_more([1]), [1])

if __name__ == '__main__':
    unittest.main()
