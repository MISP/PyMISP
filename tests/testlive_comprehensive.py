#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys


import unittest

from pymisp.tools import make_binary_objects
from datetime import datetime, timedelta, date, timezone
from io import BytesIO
import json
from pathlib import Path
import hashlib

import urllib3  # type: ignore
import time
from uuid import uuid4

import email

from collections import defaultdict

import logging
logging.disable(logging.CRITICAL)
logger = logging.getLogger('pymisp')


try:
    from pymisp import register_user, PyMISP, MISPEvent, MISPOrganisation, MISPUser, Distribution, ThreatLevel, Analysis, MISPObject, MISPAttribute, MISPSighting, MISPShadowAttribute, MISPTag, MISPSharingGroup, MISPFeed, MISPServer, MISPUserSetting, MISPEventBlocklist
    from pymisp.tools import CSVLoader, DomainIPObject, ASNObject, GenericObjectGenerator
    from pymisp.exceptions import MISPServerError
except ImportError:
    if sys.version_info < (3, 6):
        print('This test suite requires Python 3.6+, breaking.')
        sys.exit(0)
    else:
        raise

try:
    from keys import url, key  # type: ignore
    verifycert = False
except ImportError as e:
    print(e)
    url = 'https://localhost:8443'
    key = 'd6OmdDFvU3Seau3UjwvHS1y3tFQbaRNhJhDX0tjh'
    verifycert = False


urllib3.disable_warnings()

fast_mode = False


class TestComprehensive(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.maxDiff = None
        # Connect as admin
        cls.admin_misp_connector = PyMISP(url, key, verifycert, debug=False)
        cls.admin_misp_connector.set_server_setting('Security.allow_self_registration', True, force=True)
        cls.admin_misp_connector.set_server_setting('debug', 1, force=True)
        if not fast_mode:
            r = cls.admin_misp_connector.update_misp()
            print(r)
        # Creates an org
        organisation = MISPOrganisation()
        organisation.name = 'Test Org'
        cls.test_org = cls.admin_misp_connector.add_organisation(organisation, pythonify=True)
        # Create an org to delegate to
        organisation = MISPOrganisation()
        organisation.name = 'Test Org - delegate'
        cls.test_org_delegate = cls.admin_misp_connector.add_organisation(organisation, pythonify=True)
        # Set the refault role (id 3 on the VM)
        cls.admin_misp_connector.set_default_role(3)
        # Creates a user
        user = MISPUser()
        user.email = 'testusr@user.local'
        user.org_id = cls.test_org.id
        cls.test_usr = cls.admin_misp_connector.add_user(user, pythonify=True)
        cls.user_misp_connector = PyMISP(url, cls.test_usr.authkey, verifycert, debug=True)
        cls.user_misp_connector.toggle_global_pythonify()
        # Creates a publisher
        user = MISPUser()
        user.email = 'testpub@user.local'
        user.org_id = cls.test_org.id
        user.role_id = 4
        cls.test_pub = cls.admin_misp_connector.add_user(user, pythonify=True)
        cls.pub_misp_connector = PyMISP(url, cls.test_pub.authkey, verifycert)
        # Creates a user that can accept a delegation request
        user = MISPUser()
        user.email = 'testusr@delegate.recipient.local'
        user.org_id = cls.test_org_delegate.id
        user.role_id = 2
        cls.test_usr_delegate = cls.admin_misp_connector.add_user(user, pythonify=True)
        cls.delegate_user_misp_connector = PyMISP(url, cls.test_usr_delegate.authkey, verifycert, debug=False)
        cls.delegate_user_misp_connector.toggle_global_pythonify()
        if not fast_mode:
            # Update all json stuff
            cls.admin_misp_connector.update_object_templates()
            cls.admin_misp_connector.update_galaxies()
            cls.admin_misp_connector.update_noticelists()
            cls.admin_misp_connector.update_warninglists()
            cls.admin_misp_connector.update_taxonomies()
            cls.admin_misp_connector.load_default_feeds()

    @classmethod
    def tearDownClass(cls):
        # Delete publisher
        cls.admin_misp_connector.delete_user(cls.test_pub)
        # Delete user
        cls.admin_misp_connector.delete_user(cls.test_usr)
        cls.admin_misp_connector.delete_user(cls.test_usr_delegate)
        # Delete org
        cls.admin_misp_connector.delete_organisation(cls.test_org)
        cls.admin_misp_connector.delete_organisation(cls.test_org_delegate)

    def create_simple_event(self, force_timestamps=False):
        mispevent = MISPEvent(force_timestamps=force_timestamps)
        mispevent.info = 'This is a super simple test'
        mispevent.distribution = Distribution.your_organisation_only
        mispevent.threat_level_id = ThreatLevel.low
        mispevent.analysis = Analysis.completed
        mispevent.add_attribute('text', str(uuid4()))
        return mispevent

    def environment(self):
        first_event = MISPEvent()
        first_event.info = 'First event - org only - low - completed'
        first_event.distribution = Distribution.your_organisation_only
        first_event.threat_level_id = ThreatLevel.low
        first_event.analysis = Analysis.completed
        first_event.set_date("2017-12-31")
        first_event.add_attribute('text', 'FIRST_EVENT' + str(uuid4()))
        first_event.attributes[0].add_tag('admin_only')
        first_event.attributes[0].add_tag('tlp:white___test')
        first_event.add_attribute('text', str(uuid4()))
        first_event.attributes[1].add_tag('unique___test')

        second_event = MISPEvent()
        second_event.info = 'Second event - org only - medium - ongoing'
        second_event.distribution = Distribution.your_organisation_only
        second_event.threat_level_id = ThreatLevel.medium
        second_event.analysis = Analysis.ongoing
        second_event.set_date("Aug 18 2018")
        second_event.add_attribute('text', 'SECOND_EVENT' + str(uuid4()))
        second_event.attributes[0].add_tag('tlp:white___test')
        second_event.add_attribute('ip-dst', '1.1.1.1')
        second_event.attributes[1].add_tag('tlp:amber___test')
        # Same value as in first event.
        second_event.add_attribute('text', first_event.attributes[0].value)

        third_event = MISPEvent()
        third_event.info = 'Third event - all orgs - high - initial'
        third_event.distribution = Distribution.all_communities
        third_event.threat_level_id = ThreatLevel.high
        third_event.analysis = Analysis.initial
        third_event.set_date("Jun 25 2018")
        third_event.add_tag('tlp:white___test')
        third_event.add_attribute('text', 'THIRD_EVENT' + str(uuid4()))
        third_event.attributes[0].add_tag('tlp:amber___test')
        third_event.attributes[0].add_tag('foo_double___test')
        third_event.add_attribute('ip-src', '8.8.8.8')
        third_event.attributes[1].add_tag('tlp:amber___test')
        third_event.add_attribute('ip-dst', '9.9.9.9')

        # Create first and third event as admin
        # usr won't be able to see the first one
        first = self.admin_misp_connector.add_event(first_event, pythonify=True)
        third = self.admin_misp_connector.add_event(third_event, pythonify=True)
        # Create second event as user
        second = self.user_misp_connector.add_event(second_event)
        return first, second, third

    def test_server_settings(self):
        settings = self.admin_misp_connector.server_settings()
        for final_setting in settings['finalSettings']:
            if final_setting['setting'] == 'MISP.max_correlations_per_event':
                self.assertEqual(final_setting['value'], 5000)
                break
        r = self.admin_misp_connector.set_server_setting('MISP.max_correlations_per_event', 10)
        self.assertEqual(r['message'], 'Field updated', r)

        setting = self.admin_misp_connector.get_server_setting('MISP.max_correlations_per_event')
        self.assertEqual(setting['value'], 10)
        r = self.admin_misp_connector.set_server_setting('MISP.max_correlations_per_event', 5000)
        self.assertEqual(r['message'], 'Field updated', r)

        setting = self.admin_misp_connector.get_server_setting('MISP.live')
        self.assertTrue(setting['value'])
        r = self.admin_misp_connector.set_server_setting('MISP.live', False, force=True)
        self.assertEqual(r['message'], 'Field updated', r)
        setting = self.admin_misp_connector.get_server_setting('MISP.live')
        self.assertFalse(setting['value'])
        r = self.admin_misp_connector.set_server_setting('MISP.live', True, force=True)
        self.assertEqual(r['message'], 'Field updated', r)
        setting = self.admin_misp_connector.get_server_setting('MISP.live')
        self.assertTrue(setting['value'])

    def test_search_value_event(self):
        '''Search a value on the event controller
        * Test ACL admin user vs normal user in an other org
        * Make sure we have one match
        '''
        try:
            first, second, third = self.environment()
            # Search as admin
            events = self.admin_misp_connector.search(value=first.attributes[0].value, pythonify=True)
            self.assertEqual(len(events), 2)
            for e in events:
                self.assertIn(e.id, [first.id, second.id])
            # Search as user
            events = self.user_misp_connector.search(value=first.attributes[0].value)
            self.assertEqual(len(events), 1)
            for e in events:
                self.assertIn(e.id, [second.id])
            # Non-existing value
            events = self.user_misp_connector.search(value=str(uuid4()))
            self.assertEqual(events, [])
        finally:
            # Delete events
            self.admin_misp_connector.delete_event(first)
            self.admin_misp_connector.delete_event(second)
            self.admin_misp_connector.delete_event(third)

    def test_search_value_attribute(self):
        '''Search value in attributes controller'''
        try:
            first, second, third = self.environment()
            # Search as admin
            attributes = self.admin_misp_connector.search(controller='attributes', value=first.attributes[0].value, pythonify=True)
            self.assertEqual(len(attributes), 2)
            for a in attributes:
                self.assertIn(a.event_id, [first.id, second.id])
            # Search as user
            attributes = self.user_misp_connector.search(controller='attributes', value=first.attributes[0].value)
            self.assertEqual(len(attributes), 1)
            for a in attributes:
                self.assertIn(a.event_id, [second.id])
            # Non-existing value
            attributes = self.user_misp_connector.search(controller='attributes', value=str(uuid4()))
            self.assertEqual(attributes, [])

            # Include context - search as user (can only see one event)
            attributes = self.user_misp_connector.search(controller='attributes', value=first.attributes[0].value, include_context=True, pythonify=True)
            self.assertTrue(isinstance(attributes[0].Event, MISPEvent))
            self.assertEqual(attributes[0].Event.uuid, second.uuid)

            # Include context - search as admin (can see both event)
            attributes = self.admin_misp_connector.search(controller='attributes', value=first.attributes[0].value, include_context=True, pythonify=True)
            self.assertTrue(isinstance(attributes[0].Event, MISPEvent))
            self.assertEqual(attributes[0].Event.uuid, first.uuid)
            self.assertEqual(attributes[1].Event.uuid, second.uuid)

            # Include correlations - search as admin (can see both event)
            attributes = self.admin_misp_connector.search(controller='attributes', value=first.attributes[0].value, include_correlations=True, pythonify=True)
            self.assertTrue(isinstance(attributes[0].Event, MISPEvent))
            self.assertEqual(attributes[0].Event.uuid, first.uuid)
            self.assertEqual(attributes[1].Event.uuid, second.uuid)
            self.assertEqual(attributes[0].RelatedAttribute[0].Event.uuid, second.uuid)
            self.assertEqual(attributes[1].RelatedAttribute[0].Event.uuid, first.uuid)

            # Include sightings - search as admin (can see both event)
            self.admin_misp_connector.add_sighting({'value': first.attributes[0].value})
            attributes = self.admin_misp_connector.search(controller='attributes', value=first.attributes[0].value, include_sightings=True, pythonify=True)
            self.assertTrue(isinstance(attributes[0].Event, MISPEvent))
            self.assertEqual(attributes[0].Event.uuid, first.uuid)
            self.assertEqual(attributes[1].Event.uuid, second.uuid)
            self.assertTrue(isinstance(attributes[0].Sighting[0], MISPSighting))

        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)
            self.admin_misp_connector.delete_event(second)
            self.admin_misp_connector.delete_event(third)

    def test_search_type_event(self):
        '''Search multiple events, search events containing attributes with specific types'''
        try:
            first, second, third = self.environment()
            # Search as admin
            events = self.admin_misp_connector.search(timestamp=first.timestamp.timestamp(), pythonify=True)
            self.assertEqual(len(events), 3)
            for e in events:
                self.assertIn(e.id, [first.id, second.id, third.id])
            attributes_types_search = self.admin_misp_connector.build_complex_query(or_parameters=['ip-src', 'ip-dst'])
            events = self.admin_misp_connector.search(timestamp=first.timestamp.timestamp(),
                                                      type_attribute=attributes_types_search, pythonify=True)
            self.assertEqual(len(events), 2)
            for e in events:
                self.assertIn(e.id, [second.id, third.id])
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)
            self.admin_misp_connector.delete_event(second)
            self.admin_misp_connector.delete_event(third)

    def test_search_objects(self):
        '''Search for objects'''
        try:
            first = self.create_simple_event()
            obj = MISPObject('file')
            obj.add_attribute('filename', 'foo')
            first.add_object(obj)
            first = self.user_misp_connector.add_event(first)
            logger = logging.getLogger('pymisp')
            logger.setLevel(logging.DEBUG)
            objects = self.user_misp_connector.search(controller='objects',
                                                      object_name='file', pythonify=True)
            self.assertEqual(len(objects), 1)
            self.assertEqual(objects[0].attributes[0].value, 'foo')
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)

    def test_search_type_attribute(self):
        '''Search multiple attributes, search attributes with specific types'''
        try:
            first, second, third = self.environment()
            # Search as admin
            attributes = self.admin_misp_connector.search(controller='attributes',
                                                          timestamp=first.timestamp.timestamp(), pythonify=True)
            self.assertEqual(len(attributes), 8)
            for a in attributes:
                self.assertIn(a.event_id, [first.id, second.id, third.id])
            # Search as user
            attributes_types_search = self.admin_misp_connector.build_complex_query(or_parameters=['ip-src', 'ip-dst'])
            attributes = self.admin_misp_connector.search(controller='attributes',
                                                          timestamp=first.timestamp.timestamp(),
                                                          type_attribute=attributes_types_search, pythonify=True)
            self.assertEqual(len(attributes), 3)
            for a in attributes:
                self.assertIn(a.event_id, [second.id, third.id])
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)
            self.admin_misp_connector.delete_event(second)
            self.admin_misp_connector.delete_event(third)

    def test_search_tag_event(self):
        '''Search Tags at events level'''
        try:
            first, second, third = self.environment()
            # Search as admin
            events = self.admin_misp_connector.search(tags='tlp:white___test', pythonify=True)
            self.assertEqual(len(events), 3)
            for e in events:
                self.assertIn(e.id, [first.id, second.id, third.id])
            events = self.admin_misp_connector.search(tags='tlp:amber___test', pythonify=True)
            self.assertEqual(len(events), 2)
            for e in events:
                self.assertIn(e.id, [second.id, third.id])
            events = self.admin_misp_connector.search(tags='admin_only', pythonify=True)
            self.assertEqual(len(events), 1)
            for e in events:
                self.assertIn(e.id, [first.id])
            # Search as user
            events = self.user_misp_connector.search(tags='tlp:white___test')
            self.assertEqual(len(events), 2)
            for e in events:
                self.assertIn(e.id, [second.id, third.id])
            events = self.user_misp_connector.search(tags='tlp:amber___test')
            self.assertEqual(len(events), 2)
            for e in events:
                self.assertIn(e.id, [second.id, third.id])
            events = self.user_misp_connector.search(tags='admin_only')
            self.assertEqual(events, [])
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)
            self.admin_misp_connector.delete_event(second)
            self.admin_misp_connector.delete_event(third)

    def test_search_tag_attribute(self):
        '''Search Tags at attributes level'''
        try:
            first, second, third = self.environment()
            # Search as admin
            attributes = self.admin_misp_connector.search(controller='attributes', tags='tlp:white___test', pythonify=True)
            self.assertEqual(len(attributes), 5)
            attributes = self.admin_misp_connector.search(controller='attributes', tags='tlp:amber___test', pythonify=True)
            self.assertEqual(len(attributes), 3)
            attributes = self.admin_misp_connector.search(tags='admin_only', pythonify=True)
            self.assertEqual(len(attributes), 1)
            # Search as user
            attributes = self.user_misp_connector.search(controller='attributes', tags='tlp:white___test')
            self.assertEqual(len(attributes), 4)
            attributes = self.user_misp_connector.search(controller='attributes', tags='tlp:amber___test')
            self.assertEqual(len(attributes), 3)
            attributes = self.user_misp_connector.search(tags='admin_only')
            self.assertEqual(attributes, [])
            attributes_tags_search = self.admin_misp_connector.build_complex_query(or_parameters=['tlp:amber___test'], not_parameters=['tlp:white___test'])
            attributes = self.user_misp_connector.search(controller='attributes', tags=attributes_tags_search)
            self.assertEqual(len(attributes), 1)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)
            self.admin_misp_connector.delete_event(second)
            self.admin_misp_connector.delete_event(third)

    def test_search_tag_advanced_event(self):
        '''Advanced search Tags at events level'''
        try:
            first, second, third = self.environment()
            complex_query = self.admin_misp_connector.build_complex_query(or_parameters=['tlp:white___test'],
                                                                          not_parameters=['tlp:amber___test',
                                                                                          'foo_double___test'])
            events = self.admin_misp_connector.search(tags=complex_query, pythonify=True)
            self.assertEqual(len(events), 3)
            for e in events:
                self.assertIn(e.id, [first.id, second.id, third.id])
                for a in e.attributes:
                    self.assertEqual([t for t in a.tags if t.name == 'tlp:amber___test'], [])
                for a in e.attributes:
                    self.assertEqual([t for t in a.tags if t.name == 'foo_double___test'], [])

            complex_query = self.admin_misp_connector.build_complex_query(or_parameters=['unique___test'],
                                                                          not_parameters=['tlp:white___test'])
            events = self.admin_misp_connector.search(tags=complex_query, pythonify=True)
            self.assertEqual(len(events), 1)
            for e in events:
                self.assertIn(e.id, [first.id, second.id])
                for a in e.attributes:
                    self.assertEqual([t for t in a.tags if t.name == 'tlp:white___test'], [])
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)
            self.admin_misp_connector.delete_event(second)
            self.admin_misp_connector.delete_event(third)

    def test_search_tag_advanced_attributes(self):
        '''Advanced search Tags at attributes level'''
        try:
            first, second, third = self.environment()
            complex_query = self.admin_misp_connector.build_complex_query(or_parameters=['tlp:white___test'],
                                                                          not_parameters=['tlp:amber___test',
                                                                                          'foo_double___test'])
            attributes = self.admin_misp_connector.search(controller='attributes', tags=complex_query, pythonify=True)
            self.assertEqual(len(attributes), 3)
            for a in attributes:
                self.assertEqual([t for t in a.tags if t.name == 'tlp:amber___test'], [])
            for a in attributes:
                self.assertEqual([t for t in a.tags if t.name == 'foo_double___test'], [])
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)
            self.admin_misp_connector.delete_event(second)
            self.admin_misp_connector.delete_event(third)

    def test_search_timestamp_event(self):
        '''Search specific update timestamps at events level'''
        # Creating event 1 - timestamp 5 min ago
        first = self.create_simple_event(force_timestamps=True)
        event_creation_timestamp_first = datetime.now() - timedelta(minutes=5)
        first.timestamp = event_creation_timestamp_first
        # Creating event 2 - timestamp 2 min ago
        second = self.create_simple_event(force_timestamps=True)
        event_creation_timestamp_second = datetime.now() - timedelta(minutes=2)
        second.timestamp = event_creation_timestamp_second
        try:
            first = self.user_misp_connector.add_event(first)
            second = self.user_misp_connector.add_event(second)
            # Search as user
            # # Test - last 4 min
            events = self.user_misp_connector.search(timestamp='4m')
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, second.id)
            self.assertEqual(events[0].timestamp.timestamp(), int(event_creation_timestamp_second.timestamp()))

            # # Test timestamp of 2nd event
            events = self.user_misp_connector.search(timestamp=event_creation_timestamp_second.timestamp())
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, second.id)
            self.assertEqual(events[0].timestamp.timestamp(), int(event_creation_timestamp_second.timestamp()))

            # # Test interval -6 min -> -4 min
            events = self.user_misp_connector.search(timestamp=['6m', '4m'])
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, first.id)
            self.assertEqual(events[0].timestamp.timestamp(), int(event_creation_timestamp_first.timestamp()))
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)
            self.admin_misp_connector.delete_event(second)

    def test_search_timestamp_attribute(self):
        '''Search specific update timestamps at attributes level'''
        # Creating event 1 - timestamp 5 min ago
        first = self.create_simple_event(force_timestamps=True)
        event_creation_timestamp_first = datetime.now() - timedelta(minutes=5)
        first.timestamp = event_creation_timestamp_first
        first.attributes[0].timestamp = event_creation_timestamp_first
        # Creating event 2 - timestamp 2 min ago
        second = self.create_simple_event(force_timestamps=True)
        event_creation_timestamp_second = datetime.now() - timedelta(minutes=2)
        second.timestamp = event_creation_timestamp_second
        second.attributes[0].timestamp = event_creation_timestamp_second
        try:
            first = self.user_misp_connector.add_event(first)
            second = self.user_misp_connector.add_event(second)
            # Search as user
            # # Test - last 4 min
            attributes = self.user_misp_connector.search(controller='attributes', timestamp='4m')
            self.assertEqual(len(attributes), 1)
            self.assertEqual(attributes[0].event_id, second.id)
            self.assertEqual(attributes[0].timestamp.timestamp(), int(event_creation_timestamp_second.timestamp()))

            # # Test timestamp of 2nd event
            attributes = self.user_misp_connector.search(controller='attributes', timestamp=event_creation_timestamp_second.timestamp())
            self.assertEqual(len(attributes), 1)
            self.assertEqual(attributes[0].event_id, second.id)
            self.assertEqual(attributes[0].timestamp.timestamp(), int(event_creation_timestamp_second.timestamp()))

            # # Test interval -6 min -> -4 min
            attributes = self.user_misp_connector.search(controller='attributes', timestamp=['6m', '4m'])
            self.assertEqual(len(attributes), 1)
            self.assertEqual(attributes[0].event_id, first.id)
            self.assertEqual(attributes[0].timestamp.timestamp(), int(event_creation_timestamp_first.timestamp()))
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)
            self.admin_misp_connector.delete_event(second)

    def test_user_perms(self):
        '''Test publish rights'''
        try:
            first = self.create_simple_event()
            first.publish()
            # Add event as user, no publish rights
            first = self.user_misp_connector.add_event(first)
            self.assertFalse(first.published)
            # Add event as publisher
            first.publish()
            first = self.pub_misp_connector.update_event(first, pythonify=True)
            self.assertTrue(first.published)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)

    def test_delete_with_update(self):
        try:
            first = self.create_simple_event()
            obj = MISPObject('file')
            obj.add_attribute('filename', 'foo')
            first.add_object(obj)
            first = self.user_misp_connector.add_event(first)

            first.attributes[0].deleted = True
            deleted_attribute = self.user_misp_connector.update_attribute(first.attributes[0], pythonify=True)
            self.assertTrue(deleted_attribute.deleted)

            first.objects[0].deleted = True
            deleted_object = self.user_misp_connector.update_object(first.objects[0], pythonify=True)
            self.assertTrue(deleted_object.deleted)

            # Get event with deleted entries
            first = self.user_misp_connector.get_event(first, deleted=True, pythonify=True)
            self.assertTrue(first.attributes[0].deleted)
            self.assertTrue(first.objects[0].deleted)

        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)

    def test_get_non_exists_event(self):
        event = self.user_misp_connector.get_event(0)  # non exists id
        self.assertEqual(event['errors'][0], 404)

        event = self.user_misp_connector.get_event("ab2b6e28-fda5-4282-bf60-22b81de77851")  # non exists uuid
        self.assertEqual(event['errors'][0], 404)

    def test_delete_by_uuid(self):
        try:
            first = self.create_simple_event()
            obj = MISPObject('file')
            obj.add_attribute('filename', 'foo')
            first.add_object(obj)
            obj = MISPObject('file')
            obj.add_attribute('filename', 'bar')
            first.add_object(obj)
            first = self.user_misp_connector.add_event(first)
            r = self.user_misp_connector.delete_attribute(first.attributes[0].uuid)
            self.assertEqual(r['message'], 'Attribute deleted.')
            r = self.user_misp_connector.delete_object(first.objects[0].uuid)
            self.assertEqual(r['message'], 'Object deleted')
            # Test deleted search
            r = self.user_misp_connector.search(event_id=first.id, deleted=[0, 1], pythonify=True)
            self.assertTrue(isinstance(r[0], MISPEvent))
            self.assertEqual(len(r[0].objects), 2)
            self.assertTrue(r[0].objects[0].deleted)
            self.assertFalse(r[0].objects[1].deleted)
            self.assertEqual(len(r[0].attributes), 1)
            self.assertTrue(r[0].attributes[0].deleted)
            # Test deleted get
            r = self.user_misp_connector.get_event(first, deleted=True, pythonify=True)
            self.assertTrue(isinstance(r, MISPEvent))
            self.assertEqual(len(r.objects), 2)
            self.assertTrue(r.objects[0].deleted)
            self.assertFalse(r.objects[1].deleted)
            self.assertEqual(len(r.attributes), 1)
            self.assertTrue(r.attributes[0].deleted)

            r = self.user_misp_connector.delete_event(first.uuid)
            self.assertEqual(r['message'], 'Event deleted.')
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)

    def test_search_publish_timestamp(self):
        '''Search for a specific publication timestamp, an interval, and invalid values.'''
        # Creating event 1
        first = self.create_simple_event()
        first.publish()
        # Creating event 2
        second = self.create_simple_event()
        second.publish()
        try:
            first = self.pub_misp_connector.add_event(first, pythonify=True)
            time.sleep(10)
            second = self.pub_misp_connector.add_event(second, pythonify=True)
            # Test invalid query
            events = self.pub_misp_connector.search(publish_timestamp='5x', pythonify=True)
            self.assertEqual(events, [])
            events = self.pub_misp_connector.search(publish_timestamp='ad', pythonify=True)
            self.assertEqual(events, [])
            events = self.pub_misp_connector.search(publish_timestamp='aaad', pythonify=True)
            self.assertEqual(events, [])
            # Test - last 4 min
            events = self.pub_misp_connector.search(publish_timestamp='5s', pythonify=True)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, second.id)

            # Test 5 sec before timestamp of 2nd event
            events = self.pub_misp_connector.search(publish_timestamp=(second.publish_timestamp.timestamp()), pythonify=True)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, second.id)

            # Test interval -6 min -> -4 min
            events = self.pub_misp_connector.search(publish_timestamp=[first.publish_timestamp.timestamp() - 5,
                                                                       second.publish_timestamp.timestamp() - 5], pythonify=True)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, first.id)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)
            self.admin_misp_connector.delete_event(second)

    def test_default_distribution(self):
        '''The default distributions on the VM are This community only for the events and Inherit from event for attr/obj)'''
        first = self.create_simple_event()
        del first.distribution
        o = first.add_object(name='file')
        o.add_attribute('filename', value='foo.exe')
        try:
            # Event create
            first = self.user_misp_connector.add_event(first)
            self.assertEqual(first.distribution, Distribution.this_community_only.value)
            self.assertEqual(first.attributes[0].distribution, Distribution.inherit.value)
            self.assertEqual(first.objects[0].distribution, Distribution.inherit.value)
            self.assertEqual(first.objects[0].attributes[0].distribution, Distribution.inherit.value)
            # Event edit
            first.add_attribute('ip-dst', '12.54.76.43')
            o = first.add_object(name='file')
            o.add_attribute('filename', value='foo2.exe')
            first = self.user_misp_connector.update_event(first)
            self.assertEqual(first.attributes[1].distribution, Distribution.inherit.value)
            self.assertEqual(first.objects[1].distribution, Distribution.inherit.value)
            self.assertEqual(first.objects[1].attributes[0].distribution, Distribution.inherit.value)
            # Attribute create
            attribute = self.user_misp_connector.add_attribute(first, {'type': 'comment', 'value': 'bar'})
            self.assertEqual(attribute.value, 'bar', attribute.to_json())
            self.assertEqual(attribute.distribution, Distribution.inherit.value, attribute.to_json())
            # Object - add
            o = MISPObject('file')
            o.add_attribute('filename', value='blah.exe')
            new_obj = self.user_misp_connector.add_object(first, o)
            self.assertEqual(new_obj.distribution, int(Distribution.inherit.value))
            self.assertEqual(new_obj.attributes[0].distribution, int(Distribution.inherit.value))
            # Object - edit
            clean_obj = MISPObject(name=new_obj.name, strict=True)
            clean_obj.from_dict(**new_obj)
            clean_obj.add_attribute('filename', value='blah.exe')
            new_obj = self.user_misp_connector.update_object(clean_obj)
            for a in new_obj.attributes:
                self.assertEqual(a.distribution, int(Distribution.inherit.value))
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)

    def test_exists(self):
        """Check event, attribute and object existence"""
        event = self.create_simple_event()
        misp_object = MISPObject('domain-ip')
        attribute = misp_object.add_attribute('domain', value='google.fr')
        misp_object.add_attribute('ip', value='8.8.8.8')
        event.add_object(misp_object)

        # Event, attribute and object should not exists before event deletion
        self.assertFalse(self.user_misp_connector.event_exists(event))
        self.assertFalse(self.user_misp_connector.attribute_exists(attribute))
        self.assertFalse(self.user_misp_connector.object_exists(misp_object))

        try:
            event = self.user_misp_connector.add_event(event, pythonify=True)
            misp_object = event.objects[0]
            attribute = misp_object.attributes[0]
            self.assertTrue(self.user_misp_connector.event_exists(event))
            self.assertTrue(self.user_misp_connector.event_exists(event.uuid))
            self.assertTrue(self.user_misp_connector.event_exists(event.id))
            self.assertTrue(self.user_misp_connector.attribute_exists(attribute))
            self.assertTrue(self.user_misp_connector.attribute_exists(attribute.uuid))
            self.assertTrue(self.user_misp_connector.attribute_exists(attribute.id))
            self.assertTrue(self.user_misp_connector.object_exists(misp_object))
            self.assertTrue(self.user_misp_connector.object_exists(misp_object.id))
            self.assertTrue(self.user_misp_connector.object_exists(misp_object.uuid))
        finally:
            self.admin_misp_connector.delete_event(event)

        # Event, attribute and object should not exists after event deletion
        self.assertFalse(self.user_misp_connector.event_exists(event))
        self.assertFalse(self.user_misp_connector.event_exists(event.id))
        self.assertFalse(self.user_misp_connector.attribute_exists(attribute))
        self.assertFalse(self.user_misp_connector.attribute_exists(attribute.id))
        self.assertFalse(self.user_misp_connector.object_exists(misp_object))
        self.assertFalse(self.user_misp_connector.object_exists(misp_object.id))

    def test_simple_event(self):
        '''Search a bunch of parameters:
            * Value not existing
            * only return metadata
            * published yes/no
            * event id
            * uuid
            * creator org
            * substring search in value and eventinfo
            * quickfilter
            * date_from
            * date_to
            * deleted
            * to_ids
            * include_event_uuid
        warning list
        '''
        first = self.create_simple_event()
        first.info = 'foo bar blah'
        # First has one text attribute
        second = self.create_simple_event()
        second.info = 'foo blah'
        second.add_tag('tlp:amber___test')
        second.set_date('2018-09-01')
        second.add_attribute('ip-src', '8.8.8.8')
        # second has two attributes: text and ip-src
        try:
            first = self.user_misp_connector.add_event(first)
            second = self.user_misp_connector.add_event(second)
            timeframe = [first.timestamp.timestamp() - 5, first.timestamp.timestamp() + 5]
            # Search event we just created in multiple ways. Make sure it doesn't catch it when it shouldn't
            events = self.user_misp_connector.search(timestamp=timeframe)
            self.assertEqual(len(events), 2)
            self.assertEqual(events[0].id, first.id)
            self.assertEqual(events[1].id, second.id)
            events = self.user_misp_connector.search(timestamp=timeframe, value='nothere')
            self.assertEqual(events, [])
            events = self.user_misp_connector.search(timestamp=timeframe, value=first.attributes[0].value)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, first.id)
            events = self.user_misp_connector.search(timestamp=[first.timestamp.timestamp() - 50,
                                                                first.timestamp.timestamp() - 10],
                                                     value=first.attributes[0].value, pythonify=True)
            self.assertEqual(events, [])

            # Test return content
            events = self.user_misp_connector.search(timestamp=timeframe, metadata=False)
            self.assertEqual(len(events), 2)
            self.assertEqual(len(events[0].attributes), 1)
            self.assertEqual(len(events[1].attributes), 2)
            events = self.user_misp_connector.search(timestamp=timeframe, metadata=True)
            self.assertEqual(len(events), 2)
            self.assertEqual(len(events[0].attributes), 0)
            self.assertEqual(len(events[1].attributes), 0)

            # other things
            events = self.user_misp_connector.search(timestamp=timeframe, published=True)
            self.assertEqual(events, [])
            events = self.user_misp_connector.search(timestamp=timeframe, published=False)
            self.assertEqual(len(events), 2)
            events = self.user_misp_connector.search(eventid=first.id)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, first.id)
            events = self.user_misp_connector.search(uuid=first.uuid)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, first.id)
            events = self.user_misp_connector.search(org=first.orgc_id)
            self.assertEqual(len(events), 2)

            # test like search
            events = self.user_misp_connector.search(timestamp=timeframe, value='%{}%'.format(first.attributes[0].value.split('-')[2]))
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, first.id)
            events = self.user_misp_connector.search(timestamp=timeframe, eventinfo='%bar blah%')
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, first.id)

            # quickfilter
            events = self.user_misp_connector.search(timestamp=timeframe,
                                                     quickfilter='%foo blah%', pythonify=True)
            # FIXME: should return one event
            # print(events)
            # self.assertEqual(len(events), 1)
            # self.assertEqual(events[0].id, second.id)

            # date_from / date_to
            events = self.user_misp_connector.search(timestamp=timeframe, date_from=date.today().isoformat())
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, first.id)
            events = self.user_misp_connector.search(timestamp=timeframe, date_from='2018-09-01')
            self.assertEqual(len(events), 2)
            events = self.user_misp_connector.search(timestamp=timeframe, date_from='2018-09-01', date_to='2018-09-02')
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, second.id)

            # Category
            events = self.user_misp_connector.search(timestamp=timeframe, category='Network activity')
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, second.id)

            # toids
            events = self.user_misp_connector.search(timestamp=timeframe, to_ids='0')
            self.assertEqual(len(events), 2)
            events = self.user_misp_connector.search(timestamp=timeframe, to_ids='1')
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, second.id)
            self.assertEqual(len(events[0].attributes), 1)

            # deleted
            second.attributes[1].delete()
            self.user_misp_connector.update_event(second)
            events = self.user_misp_connector.search(eventid=second.id)
            self.assertEqual(len(events[0].attributes), 1)
            events = self.user_misp_connector.search(eventid=second.id, deleted=True)
            self.assertEqual(len(events[0].attributes), 1)

            # include_event_uuid
            attributes = self.user_misp_connector.search(controller='attributes', eventid=second.id, include_event_uuid=True)
            self.assertEqual(attributes[0].event_uuid, second.uuid)
            # include_event_tags
            attributes = self.user_misp_connector.search(controller='attributes', eventid=second.id, include_event_tags=True)
            self.assertEqual(attributes[0].tags[0].name, 'tlp:amber___test')

            # event_timestamp
            time.sleep(1)
            second.add_attribute('ip-src', '8.8.8.9')
            second = self.user_misp_connector.update_event(second)
            events = self.user_misp_connector.search(event_timestamp=second.timestamp.timestamp())
            self.assertEqual(len(events), 1)

            # searchall
            second.add_attribute('text', 'This is a test for the full text search', comment='Test stuff comment')
            second = self.user_misp_connector.update_event(second)
            events = self.user_misp_connector.search(value='%for the full text%', searchall=True)
            self.assertEqual(len(events), 1)

            # warninglist
            response = self.admin_misp_connector.toggle_warninglist(warninglist_name='%dns resolv%', force_enable=True)  # enable ipv4 DNS.
            self.assertDictEqual(response, {'saved': True, 'success': '3 warninglist(s) enabled'})
            second.add_attribute('ip-src', '1.11.71.4')
            second.add_attribute('ip-src', '9.9.9.9')
            second = self.user_misp_connector.update_event(second)

            events = self.user_misp_connector.search(eventid=second.id)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, second.id)
            self.assertEqual(len(events[0].attributes), 5)

            events = self.user_misp_connector.search(eventid=second.id, enforce_warninglist=False)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, second.id)
            self.assertEqual(len(events[0].attributes), 5)

            events = self.user_misp_connector.search(eventid=second.id, enforce_warninglist=True)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, second.id)
            self.assertEqual(len(events[0].attributes), 4)
            response = self.admin_misp_connector.toggle_warninglist(warninglist_name='%dns resolv%')  # disable ipv4 DNS.
            self.assertDictEqual(response, {'saved': True, 'success': '3 warninglist(s) toggled'})

            # Page / limit
            attributes = self.user_misp_connector.search(controller='attributes', eventid=second.id, page=1, limit=3)
            self.assertEqual(len(attributes), 3)

            attributes = self.user_misp_connector.search(controller='attributes', eventid=second.id, page=2, limit=3)
            self.assertEqual(len(attributes), 2)

            time.sleep(1)  # make sure the next attribute is added one at least one second later

            # attachments
            with open('tests/testlive_comprehensive.py', 'rb') as f:
                first.add_attribute('malware-sample', value='testfile.py', data=BytesIO(f.read()))

            first = self.user_misp_connector.update_event(first)
            events = self.user_misp_connector.search(timestamp=first.timestamp.timestamp(), with_attachments=True,
                                                     pythonify=True)
            self.assertEqual(len(events), 1)
            self.assertIs(type(events[0].attributes[-1].malware_binary), BytesIO)
            events = self.user_misp_connector.search(timestamp=first.timestamp.timestamp(), with_attachments=False,
                                                     pythonify=True)
            self.assertEqual(len(events), 1)
            self.assertIs(events[0].attributes[-1].malware_binary, None)

            # Search index
            # # Timestamp
            events = self.user_misp_connector.search_index(timestamp=first.timestamp.timestamp(),
                                                           pythonify=True)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].info, 'foo bar blah')
            self.assertEqual(events[0].attributes, [])

            # # Info
            complex_info = r'C:\Windows\System32\notepad.exe'
            e = events[0]
            e.info = complex_info
            e = self.user_misp_connector.update_event(e, pythonify=True)
            # Issue: https://github.com/MISP/MISP/issues/6616
            complex_info_search = r'C:\\Windows\\System32\\notepad.exe'
            events = self.user_misp_connector.search_index(eventinfo=complex_info_search,
                                                           pythonify=True)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].info, complex_info)
            self.assertEqual(events[0].attributes, [])

            # Contact reporter
            r = self.user_misp_connector.contact_event_reporter(events[0].id, 'This is a test')
            self.assertEqual(r['message'], 'Email sent to the reporter.')
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)
            self.admin_misp_connector.delete_event(second)

    def test_event_add_update_metadata(self):
        event = self.create_simple_event()
        event.add_attribute('ip-src', '9.9.9.9')
        try:
            response = self.user_misp_connector.add_event(event, metadata=True)
            self.assertEqual(len(response.attributes), 0)  # response should contains zero attributes

            event.info = "New name"
            response = self.user_misp_connector.update_event(event, metadata=True)
            self.assertEqual(len(response.attributes), 0)  # response should contains zero attributes
        finally:  # cleanup
            self.admin_misp_connector.delete_event(event)

    def test_extend_event(self):
        first = self.create_simple_event()
        first.info = 'parent event'
        first.add_tag('tlp:amber___test')
        first.set_date('2018-09-01')
        second = self.create_simple_event()
        second.info = 'event extension'
        second.add_tag('tlp:amber___test')
        second.set_date('2018-09-01')
        second.add_attribute('ip-src', '9.9.9.9')
        try:
            first = self.user_misp_connector.add_event(first)
            second = self.user_misp_connector.add_event(second)
            first_extended = self.user_misp_connector.update_event({'extends_uuid': second.uuid}, event_id=first, pythonify=True)
            self.assertTrue(isinstance(first_extended, MISPEvent), first_extended)
            self.assertEqual(first_extended.extends_uuid, second.uuid)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)
            self.admin_misp_connector.delete_event(second)

    def test_edit_attribute(self):
        first = self.create_simple_event()
        try:
            first.attributes[0].comment = 'This is the original comment'
            first = self.user_misp_connector.add_event(first)
            first.attributes[0].comment = 'This is the modified comment'
            attribute = self.user_misp_connector.update_attribute(first.attributes[0])
            self.assertTrue(isinstance(attribute, MISPAttribute), attribute)
            self.assertEqual(attribute.comment, 'This is the modified comment')
            attribute = self.user_misp_connector.update_attribute({'comment': 'This is the modified comment, again'}, attribute)
            self.assertTrue(isinstance(attribute, MISPAttribute), attribute)
            self.assertEqual(attribute.comment, 'This is the modified comment, again', attribute)
            attribute = self.user_misp_connector.update_attribute({'disable_correlation': True}, attribute)
            self.assertTrue(attribute.disable_correlation, attribute)
            attribute = self.user_misp_connector.update_attribute({'disable_correlation': False}, attribute)
            self.assertFalse(attribute.disable_correlation, attribute)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)

    def test_sightings(self):
        first = self.create_simple_event()
        second = self.create_simple_event()
        try:
            first = self.user_misp_connector.add_event(first)
            second = self.user_misp_connector.add_event(second)

            current_ts = int(time.time())
            time.sleep(5)
            r = self.user_misp_connector.add_sighting({'value': first.attributes[0].value})
            self.assertEqual(int(r.attribute_id), first.attributes[0].id)

            s = MISPSighting()
            s.value = second.attributes[0].value
            s.source = 'Testcases'
            s.type = '1'
            r = self.user_misp_connector.add_sighting(s, second.attributes[0])
            self.assertEqual(r.source, 'Testcases')

            s = self.user_misp_connector.search_sightings(publish_timestamp=current_ts, include_attribute=True,
                                                          include_event_meta=True, pythonify=True)
            self.assertEqual(len(s), 2)
            self.assertEqual(s[0]['event'].id, first.id)
            self.assertEqual(s[0]['attribute'].id, first.attributes[0].id)

            s = self.user_misp_connector.search_sightings(publish_timestamp=current_ts,
                                                          source='Testcases',
                                                          include_attribute=True,
                                                          include_event_meta=True,
                                                          pythonify=True)
            self.assertEqual(len(s), 1)
            self.assertEqual(s[0]['event'].id, second.id, s)
            self.assertEqual(s[0]['attribute'].id, second.attributes[0].id)

            s = self.user_misp_connector.search_sightings(publish_timestamp=current_ts,
                                                          type_sighting='1',
                                                          include_attribute=True,
                                                          include_event_meta=True,
                                                          pythonify=True)
            self.assertEqual(len(s), 1)
            self.assertEqual(s[0]['event'].id, second.id)
            self.assertEqual(s[0]['attribute'].id, second.attributes[0].id)

            s = self.user_misp_connector.search_sightings(context='event',
                                                          context_id=first.id,
                                                          pythonify=True)
            self.assertEqual(len(s), 1)
            self.assertEqual(s[0]['sighting'].event_id, str(first.id))

            s = self.user_misp_connector.search_sightings(context='attribute',
                                                          context_id=second.attributes[0].id,
                                                          pythonify=True)
            self.assertEqual(len(s), 1)
            self.assertEqual(s[0]['sighting'].attribute_id, str(second.attributes[0].id))

            # Get sightings from event/attribute / org
            s = self.user_misp_connector.sightings(first)
            self.assertTrue(isinstance(s, list))
            self.assertEqual(int(s[0].attribute_id), first.attributes[0].id)

            self.admin_misp_connector.add_sighting(s, second.attributes[0])
            s = self.user_misp_connector.sightings(second.attributes[0])
            self.assertEqual(len(s), 2)
            s = self.user_misp_connector.sightings(second.attributes[0], self.test_org)
            self.assertEqual(len(s), 1)
            self.assertEqual(s[0].org_id, self.test_org.id)
            # Delete sighting
            r = self.user_misp_connector.delete_sighting(s[0])
            self.assertEqual(r['message'], 'Sighting successfuly deleted.')

        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)
            self.admin_misp_connector.delete_event(second)

    def test_search_csv(self):
        first = self.create_simple_event()
        first.attributes[0].comment = 'This is the original comment'
        second = self.create_simple_event()
        second.info = 'foo blah'
        second.set_date('2018-09-01')
        second.add_attribute('ip-src', '8.8.8.8')
        try:
            first = self.user_misp_connector.add_event(first)
            second = self.user_misp_connector.add_event(second)

            response = self.user_misp_connector.publish(first, alert=False)
            self.assertEqual(response['errors'][1]['message'], 'You do not have permission to use this functionality.')

            # Default search, attribute with to_ids == True
            first.attributes[0].to_ids = True
            first = self.user_misp_connector.update_event(first)
            self.admin_misp_connector.publish(first, alert=False)
            csv = self.user_misp_connector.search(return_format='csv', publish_timestamp=first.timestamp.timestamp())
            self.assertEqual(len(csv), 1)
            self.assertEqual(csv[0]['value'], first.attributes[0].value)

            # eventid
            csv = self.user_misp_connector.search(return_format='csv', eventid=first.id)
            self.assertEqual(len(csv), 1)
            self.assertEqual(csv[0]['value'], first.attributes[0].value)

            # category
            csv = self.user_misp_connector.search(return_format='csv', publish_timestamp=first.timestamp.timestamp(), category='Other')
            self.assertEqual(len(csv), 1)
            self.assertEqual(csv[0]['value'], first.attributes[0].value)
            csv = self.user_misp_connector.search(return_format='csv', publish_timestamp=first.timestamp.timestamp(), category='Person')
            self.assertEqual(len(csv), 0)

            # type_attribute
            csv = self.user_misp_connector.search(return_format='csv', publish_timestamp=first.timestamp.timestamp(), type_attribute='text')
            self.assertEqual(len(csv), 1)
            self.assertEqual(csv[0]['value'], first.attributes[0].value)
            csv = self.user_misp_connector.search(return_format='csv', publish_timestamp=first.timestamp.timestamp(), type_attribute='ip-src')
            self.assertEqual(len(csv), 0)

            # context
            csv = self.user_misp_connector.search(return_format='csv', publish_timestamp=first.timestamp.timestamp(), include_context=True)
            self.assertEqual(len(csv), 1)
            self.assertTrue('event_info' in csv[0])

            # date_from date_to
            csv = self.user_misp_connector.search(return_format='csv', date_from=date.today().isoformat())
            self.assertEqual(len(csv), 1)
            self.assertEqual(csv[0]['value'], first.attributes[0].value)
            csv = self.user_misp_connector.search(return_format='csv', date_from='2018-09-01', date_to='2018-09-02')
            self.assertEqual(len(csv), 2)

            # headerless
            csv = self.user_misp_connector.search(return_format='csv', date_from='2018-09-01', date_to='2018-09-02', headerless=True)
            # Expects 2 lines after removing the empty ones.
            self.assertEqual(len(csv.strip().split('\n')), 2)

            # include_context
            csv = self.user_misp_connector.search(return_format='csv', date_from='2018-09-01', date_to='2018-09-02', include_context=True)
            event_context_keys = ['event_info', 'event_member_org', 'event_source_org', 'event_distribution', 'event_threat_level_id', 'event_analysis', 'event_date', 'event_tag', 'event_timestamp']
            for k in event_context_keys:
                self.assertTrue(k in csv[0])

            # requested_attributes
            columns = ['value', 'event_id']
            csv = self.user_misp_connector.search(return_format='csv', date_from='2018-09-01',
                                                  date_to='2018-09-02', requested_attributes=columns)
            self.assertEqual(len(csv[0].keys()), 2)
            for k in columns:
                self.assertTrue(k in csv[0])

        finally:
            # Mostly solved -> https://github.com/MISP/MISP/issues/4886
            time.sleep(5)
            # Delete event
            self.admin_misp_connector.delete_event(first)
            self.admin_misp_connector.delete_event(second)

    def test_search_stix(self):
        first = self.create_simple_event()
        first.add_attribute('ip-src', '8.8.8.8')
        try:
            first = self.user_misp_connector.add_event(first)
            stix = self.user_misp_connector.search(return_format='stix', eventid=first.id)
            self.assertTrue(stix['related_packages'][0]['package']['incidents'][0]['related_indicators']['indicators'][0]['indicator']['observable']['object']['properties']['address_value']['value'], '8.8.8.8')
            stix2 = self.user_misp_connector.search(return_format='stix2', eventid=first.id)
            self.assertEqual(stix2['objects'][-1]['pattern'], "[network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '8.8.8.8']")
            stix_xml = self.user_misp_connector.search(return_format='stix-xml', eventid=first.id)
            self.assertTrue('<AddressObj:Address_Value condition="Equals">8.8.8.8</AddressObj:Address_Value>' in stix_xml)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)

    def test_update_object(self):
        first = self.create_simple_event()
        ip_dom = MISPObject('domain-ip')
        ip_dom.add_attribute('domain', value='google.fr')
        ip_dom.add_attribute('ip', value='8.8.8.8')
        first.add_object(ip_dom)
        try:
            # Update with full event
            first = self.user_misp_connector.add_event(first)
            first.objects[0].attributes[0].to_ids = False
            first.objects[0].add_attribute('ip', value='8.9.9.8')
            first.objects[0].add_attribute('ip', '8.9.9.10')
            first = self.user_misp_connector.update_event(first)
            self.assertFalse(first.objects[0].attributes[0].to_ids)
            self.assertEqual(first.objects[0].attributes[2].value, '8.9.9.8')
            self.assertEqual(first.objects[0].attributes[3].value, '8.9.9.10')
            # Update object attribute with update_attribute
            attr = first.objects[0].attributes[1]
            attr.to_ids = False
            new_attr = self.user_misp_connector.update_attribute(attr)
            self.assertFalse(new_attr.to_ids)
            # Update object only
            misp_object = self.user_misp_connector.get_object(first.objects[0].id)
            misp_object.attributes[2].value = '8.9.9.9'
            misp_object.attributes[2].to_ids = False
            misp_object = self.user_misp_connector.update_object(misp_object)
            self.assertEqual(misp_object.attributes[2].value, '8.9.9.9')
            self.assertFalse(misp_object.attributes[2].to_ids)
            # Test with add_attributes
            second = self.create_simple_event()
            ip_dom = MISPObject('domain-ip')
            ip_dom.add_attribute('domain', value='google.fr', disable_correlation=True)
            ip_dom.add_attributes('ip', {'value': '10.8.8.8', 'to_ids': False}, '10.9.8.8')
            ip_dom.add_attributes('ip', '11.8.8.8', '11.9.8.8')
            second.add_object(ip_dom)
            second = self.user_misp_connector.add_event(second)
            self.assertEqual(len(second.objects[0].attributes), 5)
            self.assertTrue(second.objects[0].attributes[0].disable_correlation)
            self.assertFalse(second.objects[0].attributes[1].to_ids)
            self.assertTrue(second.objects[0].attributes[2].to_ids)

            # Test generic Tag methods
            r = self.admin_misp_connector.tag(second, 'generic_tag_test')
            self.assertTrue('successfully' in r['message'].lower() and f'Event ({second.id})' in r['message'], r['message'])
            second = self.user_misp_connector.get_event(second.id, pythonify=True)
            self.assertTrue('generic_tag_test' == second.tags[0].name)

            r = self.admin_misp_connector.untag(second, 'generic_tag_test')
            self.assertTrue(r['message'].endswith(f'successfully removed from Event({second.id}).'), r['message'])
            second = self.user_misp_connector.get_event(second.id, pythonify=True)
            self.assertFalse(second.tags)
            # NOTE: object tagging not supported yet
            # r = self.admin_misp_connector.tag(second.objects[0].uuid, 'generic_tag_test')
            # self.assertTrue(r['message'].endswith(f'successfully attached to Object({second.objects[0].id}).'), r['message'])
            # r = self.admin_misp_connector.untag(second.objects[0].uuid, 'generic_tag_test')
            # self.assertTrue(r['message'].endswith(f'successfully removed from Object({second.objects[0].id}).'), r['message'])
            r = self.admin_misp_connector.tag(second.objects[0].attributes[0].uuid, 'generic_tag_test')
            self.assertTrue('successfully' in r['message'].lower() and f'Attribute ({second.objects[0].attributes[0].id})' in r['message'], r['message'])
            attr = self.user_misp_connector.get_attribute(second.objects[0].attributes[0].uuid, pythonify=True)
            self.assertTrue('generic_tag_test' == attr.tags[0].name)
            r = self.admin_misp_connector.untag(second.objects[0].attributes[0].uuid, 'generic_tag_test')
            self.assertTrue(r['message'].endswith(f'successfully removed from Attribute({second.objects[0].attributes[0].id}).'), r['message'])
            second = self.user_misp_connector.get_event(second.id, pythonify=True)
            for tag in second.objects[0].attributes[0].tags:
                self.assertFalse('generic_tag_test' == tag.name)
            attr = self.user_misp_connector.get_attribute(second.objects[0].attributes[0].uuid, pythonify=True)
            self.assertFalse(attr.tags)

            # Delete tag to avoid polluting the db
            tags = self.admin_misp_connector.tags(pythonify=True)
            for t in tags:
                if t.name == 'generic_tag_test':
                    response = self.admin_misp_connector.delete_tag(t)
                    self.assertEqual(response['message'], 'Tag deleted.')

            # Test delete object
            r = self.user_misp_connector.delete_object(second.objects[0])
            self.assertEqual(r['message'], 'Object deleted')
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)
            self.admin_misp_connector.delete_event(second)

    def test_custom_template(self):
        first = self.create_simple_event()
        try:
            with open('tests/viper-test-files/test_files/whoami.exe', 'rb') as f:
                first.add_attribute('malware-sample', value='whoami.exe', data=BytesIO(f.read()), expand='binary')
            first.run_expansions()
            first = self.admin_misp_connector.add_event(first, pythonify=True)
            self.assertEqual(len(first.objects), 7)
            file_object = first.get_objects_by_name('file')[0]
            file_object.force_misp_objects_path_custom('tests/mispevent_testfiles', 'overwrite_file')
            file_object.add_attribute('test_overwrite', 'blah')
            obj_json = self.admin_misp_connector.update_object(file_object)
            self.assertTrue('Object' in obj_json, obj_json)
            self.assertTrue('name' in obj_json['Object'], obj_json)
            obj = MISPObject(obj_json['Object']['name'])
            obj.from_dict(**obj_json)
            self.assertEqual(obj.get_attributes_by_relation('test_overwrite')[0].value, 'blah')

            # FULL object add & update with custom template
            new_object = MISPObject('overwrite_file', misp_objects_path_custom='tests/mispevent_testfiles')
            new_object.add_attribute('test_overwrite', 'barbaz')
            new_object.add_attribute('filename', 'barbaz.exe')
            new_object = self.admin_misp_connector.add_object(first, new_object, pythonify=True)
            self.assertEqual(new_object.get_attributes_by_relation('test_overwrite')[0].value, 'barbaz', new_object)

            new_object.force_misp_objects_path_custom('tests/mispevent_testfiles', 'overwrite_file')
            new_object.add_attribute('filename', 'foobar.exe')
            new_object = self.admin_misp_connector.update_object(new_object, pythonify=True)
            self.assertEqual(new_object.get_attributes_by_relation('filename')[1].value, 'foobar.exe', new_object)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)

    def test_unknown_template(self):
        first = self.create_simple_event()
        attributeAsDict = [{'MyCoolAttribute': {'value': 'critical thing', 'type': 'text'}},
                           {'MyCoolerAttribute': {'value': 'even worse', 'type': 'text', 'disable_correlation': True}}]
        misp_object = GenericObjectGenerator('my-cool-template')
        misp_object.generate_attributes(attributeAsDict)
        first.add_object(misp_object)
        blah_object = MISPObject('BLAH_TEST')
        blah_object.add_reference(misp_object.uuid, "test relation")
        blah_object.add_attribute('transaction-number', value='foo', type="text", disable_correlation=True)
        first.add_object(blah_object)
        try:
            first = self.user_misp_connector.add_event(first)
            self.assertEqual(len(first.objects[0].attributes), 2)
            self.assertFalse(first.objects[0].attributes[0].disable_correlation)
            self.assertTrue(first.objects[0].attributes[1].disable_correlation)
            self.assertTrue(first.objects[1].attributes[0].disable_correlation)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)

    def test_domain_ip_object(self):
        first = self.create_simple_event()
        try:
            dom_ip_obj = DomainIPObject({'ip': ['1.1.1.1', {'value': '2.2.2.2', 'to_ids': False}],
                                         'first-seen': '20190101',
                                         'last-seen': '2019-02-03',
                                         'domain': 'circl.lu'})
            first.add_object(dom_ip_obj)
            first = self.user_misp_connector.add_event(first)
            self.assertEqual(len(first.objects[0].attributes), 5)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)

    def test_asn_object(self):
        first = self.create_simple_event()
        try:
            dom_ip_obj = ASNObject({'asn': '12345',
                                    'first-seen': '20190101',
                                    'last-seen': '2019-02-03'})
            first.add_object(dom_ip_obj)
            first = self.user_misp_connector.add_event(first)
            self.assertEqual(len(first.objects[0].attributes), 3)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)

    def test_object_template(self):
        r = self.admin_misp_connector.update_object_templates()
        self.assertEqual(type(r), list)
        object_templates = self.admin_misp_connector.object_templates(pythonify=True)
        self.assertTrue(isinstance(object_templates, list))
        for object_template in object_templates:
            if object_template.name == 'file':
                break

        template = self.admin_misp_connector.get_object_template(object_template.uuid, pythonify=True)
        self.assertEqual(template.name, 'file')

    def test_tags(self):
        # Get list
        tags = self.admin_misp_connector.tags(pythonify=True)
        self.assertTrue(isinstance(tags, list))
        # Get tag
        for tag in tags:
            if not tag.hide_tag:
                break
        tag = self.admin_misp_connector.get_tag(tag, pythonify=True)
        self.assertTrue('name' in tag)
        # Enable by MISPTag
        tag = self.admin_misp_connector.disable_tag(tag, pythonify=True)
        self.assertTrue(tag.hide_tag)
        tag = self.admin_misp_connector.enable_tag(tag, pythonify=True)
        self.assertFalse(tag.hide_tag)
        # Add tag
        tag = MISPTag()
        tag.name = 'this is a test tag'
        new_tag = self.admin_misp_connector.add_tag(tag, pythonify=True)
        self.assertEqual(new_tag.name, tag.name)
        # Add non-exportable tag
        tag = MISPTag()
        tag.name = 'non-exportable tag'
        tag.exportable = False
        non_exportable_tag = self.admin_misp_connector.add_tag(tag, pythonify=True)
        self.assertFalse(non_exportable_tag.exportable)
        first = self.create_simple_event()
        first.attributes[0].add_tag('non-exportable tag')
        # Add tag restricted to an org
        tag = MISPTag()
        tag.name = f'restricted to org {self.test_org.id}'
        tag.org_id = self.test_org.id
        tag_org_restricted = self.admin_misp_connector.add_tag(tag, pythonify=True)
        self.assertEqual(tag_org_restricted.org_id, tag.org_id)
        # Add tag restricted to a user
        tag.name = f'restricted to user {self.test_usr.id}'
        tag.user_id = self.test_usr.id
        tag_user_restricted = self.admin_misp_connector.add_tag(tag, pythonify=True)
        self.assertEqual(tag_user_restricted.user_id, tag.user_id)
        try:
            first = self.user_misp_connector.add_event(first)
            self.assertFalse(first.attributes[0].tags)
            first = self.admin_misp_connector.get_event(first, pythonify=True)
            # Reference: https://github.com/MISP/MISP/issues/1394
            self.assertFalse(first.attributes[0].tags)
            # Reference: https://github.com/MISP/PyMISP/issues/483
            r = self.delegate_user_misp_connector.tag(first, tag_org_restricted)
            # FIXME: The error message changed and is unhelpful.
            # self.assertEqual(r['errors'][1]['message'], 'Invalid Tag. This tag can only be set by a fixed organisation.')
            self.assertEqual(r['errors'][1]['message'], 'Invalid Target.')
            r = self.user_misp_connector.tag(first, tag_org_restricted)
            self.assertTrue('successfully' in r['message'].lower() and f'Event ({first.id})' in r['message'], r['message'])
            r = self.pub_misp_connector.tag(first.attributes[0], tag_user_restricted)
            self.assertIn('Invalid Tag. This tag can only be set by a fixed user.', r['errors'][1]['errors'])
            r = self.user_misp_connector.tag(first.attributes[0], tag_user_restricted)
            self.assertTrue('successfully' in r['message'].lower() and f'Attribute ({first.attributes[0].id})' in r['message'], r['message'])
            first = self.user_misp_connector.get_event(first, pythonify=True)
            self.assertTrue(len(first.attributes[0].tags) == 1)
            # test delete tag on attribute edit
            deleted_tag = first.attributes[0].tags[0]
            first.attributes[0].tags[0].delete()
            attribute = self.user_misp_connector.update_attribute(first.attributes[0], pythonify=True)
            for tag in attribute.tags:
                self.assertTrue(tag.name != deleted_tag.name)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)

        # Search tag
        # Partial search
        tags = self.admin_misp_connector.search_tags(f'{new_tag.name[:5]}%', pythonify=True)
        self.assertEqual(tags[0].name, 'this is a test tag')
        # No tags found
        tags = self.admin_misp_connector.search_tags('not a tag')
        self.assertFalse(tags)

        # Update tag
        non_exportable_tag.name = 'non-exportable tag - edit'
        non_exportable_tag_edited = self.admin_misp_connector.update_tag(non_exportable_tag, pythonify=True)
        self.assertTrue(non_exportable_tag_edited.name == 'non-exportable tag - edit', non_exportable_tag_edited.to_json(indent=2))

        # Delete tag
        response = self.admin_misp_connector.delete_tag(new_tag)
        self.assertEqual(response['message'], 'Tag deleted.')
        response = self.admin_misp_connector.delete_tag(non_exportable_tag)
        self.assertEqual(response['message'], 'Tag deleted.')
        response = self.admin_misp_connector.delete_tag(tag_org_restricted)
        response = self.admin_misp_connector.delete_tag(tag_user_restricted)

    def test_add_event_with_attachment_object_controller(self):
        first = self.create_simple_event()
        try:
            first = self.user_misp_connector.add_event(first)
            fo, peo, seos = make_binary_objects('tests/viper-test-files/test_files/whoami.exe')
            for s in seos:
                r = self.user_misp_connector.add_object(first, s)
                self.assertEqual(r.name, 'pe-section', r)

            r = self.user_misp_connector.add_object(first, peo)
            self.assertEqual(r.name, 'pe', r)
            for ref in peo.ObjectReference:
                r = self.user_misp_connector.add_object_reference(ref)
                self.assertEqual(r.object_uuid, peo.uuid, r.to_json())

            r = self.user_misp_connector.add_object(first, fo)
            obj_attrs = r.get_attributes_by_relation('ssdeep')
            self.assertEqual(len(obj_attrs), 1, obj_attrs)
            self.assertEqual(r.name, 'file', r)

            # Test break_on_duplicate at object level
            # with open('fo.json', 'w') as f:
            #    f.write(fo.to_json(indent=2))
            print(peo.to_json(indent=2))
            fo_dup, peo_dup, _ = make_binary_objects('tests/viper-test-files/test_files/whoami.exe')
            # with open('fo_dup.json', 'w') as f:
            #    f.write(fo_dup.to_json(indent=2))
            print(peo_dup.to_json(indent=2))
            r = self.user_misp_connector.add_object(first, peo_dup, break_on_duplicate=True)
            # r = self.user_misp_connector.add_object(first, fo_dup)
            #time.sleep(60)
            raise Exception(r)

            # Test refs
            r = self.user_misp_connector.add_object_reference(fo.ObjectReference[0])
            self.assertEqual(r.object_uuid, fo.uuid, r.to_json())
            self.assertEqual(r.referenced_uuid, peo.uuid, r.to_json())
            r = self.user_misp_connector.delete_object_reference(r)
            self.assertEqual(r['message'], 'ObjectReference deleted')
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)

    def test_add_event_with_attachment(self):
        first = self.create_simple_event()
        try:
            first = self.user_misp_connector.add_event(first)
            file_obj, bin_obj, sections = make_binary_objects('tests/viper-test-files/test_files/whoami.exe', standalone=False)
            first.add_object(file_obj)
            first.add_object(bin_obj)
            for s in sections:
                first.add_object(s)
            self.assertEqual(len(first.objects[0].references), 1)
            self.assertEqual(first.objects[0].references[0].relationship_type, 'includes')
            first = self.user_misp_connector.update_event(first)
            self.assertEqual(len(first.objects[0].references), 1)
            self.assertEqual(first.objects[0].references[0].relationship_type, 'includes')
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)

    def test_taxonomies(self):
        # Make sure we're up-to-date
        r = self.admin_misp_connector.update_taxonomies()
        self.assertEqual(r['name'], 'All taxonomy libraries are up to date already.')
        # Get list
        taxonomies = self.admin_misp_connector.taxonomies(pythonify=True)
        self.assertTrue(isinstance(taxonomies, list))
        list_name_test = 'tlp'
        for tax in taxonomies:
            if tax.namespace == list_name_test:
                break
        r = self.admin_misp_connector.get_taxonomy(tax, pythonify=True)
        self.assertEqual(r.namespace, list_name_test)
        self.assertTrue('enabled' in r)
        r = self.admin_misp_connector.enable_taxonomy(tax)
        self.assertEqual(r['message'], 'Taxonomy enabled')
        r = self.admin_misp_connector.enable_taxonomy_tags(tax)
        self.assertEqual(r['name'], 'The tag(s) has been saved.')
        r = self.admin_misp_connector.disable_taxonomy(tax)
        self.assertEqual(r['message'], 'Taxonomy disabled')

    def test_warninglists(self):
        # Make sure we're up-to-date
        r = self.admin_misp_connector.update_warninglists()
        self.assertTrue('name' in r, msg=r)
        try:
            self.assertEqual(r['name'], 'All warninglists are up to date already.', msg=r)
        except Exception:
            print(r)
        # Get list
        warninglists = self.admin_misp_connector.warninglists(pythonify=True)
        self.assertTrue(isinstance(warninglists, list))
        list_name_test = 'List of known hashes with common false-positives (based on Florian Roth input list)'
        for wl in warninglists:
            if wl.name == list_name_test:
                break
        testwl = wl
        r = self.admin_misp_connector.get_warninglist(testwl, pythonify=True)
        self.assertEqual(r.name, list_name_test)
        self.assertTrue('WarninglistEntry' in r)
        r = self.admin_misp_connector.enable_warninglist(testwl)
        self.assertEqual(r['success'], '1 warninglist(s) enabled')
        # Check if a value is in a warning list
        md5_empty_file = 'd41d8cd98f00b204e9800998ecf8427e'
        r = self.user_misp_connector.values_in_warninglist([md5_empty_file])
        self.assertEqual(r[md5_empty_file][0]['name'], list_name_test)

        r = self.admin_misp_connector.disable_warninglist(testwl)
        self.assertEqual(r['success'], '1 warninglist(s) disabled')

    def test_noticelists(self):
        # Make sure we're up-to-date
        r = self.admin_misp_connector.update_noticelists()
        self.assertEqual(r['name'], 'All noticelists are up to date already.')
        # Get list
        noticelists = self.admin_misp_connector.noticelists(pythonify=True)
        self.assertTrue(isinstance(noticelists, list))
        list_name_test = 'gdpr'
        for nl in noticelists:
            if nl.name == list_name_test:
                break
        testnl = nl
        r = self.admin_misp_connector.get_noticelist(testnl, pythonify=True)
        self.assertEqual(r.name, list_name_test)
        # FIXME: https://github.com/MISP/MISP/issues/4856
        self.assertTrue('NoticelistEntry' in r)
        r = self.admin_misp_connector.enable_noticelist(testnl)
        self.assertTrue(r['Noticelist']['enabled'], r)
        r = self.admin_misp_connector.disable_noticelist(testnl)
        self.assertFalse(r['Noticelist']['enabled'], r)

    def test_galaxies(self):
        # Make sure we're up-to-date
        r = self.admin_misp_connector.update_galaxies()
        self.assertEqual(r['name'], 'Galaxies updated.')
        # Get list
        galaxies = self.admin_misp_connector.galaxies(pythonify=True)
        self.assertTrue(isinstance(galaxies, list))
        list_name_test = 'Mobile Attack - Attack Pattern'
        for galaxy in galaxies:
            if galaxy.name == list_name_test:
                break
        r = self.admin_misp_connector.get_galaxy(galaxy, pythonify=True)
        self.assertEqual(r.name, list_name_test)
        # FIXME: Fails due to https://github.com/MISP/MISP/issues/4855
        # self.assertTrue('GalaxyCluster' in r)

    def test_zmq(self):
        first = self.create_simple_event()
        try:
            first = self.user_misp_connector.add_event(first)
            r = self.admin_misp_connector.push_event_to_ZMQ(first)
            self.assertEqual(r['message'], 'Event published to ZMQ')
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)

    def test_csv_loader(self):
        csv1 = CSVLoader(template_name='file', csv_path=Path('tests/csv_testfiles/valid_fieldnames.csv'))
        event = MISPEvent()
        event.info = 'Test event from CSV loader'
        for o in csv1.load():
            event.add_object(**o)

        csv2 = CSVLoader(template_name='file', csv_path=Path('tests/csv_testfiles/invalid_fieldnames.csv'),
                         fieldnames=['SHA1', 'fileName', 'size-in-bytes'], has_fieldnames=True)
        try:
            first = self.user_misp_connector.add_event(event)
            for o in csv2.load():
                new_object = self.user_misp_connector.add_object(first, o)
                self.assertEqual(len(new_object.attributes), 3)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)

    def test_user(self):
        # Get list
        users = self.admin_misp_connector.users(pythonify=True)
        self.assertTrue(isinstance(users, list))
        users_email = 'testusr@user.local'
        for user in users:
            if user.email == users_email:
                break
        else:
            raise Exception('Unable to find that user')
        self.assertEqual(user.email, users_email)
        # get user
        user = self.user_misp_connector.get_user(pythonify=True)
        self.assertEqual(user.authkey, self.test_usr.authkey)
        # Update user
        user.email = 'foo@bar.de'
        user = self.admin_misp_connector.update_user(user, pythonify=True)
        self.assertEqual(user.email, 'foo@bar.de')

    def test_organisation(self):
        # Get list
        orgs = self.admin_misp_connector.organisations(pythonify=True)
        self.assertTrue(isinstance(orgs, list))
        org_name = 'ORGNAME'
        for org in orgs:
            if org.name == org_name:
                break
        self.assertEqual(org.name, org_name)
        # Get org
        organisation = self.user_misp_connector.get_organisation(self.test_usr.org_id)
        self.assertEqual(organisation.name, 'Test Org')
        # Update org
        organisation.name = 'blah'
        organisation = self.admin_misp_connector.update_organisation(organisation, pythonify=True)
        self.assertEqual(organisation.name, 'blah', organisation)

    def test_attribute(self):
        first = self.create_simple_event()
        second = self.create_simple_event()
        a = second.add_attribute('ip-src', '11.11.11.11')
        a.add_tag('testtag_admin_created')
        second.distribution = Distribution.all_communities
        try:
            first = self.user_misp_connector.add_event(first)
            second = self.admin_misp_connector.add_event(second, pythonify=True)
            # Get attribute
            attribute = self.user_misp_connector.get_attribute(first.attributes[0])
            self.assertEqual(first.attributes[0].uuid, attribute.uuid)
            # Add attribute
            new_attribute = MISPAttribute()
            new_attribute.value = '1.2.3.4'
            new_attribute.type = 'ip-dst'
            new_attribute = self.user_misp_connector.add_attribute(first, new_attribute)
            self.assertTrue(isinstance(new_attribute, MISPAttribute), new_attribute)
            self.assertEqual(new_attribute.value, '1.2.3.4', new_attribute)
            # Test attribute already in event
            # new_attribute.uuid = str(uuid4())
            # new_attribute = self.user_misp_connector.add_attribute(first, new_attribute)
            new_similar = MISPAttribute()
            new_similar.value = '1.2.3.4'
            new_similar.type = 'ip-dst'
            similar_error = self.user_misp_connector.add_attribute(first, new_similar)
            self.assertEqual(similar_error['errors'][1]['errors']['value'][0], 'A similar attribute already exists for this event.')

            # Test add multiple attributes at once
            attr0 = MISPAttribute()
            attr0.value = '0.0.0.0'
            attr0.type = 'ip-dst'
            response = self.user_misp_connector.add_attribute(first, [attr0])
            time.sleep(5)
            self.assertTrue(isinstance(response['attributes'], list), response['attributes'])
            self.assertEqual(response['attributes'][0].value, '0.0.0.0')
            attr1 = MISPAttribute()
            attr1.value = '1.2.3.4'
            attr1.type = 'ip-dst'
            attr2 = MISPAttribute()
            attr2.value = '1.2.3.5'
            attr2.type = 'ip-dst'
            attr3 = MISPAttribute()
            attr3.value = first.attributes[0].value
            attr3.type = first.attributes[0].type
            attr4 = MISPAttribute()
            attr4.value = '1.2.3.6'
            attr4.type = 'ip-dst'
            attr4.add_tag('tlp:amber___test_unique_not_created')
            attr4.add_tag('testtag_admin_created')
            response = self.user_misp_connector.add_attribute(first, [attr1, attr2, attr3, attr4])
            time.sleep(5)
            self.assertTrue(isinstance(response['attributes'], list), response['attributes'])
            self.assertEqual(response['attributes'][0].value, '1.2.3.5')
            self.assertEqual(response['attributes'][1].value, '1.2.3.6')
            self.assertTrue(isinstance(response['attributes'][1].tags, list), response['attributes'][1].to_json())
            self.assertTrue(len(response['attributes'][1].tags), response['attributes'][1].to_json())
            self.assertEqual(response['attributes'][1].tags[0].name, 'testtag_admin_created')
            self.assertEqual(response['errors']['attribute_0']['value'][0], 'A similar attribute already exists for this event.')
            self.assertEqual(response['errors']['attribute_2']['value'][0], 'A similar attribute already exists for this event.')

            # Add attribute as proposal
            new_proposal = MISPAttribute()
            new_proposal.value = '5.2.3.4'
            new_proposal.type = 'ip-dst'
            new_proposal.category = 'Network activity'
            new_proposal = self.user_misp_connector.add_attribute_proposal(first.id, new_proposal)
            self.assertEqual(new_proposal.value, '5.2.3.4')
            # Update attribute
            new_attribute.value = '5.6.3.4'
            new_attribute = self.user_misp_connector.update_attribute(new_attribute)
            self.assertEqual(new_attribute.value, '5.6.3.4')
            # Update attribute as proposal
            new_proposal_update = self.user_misp_connector.update_attribute_proposal(new_attribute.id, {'to_ids': False})
            self.assertEqual(new_proposal_update.to_ids, False)
            # Delete attribute as proposal
            proposal_delete = self.user_misp_connector.delete_attribute_proposal(new_attribute)
            self.assertTrue(proposal_delete['saved'])
            # Get attribute proposal
            temp_new_proposal = self.user_misp_connector.get_attribute_proposal(new_proposal)
            self.assertEqual(temp_new_proposal.uuid, new_proposal.uuid)
            # Get attribute proposal*S*
            proposals = self.user_misp_connector.attribute_proposals()
            self.assertTrue(isinstance(proposals, list))
            self.assertEqual(len(proposals), 3)
            self.assertEqual(proposals[0].value, '5.2.3.4')
            # Get proposals on a specific event
            self.admin_misp_connector.add_attribute_proposal(second.id, {'type': 'ip-src', 'value': '123.123.123.1'})
            proposals = self.admin_misp_connector.attribute_proposals(pythonify=True)
            self.assertTrue(isinstance(proposals, list))
            self.assertEqual(len(proposals), 4)
            proposals = self.admin_misp_connector.attribute_proposals(second, pythonify=True)
            self.assertTrue(isinstance(proposals, list))
            self.assertEqual(len(proposals), 1)
            self.assertEqual(proposals[0].value, '123.123.123.1')
            # Accept attribute proposal - New attribute
            self.user_misp_connector.accept_attribute_proposal(new_proposal)
            first = self.user_misp_connector.get_event(first)
            self.assertEqual(first.attributes[-1].value, '5.2.3.4')
            # Accept attribute proposal - Attribute update
            response = self.user_misp_connector.accept_attribute_proposal(new_proposal_update)
            self.assertEqual(response['message'], 'Proposed change accepted.')
            attribute = self.user_misp_connector.get_attribute(new_attribute)
            self.assertEqual(attribute.to_ids, False)
            # Discard attribute proposal
            new_proposal_update = self.user_misp_connector.update_attribute_proposal(new_attribute.id, {'to_ids': True})
            response = self.user_misp_connector.discard_attribute_proposal(new_proposal_update)
            self.assertEqual(response['message'], 'Proposal discarded.')
            attribute = self.user_misp_connector.get_attribute(new_attribute)
            self.assertEqual(attribute.to_ids, False)

            # Test fallback to proposal if the user doesn't own the event
            prop_attr = MISPAttribute()
            prop_attr.from_dict(**{'type': 'ip-dst', 'value': '123.43.32.21'})
            # Add attribute on event owned by someone else
            attribute = self.user_misp_connector.add_attribute(second.id, prop_attr)
            self.assertTrue(isinstance(attribute, MISPShadowAttribute), attribute)
            # Test if add proposal without category works - https://github.com/MISP/MISP/issues/4868
            attribute = self.user_misp_connector.add_attribute(second.id, {'type': 'ip-dst', 'value': '123.43.32.22'})
            self.assertTrue(isinstance(attribute, MISPShadowAttribute), attribute)
            # Add attribute with the same value as an existing proposal
            prop_attr.uuid = str(uuid4())
            attribute = self.admin_misp_connector.add_attribute(second, prop_attr, pythonify=True)
            prop_attr.uuid = str(uuid4())
            # Add a duplicate attribute (same value)
            attribute = self.admin_misp_connector.add_attribute(second, prop_attr, pythonify=True)
            self.assertTrue('errors' in attribute)
            # Update attribute owned by someone else
            attribute = self.user_misp_connector.update_attribute({'comment': 'blah'}, second.attributes[0].id)
            self.assertTrue(isinstance(attribute, MISPShadowAttribute), attribute)
            self.assertEqual(attribute.value, second.attributes[0].value)
            second = self.admin_misp_connector.get_event(second, pythonify=True)
            self.assertEqual(len(second.attributes), 3)
            # Delete attribute owned by someone else
            response = self.user_misp_connector.delete_attribute(second.attributes[1])
            self.assertTrue(response['success'])
            # Delete attribute owned by user
            response = self.admin_misp_connector.delete_attribute(second.attributes[1])
            self.assertEqual(response['message'], 'Attribute deleted.')
            # Hard delete
            response = self.admin_misp_connector.delete_attribute(second.attributes[0], hard=True)
            self.assertEqual(response['message'], 'Attribute deleted.')
            new_second = self.admin_misp_connector.get_event(second, deleted=[0, 1], pythonify=True)
            self.assertEqual(len(new_second.attributes), 2)

            # Test attribute*S*
            attributes = self.admin_misp_connector.attributes()
            self.assertEqual(len(attributes), 7)
            # attributes = self.user_misp_connector.attributes()
            # self.assertEqual(len(attributes), 5)
            # Test event*S*
            events = self.admin_misp_connector.events()
            self.assertEqual(len(events), 2)
            events = self.user_misp_connector.events()
            self.assertEqual(len(events), 2)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)
            self.admin_misp_connector.delete_event(second)

    def test_search_type_event_csv(self):
        try:
            first, second, third = self.environment()
            # Search as admin
            events = self.admin_misp_connector.search(return_format='csv', timestamp=first.timestamp.timestamp(), pythonify=True)
            self.assertTrue(isinstance(events, list))
            self.assertEqual(len(events), 8)
            attributes_types_search = self.admin_misp_connector.build_complex_query(or_parameters=['ip-src', 'ip-dst'])
            events = self.admin_misp_connector.search(return_format='csv', timestamp=first.timestamp.timestamp(),
                                                      type_attribute=attributes_types_search, pythonify=True)
            self.assertTrue(isinstance(events, list))
            self.assertEqual(len(events), 6)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)
            self.admin_misp_connector.delete_event(second)
            self.admin_misp_connector.delete_event(third)

    def test_search_logs(self):
        # FIXME: https://github.com/MISP/MISP/issues/4872
        r = self.admin_misp_connector.update_user({'email': 'testusr-changed@user.local'}, self.test_usr)
        r = self.admin_misp_connector.search_logs(model='User', created=date.today(), pythonify=True)
        for entry in r[-1:]:
            self.assertEqual(entry.action, 'edit')
        r = self.admin_misp_connector.search_logs(email='admin@admin.test', created=date.today(), pythonify=True)
        for entry in r[-1:]:
            self.assertEqual(entry.action, 'edit')
        r = self.admin_misp_connector.update_user({'email': 'testusr@user.local'}, self.test_usr)

    def test_db_schema(self):
        diag = self.admin_misp_connector.db_schema_diagnostic()
        self.assertEqual(diag['actual_db_version'], diag['expected_db_version'], diag)

    def test_live_acl(self):
        missing_acls = self.admin_misp_connector.remote_acl()
        self.assertEqual(missing_acls, [], msg=missing_acls)

    def test_roles(self):
        role = self.admin_misp_connector.set_default_role(4)
        self.assertEqual(role['message'], 'Default role set.')
        self.admin_misp_connector.set_default_role(3)
        roles = self.admin_misp_connector.roles(pythonify=True)
        self.assertTrue(isinstance(roles, list))

    def test_describe_types(self):
        remote = self.admin_misp_connector.describe_types_remote
        remote_types = remote.pop('types')
        remote_categories = remote.pop('categories')
        remote_category_type_mappings = remote.pop('category_type_mappings')
        local = dict(self.admin_misp_connector.describe_types_local)
        local_types = local.pop('types')
        local_categories = local.pop('categories')
        local_category_type_mappings = local.pop('category_type_mappings')
        self.assertDictEqual(remote, local)
        self.assertEqual(sorted(remote_types), sorted(local_types))
        self.assertEqual(sorted(remote_categories), sorted(local_categories))
        for category, mapping in remote_category_type_mappings.items():
            self.assertEqual(sorted(local_category_type_mappings[category]), sorted(mapping))

    def test_versions(self):
        self.assertEqual(self.user_misp_connector.version, self.user_misp_connector.pymisp_version_master)
        self.assertEqual(self.user_misp_connector.misp_instance_version['version'],
                         self.user_misp_connector.misp_instance_version_master['version'])

    def test_statistics(self):
        try:
            # Attributes
            first, second, third = self.environment()
            expected_attr_stats = {'ip-dst': '2', 'ip-src': '1', 'text': '5'}
            attr_stats = self.admin_misp_connector.attributes_statistics()
            self.assertDictEqual(attr_stats, expected_attr_stats)
            expected_attr_stats_percent = {'ip-dst': '25%', 'ip-src': '12.5%', 'text': '62.5%'}
            attr_stats = self.admin_misp_connector.attributes_statistics(percentage=True)
            self.assertDictEqual(attr_stats, expected_attr_stats_percent)
            expected_attr_stats_category_percent = {'Network activity': '37.5%', 'Other': '62.5%'}
            attr_stats = self.admin_misp_connector.attributes_statistics(context='category', percentage=True)
            self.assertDictEqual(attr_stats, expected_attr_stats_category_percent)
            # Tags
            to_test = {'tags': {'tlp:white___test': '1'}, 'taxonomies': []}
            tags_stats = self.admin_misp_connector.tags_statistics()
            self.assertDictEqual(tags_stats, to_test)
            to_test = {'tags': {'tlp:white___test': '100%'}, 'taxonomies': []}
            tags_stats = self.admin_misp_connector.tags_statistics(percentage=True, name_sort=True)
            self.assertDictEqual(tags_stats, to_test)
            # Users
            users_stats = self.admin_misp_connector.users_statistics(context='data')
            self.assertTrue('stats' in users_stats)

            users_stats = self.admin_misp_connector.users_statistics(context='orgs')
            self.assertTrue('ORGNAME' in list(users_stats.keys()))

            users_stats = self.admin_misp_connector.users_statistics(context='users')
            self.assertEqual(list(users_stats.keys()), ['user', 'org_local', 'org_external'])

            users_stats = self.admin_misp_connector.users_statistics(context='tags')
            self.assertEqual(list(users_stats.keys()), ['flatData', 'treemap'])

            users_stats = self.admin_misp_connector.users_statistics(context='attributehistogram')
            self.assertTrue(isinstance(users_stats, list), users_stats)

            self.user_misp_connector.add_sighting({'value': first.attributes[0].value})
            users_stats = self.user_misp_connector.users_statistics(context='sightings')
            self.assertEqual(list(users_stats.keys()), ['toplist', 'eventids'])

            # FIXME this one fails on travis.
            # users_stats = self.admin_misp_connector.users_statistics(context='galaxyMatrix')
            # self.assertTrue('matrix' in users_stats)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)
            self.admin_misp_connector.delete_event(second)
            self.admin_misp_connector.delete_event(third)

    def test_direct(self):
        try:
            r = self.user_misp_connector.direct_call('events/add', data={'info': 'foo'})
            event = MISPEvent()
            event.from_dict(**r)
            r = self.user_misp_connector.direct_call(f'events/view/{event.id}')
            event_get = MISPEvent()
            event_get.from_dict(**r)
            self.assertDictEqual(event.to_dict(), event_get.to_dict())
            r = self.user_misp_connector.direct_call('events/restSearch', data={"returnFormat": "csv",
                                                                                "type": {"AND": ["campaign-name", "threat-actor"]},
                                                                                "category": "Attribution", "includeEventUuid": 1})
            self.assertTrue(r.startswith('uuid,event_id,category,type,value'))

        finally:
            self.admin_misp_connector.delete_event(event)

    def test_freetext(self):
        first = self.create_simple_event()
        try:
            self.admin_misp_connector.toggle_warninglist(warninglist_name='%dns resolv%', force_enable=True)
            first = self.user_misp_connector.add_event(first)
            # disable_background_processing => returns the parsed data, before insertion
            r = self.user_misp_connector.freetext(first, '1.1.1.1 foo@bar.de', adhereToWarninglists=False,
                                                  distribution=2, returnMetaAttributes=False, pythonify=True,
                                                  kw_params={'disable_background_processing': 1})
            self.assertTrue(isinstance(r, list))
            self.assertEqual(r[0].value, '1.1.1.1')
            r = self.user_misp_connector.freetext(first, '9.9.9.9 foo@bar.com', adhereToWarninglists='soft',
                                                  distribution=2, returnMetaAttributes=False, pythonify=True,
                                                  kw_params={'disable_background_processing': 1})
            self.assertTrue(isinstance(r, list))
            self.assertEqual(r[0].value, '9.9.9.9')
            event = self.user_misp_connector.get_event(first, pythonify=True)
            self.assertEqual(event.attributes[3].value, '9.9.9.9')
            self.assertFalse(event.attributes[3].to_ids)
            r_wl = self.user_misp_connector.freetext(first, '8.8.8.8 foo@bar.de', adhereToWarninglists=True,
                                                     distribution=2, returnMetaAttributes=False,
                                                     kw_params={'disable_background_processing': 0})
            self.assertEqual(r_wl[0].value, '8.8.8.8')
            event = self.user_misp_connector.get_event(first, pythonify=True)
            for attribute in event.attributes:
                self.assertFalse(attribute.value == '8.8.8.8')
            r = self.user_misp_connector.freetext(first, '1.1.1.1 foo@bar.de', adhereToWarninglists=True,
                                                  distribution=2, returnMetaAttributes=True)
            self.assertTrue(isinstance(r, list))
            self.assertTrue(isinstance(r[0]['types'], dict))
        finally:
            # Mostly solved https://github.com/MISP/MISP/issues/4886
            time.sleep(10)
            # Delete event
            self.admin_misp_connector.delete_event(first)

    def test_sharing_groups(self):
        # add
        sg = MISPSharingGroup()
        sg.name = 'Testcases SG'
        sg.releasability = 'Testing'
        sharing_group = self.admin_misp_connector.add_sharing_group(sg, pythonify=True)
        self.assertEqual(sharing_group.name, 'Testcases SG')
        self.assertEqual(sharing_group.releasability, 'Testing')
        # add org
        r = self.admin_misp_connector.add_org_to_sharing_group(sharing_group,
                                                               self.test_org, extend=True)
        self.assertEqual(r['name'], 'Organisation added to the sharing group.')

        # delete org
        r = self.admin_misp_connector.remove_org_from_sharing_group(sharing_group,
                                                                    self.test_org)
        self.assertEqual(r['name'], 'Organisation removed from the sharing group.', r)
        # Get list
        sharing_groups = self.admin_misp_connector.sharing_groups(pythonify=True)
        self.assertTrue(isinstance(sharing_groups, list))
        self.assertEqual(sharing_groups[0].name, 'Testcases SG')

        # Use the SG

        first = self.create_simple_event()
        o = first.add_object(name='file')
        o.add_attribute('filename', value='foo2.exe')
        second_object = MISPObject('file')
        second_object.add_attribute("tlsh", value='92a4b4a3d342a21fe1147474c19c9ab6a01717713a0248a2bb15affce77c1c14a79b93',
                                    category="Payload delivery", to_ids=True, distribution=4, sharing_group_id=sharing_group.id)

        try:
            first = self.user_misp_connector.add_event(first)
            first = self.admin_misp_connector.change_sharing_group_on_entity(first, sharing_group.id, pythonify=True)
            self.assertEqual(first.SharingGroup['name'], 'Testcases SG')

            first_object = self.admin_misp_connector.change_sharing_group_on_entity(first.objects[0], sharing_group.id, pythonify=True)
            self.assertEqual(first_object.sharing_group_id, sharing_group.id)
            first_attribute = self.admin_misp_connector.change_sharing_group_on_entity(first.attributes[0], sharing_group.id, pythonify=True)
            self.assertEqual(first_attribute.distribution, 4)
            self.assertEqual(first_attribute.sharing_group_id, int(sharing_group.id))
            # manual create
            second_object = self.admin_misp_connector.add_object(first.id, second_object, pythonify=True)
            self.assertEqual(second_object.attributes[0].sharing_group_id, int(sharing_group.id))
            # manual update
            first_object.add_attribute("tlsh", value='92a4b4a3d342a21fe1147474c19c9ab6a01717713a0248a2bb15affce77c1c14a79b93',
                                       category="Payload delivery", to_ids=True, distribution=4, sharing_group_id=sharing_group.id)
            first_object = self.admin_misp_connector.update_object(first_object, pythonify=True)
            self.assertEqual(first_object.attributes[-1].sharing_group_id, int(sharing_group.id))
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)
            # Delete sharing group
            r = self.admin_misp_connector.delete_sharing_group(sharing_group.id)
            self.assertEqual(r['message'], 'SharingGroup deleted')

    def test_feeds(self):
        # Add
        feed = MISPFeed()
        feed.name = 'TestFeed'
        feed.provider = 'TestFeed - Provider'
        feed.url = 'http://example.com'
        feed = self.admin_misp_connector.add_feed(feed, pythonify=True)
        self.assertEqual(feed.name, 'TestFeed')
        self.assertEqual(feed.url, 'http://example.com')
        # Update
        feed.name = 'TestFeed - Update'
        feed = self.admin_misp_connector.update_feed(feed, pythonify=True)
        self.assertEqual(feed.name, 'TestFeed - Update')
        # Delete
        r = self.admin_misp_connector.delete_feed(feed)
        self.assertEqual(r['message'], 'Feed deleted.')
        # List
        feeds = self.admin_misp_connector.feeds(pythonify=True)
        self.assertTrue(isinstance(feeds, list))
        for feed in feeds:
            if feed.name == 'The Botvrij.eu Data':
                break
        # Get
        botvrij = self.admin_misp_connector.get_feed(feed, pythonify=True)
        self.assertEqual(botvrij.url, "https://www.botvrij.eu/data/feed-osint")
        # Enable
        # MISP OSINT
        feed = self.admin_misp_connector.enable_feed(feeds[0].id, pythonify=True)
        self.assertTrue(feed.enabled)
        feed = self.admin_misp_connector.enable_feed_cache(feeds[0].id, pythonify=True)
        self.assertTrue(feed.caching_enabled)
        # Botvrij.eu
        feed = self.admin_misp_connector.enable_feed(botvrij.id, pythonify=True)
        self.assertTrue(feed.enabled)
        feed = self.admin_misp_connector.enable_feed_cache(botvrij.id, pythonify=True)
        self.assertTrue(feed.caching_enabled)
        # Cache
        r = self.admin_misp_connector.cache_feed(botvrij)
        self.assertEqual(r['message'], 'Feed caching job initiated.')
        # Fetch
        # Cannot test that, it fetches all the events.
        # r = self.admin_misp_connector.fetch_feed(botvrij)
        # FIXME https://github.com/MISP/MISP/issues/4834#issuecomment-511889274
        # self.assertEqual(r['message'], 'Feed caching job initiated.')

        # Cache all enabled feeds
        r = self.admin_misp_connector.cache_all_feeds()
        self.assertEqual(r['message'], 'Feed caching job initiated.')
        # Compare all enabled feeds
        r = self.admin_misp_connector.compare_feeds()
        # FIXME: https://github.com/MISP/MISP/issues/4834#issuecomment-511890466
        # self.assertEqual(r['message'], 'Feed caching job initiated.')
        # Disable both feeds
        feed = self.admin_misp_connector.disable_feed(feeds[0].id, pythonify=True)
        self.assertFalse(feed.enabled)
        feed = self.admin_misp_connector.disable_feed(botvrij.id, pythonify=True)
        self.assertFalse(feed.enabled)
        feed = self.admin_misp_connector.disable_feed_cache(feeds[0].id, pythonify=True)
        self.assertFalse(feed.enabled)
        feed = self.admin_misp_connector.disable_feed_cache(botvrij.id, pythonify=True)
        self.assertFalse(feed.enabled)
        # Test enable csv feed - https://github.com/MISP/PyMISP/issues/574
        feeds = self.admin_misp_connector.feeds(pythonify=True)
        for feed in feeds:
            if feed.name == 'blockrules of rules.emergingthreats.net':
                e_thread_csv_feed = feed
                break
        updated_feed = self.admin_misp_connector.enable_feed(e_thread_csv_feed, pythonify=True)
        self.assertEqual(updated_feed.settings, e_thread_csv_feed.settings)
        updated_feed = self.admin_misp_connector.disable_feed(e_thread_csv_feed, pythonify=True)
        self.assertEqual(updated_feed.settings, e_thread_csv_feed.settings)

        # Test partial update
        updated_feed = self.admin_misp_connector.enable_feed(e_thread_csv_feed.id, pythonify=True)
        self.assertEqual(updated_feed.settings, e_thread_csv_feed.settings)

    def test_servers(self):
        # add
        server = MISPServer()
        server.name = 'Test Server'
        server.url = 'https://127.0.0.1'
        server.remote_org_id = 1
        server.authkey = key
        server = self.admin_misp_connector.add_server(server, pythonify=True)
        self.assertEqual(server.name, 'Test Server')
        # Update
        server.name = 'Updated name'
        server = self.admin_misp_connector.update_server(server, pythonify=True)
        self.assertEqual(server.name, 'Updated name')
        # List
        servers = self.admin_misp_connector.servers(pythonify=True)
        self.assertEqual(servers[0].name, 'Updated name')
        # Delete
        r = self.admin_misp_connector.delete_server(server)
        self.assertEqual(r['name'], 'Server deleted')

    def test_roles_expanded(self):
        '''Test all possible things regarding roles
        1. Use existing roles (ID in test VM):
            * Read only (6):  Can only connect via API and see events visible by its organisation
            * User (3): Same as readonly + create event, tag (using existing tags), add sighting
            * Publisher (4): Same as User + publish (also on zmq and kafka), and delegate
            * Org Admin (2): Same as publisher + admin org, audit, create tags, templates, sharing groups
            * Sync user (5): Same as publisher + sync, create tag, sharing group
            * admin (1): Same as Org admin and sync user + site admin, edit regexes, edit object templates
        2. Create roles:
            * No Auth key access
            * Auth key (=> Read only)
            * + tagger
            * + sightings creator (=> User)
            * +
        '''
        # Creates a test user for roles
        user = MISPUser()
        user.email = 'testusr-roles@user.local'
        user.org_id = self.test_org.id
        tag = MISPTag()
        tag.name = 'tlp:white___test'
        try:
            test_roles_user = self.admin_misp_connector.add_user(user, pythonify=True)
            test_tag = self.admin_misp_connector.add_tag(tag, pythonify=True)
            test_roles_user_connector = PyMISP(url, test_roles_user.authkey, verifycert, debug=False)
            test_roles_user_connector.toggle_global_pythonify()
            # ===== Read Only
            self.admin_misp_connector.update_user({'role_id': 6}, test_roles_user)
            base_event = MISPEvent()
            base_event.info = 'Test Roles'
            base_event.distribution = 0
            base_event.add_attribute('ip-dst', '8.8.8.8')
            base_event.add_attribute('ip-dst', '9.9.9.9')
            base_event.attributes[0].add_tag('tlp:white___test')
            r = test_roles_user_connector.add_event(base_event)
            self.assertTrue(isinstance(r['errors'], tuple), r['errors'])
            self.assertEqual(r['errors'][1]['message'], 'You do not have permission to use this functionality.', r)
            try:
                e = self.user_misp_connector.add_event(base_event, pythonify=True)
                e = test_roles_user_connector.get_event(e)
                self.assertEqual(e.info, 'Test Roles')
                self.assertEqual(e.attributes[0].tags[0].name, 'tlp:white___test')
                r = test_roles_user_connector.publish(e)
                self.assertEqual(r['errors'][1]['message'], 'You do not have permission to use this functionality.', r)
                r = test_roles_user_connector.tag(e.attributes[1], 'tlp:white___test')
                self.assertEqual(r['errors'][1]['message'], 'You do not have permission to use this functionality.', r)
                r = test_roles_user_connector.add_sighting({'name': 'foo'}, e.attributes[1])
                self.assertEqual(r['errors'][1]['message'], 'You do not have permission to use this functionality.', r)

                self.user_misp_connector.add_sighting({'source': 'blah'}, e.attributes[0])
                sightings = test_roles_user_connector.sightings(e.attributes[0])
                self.assertEqual(sightings[0].source, 'blah')

                e = test_roles_user_connector.get_event(e)
                self.assertEqual(e.attributes[0].sightings[0].source, 'blah')
                # FIXME: http://github.com/MISP/MISP/issues/5022
                # a = test_roles_user_connector.get_attribute(e.attributes[0])
                # self.assertEqual(a.sightings[0].source, 'blah')

                # ===== User (the capabilities were tested just before, only testing the publisher capabilities)
                self.admin_misp_connector.update_user({'role_id': 3}, test_roles_user)
                r = test_roles_user_connector.publish(e)
                self.assertEqual(r['errors'][1]['message'], 'You do not have permission to use this functionality.', r)
                r = test_roles_user_connector.delegate_event(e, self.test_org_delegate)
                self.assertEqual(r['errors'][1]['message'], 'You do not have permission to use this functionality.', r)
                # ===== Publisher
                # Make sure the delegation is enabled
                r = self.admin_misp_connector.set_server_setting('MISP.delegation', True, force=True)
                self.assertEqual(r['message'], 'Field updated', r)
                setting = self.admin_misp_connector.get_server_setting('MISP.delegation')
                self.assertTrue(setting['value'])
                # ======
                self.admin_misp_connector.update_user({'role_id': 4}, test_roles_user)
                r = test_roles_user_connector.publish(e)
                self.assertEqual(r['message'], 'Job queued', r)
                delegation = test_roles_user_connector.delegate_event(e, self.test_org_delegate)
                self.assertEqual(delegation.org_id, self.test_org_delegate.id)
                self.assertEqual(delegation.requester_org_id, self.test_org.id)
                r = test_roles_user_connector.accept_event_delegation(delegation.id)
                self.assertEqual(r['errors'][1]['message'], 'You are not authorised to do that.', r)
                # Test delegation
                delegations = self.delegate_user_misp_connector.event_delegations()
                self.assertEqual(delegations[0].id, delegation.id)
                r = self.delegate_user_misp_connector.accept_event_delegation(delegation)
                self.assertEqual(r['message'], 'Event ownership transferred.')
                e = self.delegate_user_misp_connector.get_event(e)
                self.assertTrue(isinstance(e, MISPEvent), e)
                self.assertEqual(e.info, 'Test Roles')
                self.assertEqual(e.org.name, 'Test Org - delegate')
                r = self.delegate_user_misp_connector.delete_event(e)
                self.assertEqual(r['message'], 'Event deleted.', r)
                # Change base_event UUID do we can add it
                base_event.uuid = str(uuid4())
                e = test_roles_user_connector.add_event(base_event)
                delegation = test_roles_user_connector.delegate_event(e, self.test_org_delegate)
                r = test_roles_user_connector.discard_event_delegation(delegation.id)
                self.assertEqual(r['message'], 'Delegation request deleted.')

                e = test_roles_user_connector.get_event(e)
                self.assertTrue(isinstance(e, MISPEvent), e)
                self.assertEqual(e.info, 'Test Roles')
                self.assertEqual(e.org_id, int(self.test_org.id))
            finally:
                self.user_misp_connector.delete_event(e)

            # Publisher
            self.admin_misp_connector.update_user({'role_id': 4}, test_roles_user)
            # Org Admin
            self.admin_misp_connector.update_user({'role_id': 2}, test_roles_user)
            # Sync User
            self.admin_misp_connector.update_user({'role_id': 5}, test_roles_user)
            # Admin
            self.admin_misp_connector.update_user({'role_id': 1}, test_roles_user)
        finally:
            self.admin_misp_connector.delete_user(test_roles_user)
            self.admin_misp_connector.delete_tag(test_tag)

    def test_expansion(self):
        first = self.create_simple_event()
        try:
            md5_disk = hashlib.md5()
            with open('tests/viper-test-files/test_files/sample2.pe', 'rb') as f:
                filecontent = f.read()
                md5_disk.update(filecontent)
                malware_sample_initial_attribute = first.add_attribute('malware-sample', value='Big PE sample', data=BytesIO(filecontent), expand='binary')
            md5_init_attribute = hashlib.md5()
            md5_init_attribute.update(malware_sample_initial_attribute.malware_binary.getvalue())
            self.assertEqual(md5_init_attribute.digest(), md5_disk.digest())

            first.run_expansions()
            first = self.admin_misp_connector.add_event(first, pythonify=True)
            self.assertEqual(len(first.objects), 8, first.objects)
            # Speed test
            # # reference time
            start = time.time()
            self.admin_misp_connector.get_event(first.id, pythonify=False)
            ref_time = time.time() - start
            # # Speed test pythonify
            start = time.time()
            first = self.admin_misp_connector.get_event(first.id, pythonify=True)
            pythonify_time = time.time() - start
            self.assertTrue((pythonify_time - ref_time) <= 0.5, f'Pythonify too slow: {ref_time} vs. {pythonify_time}.')

            # Test on demand decrypt malware binary
            file_objects = first.get_objects_by_name('file')
            samples = file_objects[0].get_attributes_by_relation('malware-sample')
            binary = samples[0].malware_binary
            md5_from_server = hashlib.md5()
            md5_from_server.update(binary.getvalue())
            self.assertEqual(md5_from_server.digest(), md5_disk.digest())
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)

    def test_user_settings(self):
        first = self.create_simple_event()
        first.distribution = 3
        first.add_tag('test_publish_filter')
        first.add_tag('test_publish_filter_not')
        second = self.create_simple_event()
        second.distribution = 3
        try:
            # Set
            setting = self.admin_misp_connector.set_user_setting('dashboard_access', 1, pythonify=True)
            setting_value = {'Tag.name': 'test_publish_filter'}
            setting = self.admin_misp_connector.set_user_setting('publish_alert_filter', setting_value, pythonify=True)
            self.assertTrue(isinstance(setting, MISPUserSetting))
            self.assertEqual(setting.value, setting_value)

            # Get
            # FIXME: https://github.com/MISP/MISP/issues/5297
            # setting = self.admin_misp_connector.get_user_setting('dashboard_access', pythonify=True)

            # Get All
            user_settings = self.admin_misp_connector.user_settings(pythonify=True)
            # TODO: Make that one better
            self.assertTrue(isinstance(user_settings, list))

            # Test if publish_alert_filter works
            # # Enable autoalert on admin
            self.admin_misp_connector._current_user.autoalert = True
            self.admin_misp_connector._current_user.termsaccepted = True
            self.user_misp_connector.update_user(self.admin_misp_connector._current_user)

            first = self.admin_misp_connector.add_event(first, pythonify=True)
            second = self.admin_misp_connector.add_event(second, pythonify=True)
            r = self.user_misp_connector.change_user_password('Password1234')
            self.assertEqual(r['message'], 'Password Changed.')
            self.test_usr.autoalert = True
            self.test_usr.termsaccepted = True
            user = self.user_misp_connector.update_user(self.test_usr, pythonify=True)
            self.assertTrue(user.autoalert)
            self.admin_misp_connector.publish(first, alert=True)
            self.admin_misp_connector.publish(second, alert=True)
            time.sleep(10)
            # FIXME https://github.com/MISP/MISP/issues/4872
            # mail_logs = self.admin_misp_connector.search_logs(model='User', action='email', limit=2, pythonify=True)
            mail_logs = self.admin_misp_connector.search_logs(model='User', action='email', created=datetime.now() - timedelta(seconds=30), pythonify=True)
            if mail_logs:
                # FIXME: On travis, the mails aren't working, so we stik that.
                self.assertEqual(len(mail_logs), 3)
                self.assertTrue(mail_logs[0].title.startswith(f'Email  to {self.admin_misp_connector._current_user.email}'), mail_logs[0].title)
                self.assertTrue(mail_logs[1].title.startswith(f'Email  to {self.user_misp_connector._current_user.email}'), mail_logs[1].title)
                self.assertTrue(mail_logs[2].title.startswith(f'Email  to {self.user_misp_connector._current_user.email}'), mail_logs[2].title)

            # Delete
            # FIXME: https://github.com/MISP/MISP/issues/5297
            # response = self.admin_misp_connector.delete_user_setting('publish_alert_filter')
        finally:
            self.test_usr.autoalert = False
            self.user_misp_connector.update_user(self.test_usr)
            # Delete event
            self.admin_misp_connector.delete_event(first)
            self.admin_misp_connector.delete_event(second)

    def test_communities(self):
        communities = self.admin_misp_connector.communities(pythonify=True)
        self.assertEqual(communities[0].name, 'CIRCL Private Sector Information Sharing Community - aka MISPPRIV')
        community = self.admin_misp_connector.get_community(communities[1], pythonify=True)
        self.assertEqual(community.name, 'CIRCL n/g CSIRT information sharing community - aka MISP')
        # FIXME: Fails on travis for now due to GPG misconfigured
        # r = self.admin_misp_connector.request_community_access(community, mock=False)
        # self.assertTrue(r['message'], 'Request sent.')
        # r = self.admin_misp_connector.request_community_access(community, mock=True)
        # mail = email.message_from_string(r['headers'] + '\n' + r['message'])
        # for k, v in mail.items():
        #    if k == 'To':
        #        self.assertEqual(v, 'info@circl.lu')

    def test_upload_stix(self):
        # FIXME https://github.com/MISP/MISP/issues/4892
        pass

    def test_toggle_global_pythonify(self):
        first = self.create_simple_event()
        second = self.create_simple_event()
        try:
            self.admin_misp_connector.toggle_global_pythonify()
            first = self.admin_misp_connector.add_event(first)
            self.assertTrue(isinstance(first, MISPEvent))
            self.admin_misp_connector.toggle_global_pythonify()
            second = self.admin_misp_connector.add_event(second)
            self.assertTrue(isinstance(second, dict))
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first)
            self.admin_misp_connector.delete_event(second)

    def test_first_last_seen(self):
        event = MISPEvent()
        event.info = 'Test First Last seen'
        event.add_attribute('ip-dst', '8.8.8.8', first_seen='2020-01-04', last_seen='2020-01-04T12:30:34.323242+0800')
        obj = event.add_object(name='file', first_seen=1580147259.268763, last_seen=1580147300)
        attr = obj.add_attribute('filename', 'blah.exe')
        attr.first_seen = '2022-01-30'
        attr.last_seen = '2022-02-23'
        try:
            first = self.admin_misp_connector.add_event(event, pythonify=True)
            # Simple attribute
            self.assertEqual(first.attributes[0].first_seen, datetime(2020, 1, 4, 0, 0).astimezone())
            self.assertEqual(first.attributes[0].last_seen, datetime(2020, 1, 4, 4, 30, 34, 323242, tzinfo=timezone.utc))

            # Object
            self.assertEqual(first.objects[0].first_seen, datetime(2020, 1, 27, 17, 47, 39, 268763, tzinfo=timezone.utc))
            self.assertEqual(first.objects[0].last_seen, datetime(2020, 1, 27, 17, 48, 20, tzinfo=timezone.utc))

            # Object attribute
            self.assertEqual(first.objects[0].attributes[0].first_seen, datetime(2022, 1, 30, 0, 0).astimezone())
            self.assertEqual(first.objects[0].attributes[0].last_seen, datetime(2022, 2, 23, 0, 0).astimezone())

            # Update values
            # Attribute in full event
            now = datetime.now().astimezone()
            first.attributes[0].last_seen = now
            first = self.admin_misp_connector.update_event(first, pythonify=True)
            self.assertEqual(first.attributes[0].last_seen, now)
            # Object only
            now = datetime.now().astimezone()
            obj = first.objects[0]
            obj.last_seen = now
            obj = self.admin_misp_connector.update_object(obj, pythonify=True)
            self.assertEqual(obj.last_seen, now)
            # Attribute in object only
            now = datetime.now().astimezone()
            attr = obj.attributes[0]
            attr.first_seen = '2020-01-04'
            attr.last_seen = now
            attr = self.admin_misp_connector.update_attribute(attr, pythonify=True)
            self.assertEqual(attr.last_seen, now)

        finally:
            self.admin_misp_connector.delete_event(first)

    def test_registrations(self):
        r = register_user(url, 'self_register@user.local', organisation=self.test_org,
                          org_name=self.test_org.name, verify=verifycert)
        self.assertTrue(r['saved'])

        r = register_user(url, 'discard@tesst.de', verify=verifycert)
        self.assertTrue(r['saved'])

        registrations = self.admin_misp_connector.user_registrations(pythonify=True)
        self.assertTrue(len(registrations), 2)
        self.assertEqual(registrations[0].data['email'], 'self_register@user.local')
        self.assertEqual(registrations[0].data['org_name'], 'Test Org')
        self.assertEqual(registrations[1].data['email'], 'discard@tesst.de')

        m = self.admin_misp_connector.accept_user_registration(registrations[0], unsafe_fallback=True)
        self.assertTrue(m['saved'])

        # delete new user
        for user in self.admin_misp_connector.users(pythonify=True):
            if user.email == registrations[0].data['email']:
                self.admin_misp_connector.delete_user(user)
                break

        # Expected: accept registration fails because the orgname is missing
        m = self.admin_misp_connector.accept_user_registration(registrations[1], unsafe_fallback=True)
        self.assertEqual(m['errors'][1]['message'], 'No organisation selected. Supply an Organisation ID')

        m = self.admin_misp_connector.discard_user_registration(registrations[1].id)
        self.assertEqual(m['name'], '1 registration(s) discarded.')

    def test_search_workflow(self):
        first = self.create_simple_event()
        first.add_attribute('domain', 'google.com')
        tag = MISPTag()
        tag.name = 'my_tag'
        try:
            # Note: attribute 0 doesn't matter
            # Attribute 1 = google.com, no tag
            # Init tag and event
            tag = self.admin_misp_connector.add_tag(tag, pythonify=True)
            self.assertEqual(tag.name, 'my_tag')
            first = self.user_misp_connector.add_event(first, pythonify=True)
            time.sleep(10)
            # Add tag to attribute 1, add attribute 2, update
            first.attributes[1].add_tag(tag)
            first.add_attribute('domain', 'google.fr')
            # Attribute 1 = google.com, tag
            # Attribute 2 = google.fr, no tag
            first = self.user_misp_connector.update_event(first, pythonify=True)
            self.assertEqual(first.attributes[1].tags[0].name, 'my_tag')
            self.assertEqual(first.attributes[2].tags, [])
            updated_attrs = self.user_misp_connector.search(controller='attributes', eventid=first.id, timestamp='5s', pythonify=True)
            # Get two attributes, 0 (google.com) has a tag, 1 (google.fr) doesn't
            self.assertEqual(len(updated_attrs), 2)
            self.assertEqual(updated_attrs[0].tags[0].name, 'my_tag')
            self.assertEqual(updated_attrs[1].value, 'google.fr')
            self.assertEqual(updated_attrs[1].tags, [])
            # Get the metadata only of the event
            first_meta_only = self.user_misp_connector.search(eventid=first.id, metadata=True, pythonify=True)

            # Add tag to attribute 1 (google.fr)
            attr_to_update = updated_attrs[1]
            attr_to_update.add_tag(tag)
            # attr_to_update.pop('timestamp')
            # Add new attribute to event with metadata only
            first_meta_only[0].add_attribute('domain', 'google.lu')
            # Add tag to new attribute
            first_meta_only[0].attributes[0].add_tag('my_tag')
            # Re-add attribute 1 (google.fr), newly tagged
            first_meta_only[0].add_attribute(**attr_to_update)
            # When we push, all the attributes should be tagged
            first = self.user_misp_connector.update_event(first_meta_only[0], pythonify=True)
            self.assertEqual(first.attributes[1].tags[0].name, 'my_tag')
            self.assertEqual(first.attributes[2].tags[0].name, 'my_tag')
            self.assertEqual(first.attributes[3].tags[0].name, 'my_tag')
        finally:
            self.admin_misp_connector.delete_event(first)
            self.admin_misp_connector.delete_tag(tag)

    def test_search_workflow_ts(self):
        first = self.create_simple_event()
        first.add_attribute('domain', 'google.com')
        tag = MISPTag()
        tag.name = 'my_tag'
        try:
            # Note: attribute 0 doesn't matter
            # Attribute 1 = google.com, no tag
            # Init tag and event
            tag = self.admin_misp_connector.add_tag(tag, pythonify=True)
            self.assertEqual(tag.name, 'my_tag')
            first = self.user_misp_connector.add_event(first, pythonify=True)
            time.sleep(10)
            # Add tag to attribute 1, add attribute 2, update
            first.attributes[1].add_tag(tag)
            first.add_attribute('domain', 'google.fr')
            # Attribute 1 = google.com, tag
            # Attribute 2 = google.fr, no tag
            first = self.user_misp_connector.update_event(first, pythonify=True)
            self.assertEqual(first.attributes[1].tags[0].name, 'my_tag')
            self.assertEqual(first.attributes[2].tags, [])
            updated_attrs = self.user_misp_connector.search(controller='attributes', eventid=first.id, timestamp=first.timestamp.timestamp(), pythonify=True)
            # Get two attributes, 0 (google.com) has a tag, 1 (google.fr) doesn't
            self.assertEqual(len(updated_attrs), 2)
            self.assertEqual(updated_attrs[0].tags[0].name, 'my_tag')
            self.assertEqual(updated_attrs[1].value, 'google.fr')
            self.assertEqual(updated_attrs[1].tags, [])
            # Get the metadata only of the event
            first_meta_only = self.user_misp_connector.search(eventid=first.id, metadata=True, pythonify=True)

            # Add tag to attribute 1 (google.fr)
            attr_to_update = updated_attrs[1]
            attr_to_update.add_tag(tag)
            # attr_to_update.pop('timestamp')
            # Add new attribute to event with metadata only
            first_meta_only[0].add_attribute('domain', 'google.lu')
            # Add tag to new attribute
            first_meta_only[0].attributes[0].add_tag('my_tag')
            # Re-add attribute 1 (google.fr), newly tagged
            first_meta_only[0].add_attribute(**attr_to_update)
            # When we push, all the attributes should be tagged
            first = self.user_misp_connector.update_event(first_meta_only[0], pythonify=True)
            self.assertEqual(first.attributes[1].tags[0].name, 'my_tag')
            self.assertEqual(first.attributes[2].tags[0].name, 'my_tag')
            self.assertEqual(first.attributes[3].tags[0].name, 'my_tag')
        finally:
            self.admin_misp_connector.delete_event(first)
            self.admin_misp_connector.delete_tag(tag)

    def test_blocklists(self):
        first = self.create_simple_event()
        second = self.create_simple_event()
        second.Orgc = self.test_org
        to_delete = {'bl_events': [], 'bl_organisations': []}
        try:
            # test events BL
            ebl = self.admin_misp_connector.add_event_blocklist(uuids=[first.uuid])
            self.assertEqual(ebl['result']['successes'][0], first.uuid, ebl)
            bl_events = self.admin_misp_connector.event_blocklists(pythonify=True)
            for ble in bl_events:
                if ble.event_uuid == first.uuid:
                    to_delete['bl_events'].append(ble)
                    break
            else:
                raise Exception('Unable to find UUID in Events blocklist')
            first = self.user_misp_connector.add_event(first, pythonify=True)
            self.assertEqual(first['errors'][1]['message'], 'Could not add Event', first)
            ble.comment = 'This is a test'
            ble.event_info = 'foo'
            ble.event_orgc = 'bar'
            ble = self.admin_misp_connector.update_event_blocklist(ble, pythonify=True)
            self.assertEqual(ble.comment, 'This is a test')
            r = self.admin_misp_connector.delete_event_blocklist(ble)
            self.assertTrue(r['success'])

            # test Org BL
            obl = self.admin_misp_connector.add_organisation_blocklist(uuids=self.test_org.uuid)
            self.assertEqual(obl['result']['successes'][0], self.test_org.uuid, obl)
            bl_orgs = self.admin_misp_connector.organisation_blocklists(pythonify=True)
            for blo in bl_orgs:
                if blo.org_uuid == self.test_org.uuid:
                    to_delete['bl_organisations'].append(blo)
                    break
            else:
                raise Exception('Unable to find UUID in Orgs blocklist')
            first = self.user_misp_connector.add_event(first, pythonify=True)
            self.assertEqual(first['errors'][1]['message'], 'Could not add Event', first)

            blo.comment = 'This is a test'
            blo.org_name = 'bar'
            blo = self.admin_misp_connector.update_organisation_blocklist(blo, pythonify=True)
            self.assertEqual(blo.org_name, 'bar')
            r = self.admin_misp_connector.delete_organisation_blocklist(blo)
            self.assertTrue(r['success'])

        finally:
            for ble in to_delete['bl_events']:
                self.admin_misp_connector.delete_event_blocklist(ble)
            for blo in to_delete['bl_organisations']:
                self.admin_misp_connector.delete_organisation_blocklist(blo)

    @unittest.skip("Internal use only")
    def missing_methods(self):
        skip = [
            "attributes/download",
            "attributes/add_attachment",
            "attributes/add_threatconnect",
            "attributes/editField",
            "attributes/viewPicture",
            "attributes/restore",
            "attributes/deleteSelected",
            "attributes/editSelected",
            "attributes/search",
            "attributes/searchAlternate",
            "attributes/checkComposites",
            "attributes/downloadAttachment",
            "attributes/returnAttributes",
            "attributes/text",
            "attributes/rpz",
            "attributes/bro",
            "attributes/reportValidationIssuesAttributes",
            "attributes/generateCorrelation",
            "attributes/getMassEditForm",
            "attributes/fetchViewValue",
            "attributes/fetchEditForm",
            "attributes/attributeReplace",
            "attributes/downloadSample",
            "attributes/pruneOrphanedAttributes",
            "attributes/checkOrphanedAttributes",
            "attributes/updateAttributeValues",
            "attributes/hoverEnrichment",
            "attributes/addTag",
            "attributes/removeTag",
            "attributes/toggleCorrelation",  # Use update attribute
            "attributes/toggleToIDS",  # Use update attribute
            "attributes/checkAttachments",
            "attributes/exportSearch",
            'dashboards',
            'decayingModel',
            "eventBlocklists/massDelete",
            "eventDelegations/view",
            "eventDelegations/index",
            "eventGraph/view",
            "eventGraph/add",
            "eventGraph/delete",
            "events/filterEventIndex",
            "events/viewEventAttributes",
            "events/removePivot",
            "events/addIOC",
            "events/add_misp_export",
            "events/merge",
            "events/unpublish",
            "events/publishSightings",
            "events/automation",
            "events/export",
            "events/downloadExport",
            "events/xml",
            "events/nids",
            "events/hids",
            "events/csv",
            "events/downloadOpenIOCEvent",
            "events/proposalEventIndex",
            "events/reportValidationIssuesEvents",
            "events/addTag",
            "events/removeTag",
            "events/saveFreeText",
            "events/stix2",
            "events/stix",
            "events/filterEventIdsForPush",
            "events/checkuuid",
            "events/pushProposals",
            "events/exportChoice",
            "events/importChoice",
            "events/upload_sample",
            "events/viewGraph",
            "events/viewEventGraph",
            "events/updateGraph",
            "events/genDistributionGraph",
            "events/getEventTimeline",
            "events/getDistributionGraph",
            "events/getEventGraphReferences",
            "events/getEventGraphTags",
            "events/getEventGraphGeneric",
            "events/getReferenceData",
            "events/getObjectTemplate",
            "events/viewGalaxyMatrix",
            "events/delegation_index",
            "events/queryEnrichment",
            "events/handleModuleResults",
            "events/importModule",
            "events/exportModule",
            "events/toggleCorrelation",  # TODO
            "events/checkPublishedStatus",
            "events/pushEventToKafka",
            "events/getEventInfoById",
            "events/enrichEvent",  # TODO
            "events/checkLocks",
            "events/getEditStrategy",
            "events/upload_analysis_file",
            "events/cullEmptyEvents",
            "favouriteTags/toggle",  # TODO
            "favouriteTags/getToggleField",  # TODO
            "feeds/feedCoverage",
            "feeds/importFeeds",
            "feeds/fetchFromAllFeeds",
            "feeds/getEvent",
            "feeds/previewIndex",  # TODO
            "feeds/previewEvent",  # TODO
            "feeds/enable",
            "feeds/disable",
            "feeds/fetchSelectedFromFreetextIndex",
            "feeds/toggleSelected",  # TODO
            "galaxies/delete",
            "galaxies/selectGalaxy",
            "galaxies/selectGalaxyNamespace",
            "galaxies/selectCluster",
            "galaxies/attachCluster",
            "galaxies/attachMultipleClusters",
            "galaxies/viewGraph",
            "galaxies/showGalaxies",
            "galaxyClusters/index",
            "galaxyClusters/view",
            "galaxyClusters/attachToEvent",
            "galaxyClusters/detach",
            "galaxyClusters/delete",
            "galaxyClusters/viewGalaxyMatrix",
            "galaxyElements/index",
            "jobs/index",
            "jobs/getError",
            "jobs/getGenerateCorrelationProgress",
            "jobs/getProgress",
            "jobs/cache",
            "jobs/clearJobs",
            "logs/event_index",
            "admin/logs/search",
            "logs/returnDates",
            "logs/pruneUpdateLogs",
            "logs/testForStolenAttributes",
            "modules/queryEnrichment",
            "modules/index",
            "news/index",
            "news/add",
            "news/edit",
            "news/delete",
            "noticelists/toggleEnable",
            "noticelists/getToggleField",
            "noticelists/delete",
            "objectReferences/view",
            "objectTemplateElements/viewElements",
            "objectTemplates/objectMetaChoice",
            "objectTemplates/objectChoice",
            "objectTemplates/delete",
            "objectTemplates/viewElements",
            "objectTemplates/activate",
            "objectTemplates/getToggleField",
            "objects/revise_object",
            "objects/get_row",
            "objects/editField",
            "objects/fetchViewValue",
            "objects/fetchEditForm",
            "objects/quickFetchTemplateWithValidObjectAttributes",
            "objects/quickAddAttributeForm",
            "objects/orphanedObjectDiagnostics",
            "objects/proposeObjectsFromAttributes",
            "objects/groupAttributesIntoObject",
            "admin/organisations/generateuuid",
            "organisations/landingpage",
            "organisations/fetchOrgsForSG",
            "organisations/fetchSGOrgRow",
            "organisations/getUUIDs",
            "admin/organisations/merge",
            "pages/display",
            "posts/pushMessageToZMQ",
            "posts/add",
            "posts/edit",
            "posts/delete",
            "admin/regexp/add",
            "admin/regexp/index",
            "admin/regexp/edit",
            "admin/regexp/delete",
            "regexp/index",
            "admin/regexp/clean",
            "regexp/cleanRegexModifiers",
            "restClientHistory/index",
            "restClientHistory/delete",
            "roles/view",
            "admin/roles/add",  # TODO
            "admin/roles/edit",  # TODO
            "admin/roles/index",  # TODO
            "admin/roles/delete",  # TODO
            "servers/previewIndex",
            "servers/previewEvent",
            "servers/filterEventIndex",
            "servers/eventBlockRule",
            "servers/serverSettingsReloadSetting",
            "servers/startWorker",  # TODO
            "servers/stopWorker",  # TODO
            "servers/getWorkers",  # TODO
            "servers/getSubmodulesStatus",  # TODO,
            "servers/restartDeadWorkers",  # TODO
            "servers/deleteFile",
            "servers/uploadFile",
            "servers/fetchServersForSG",
            "servers/postTest",
            "servers/getRemoteUser",
            "servers/startZeroMQServer",
            "servers/stopZeroMQServer",
            "servers/statusZeroMQServer",
            "servers/purgeSessions",
            "servers/clearWorkerQueue",  # TODO
            "servers/getGit",
            "servers/checkout",
            "servers/ondemandAction",
            "servers/updateProgress",
            "servers/getSubmoduleQuickUpdateForm",
            "servers/updateSubmodule",
            "servers/getInstanceUUID",
            "servers/getApiInfo",
            "servers/cache",
            "servers/updateJSON",
            "servers/resetRemoteAuthKey",
            "servers/changePriority",
            "servers/releaseUpdateLock",
            "servers/viewDeprecatedFunctionUse",
            "shadowAttributes/download",
            "shadowAttributes/add_attachment",
            "shadowAttributes/discardSelected",
            "shadowAttributes/acceptSelected",
            "shadowAttributes/generateCorrelation",
            "sharingGroups/edit",
            "sharingGroups/view",
            "sightingdb/add",
            "sightingdb/edit",
            "sightingdb/delete",
            "sightingdb/index",
            "sightingdb/requestStatus",
            "sightingdb/search",
            "sightings/advanced",
            "sightings/quickAdd",
            "sightings/quickDelete",
            "sightings/viewSightings",
            "sightings/bulkSaveSightings",
            "tagCollections/add",
            "tagCollections/import",
            "tagCollections/view",
            "tagCollections/edit",
            "tagCollections/delete",
            "tagCollections/addTag",
            "tagCollections/removeTag",
            "tagCollections/index",
            "tagCollections/getRow",
            "tags/quickAdd",
            "tags/showEventTag",
            "tags/showAttributeTag",
            "tags/showTagControllerTag",
            "tags/viewTag",
            "tags/selectTaxonomy",
            "tags/selectTag",
            "tags/viewGraph",
            "tags/search",
            "tasks/index",
            "tasks/setTask",
            "taxonomies/hideTag",
            "taxonomies/unhideTag",
            "taxonomies/taxonomyMassConfirmation",
            "taxonomies/taxonomyMassHide",
            "taxonomies/taxonomyMassUnhide",
            "taxonomies/delete",
            "taxonomies/toggleRequired",
            "templateElements/index",
            "templateElements/templateElementAddChoices",
            "templateElements/add",
            "templateElements/edit",
            "templateElements/delete",
            "templates/index",
            "templates/edit",
            "templates/view",
            "templates/add",
            "templates/saveElementSorting",
            "templates/delete",
            "templates/templateChoices",
            "templates/populateEventFromTemplate",
            "templates/submitEventPopulation",
            "templates/uploadFile",
            "templates/deleteTemporaryFile",
            "threads/viewEvent",
            "threads/view",
            "threads/index",
            "userSettings/view",
            "userSettings/setHomePage",
            "users/request_API",
            "admin/users/filterUserIndex",
            "admin/users/view",
            "admin/users/edit",
            "users/updateLoginTime",
            "users/login",
            "users/routeafterlogin",
            "users/logout",
            "users/resetauthkey",
            "users/resetAllSyncAuthKeys",
            "users/histogram",
            "users/terms",
            "users/downloadTerms",
            "users/checkAndCorrectPgps",
            "admin/users/quickEmail",
            "admin/users/email",
            "users/initiatePasswordReset",
            "users/email_otp",
            "users/tagStatisticsGraph",
            "users/verifyGPG",
            "users/verifyCertificate",
            "users/searchGpgKey",
            "users/fetchGpgKey",
            "users/checkIfLoggedIn",
            "admin/users/monitor",
            "warninglists/enableWarninglist",
            "warninglists/getToggleField",
            "warninglists/delete",
            "admin/allowedlists/add",
            "admin/allowedlists/index",
            "admin/allowedlists/edit",
            "admin/allowedlists/delete",
            "allowedlists/index"
        ]
        missing = self.admin_misp_connector.get_all_functions(True)
        with open('all_missing.json', 'w') as f:
            json.dump(missing, f, indent=2)
        final_missing = []
        for m in missing:
            if any(m.startswith(s) for s in skip):
                continue
            final_missing.append(m)
        with open('plop', 'w') as f:
            json.dump(final_missing, f, indent=2)
        print(final_missing)
        print(len(final_missing))
        raise Exception()


if __name__ == '__main__':
    unittest.main()
