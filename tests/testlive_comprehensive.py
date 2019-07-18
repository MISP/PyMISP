#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys


import unittest

from pymisp.tools import make_binary_objects
from datetime import datetime, timedelta, date
from io import BytesIO
import re
import json
from pathlib import Path

import urllib3
import time
from uuid import uuid4

import logging
logging.disable(logging.CRITICAL)

try:
    from pymisp import ExpandedPyMISP, MISPEvent, MISPOrganisation, MISPUser, Distribution, ThreatLevel, Analysis, MISPObject, MISPAttribute, MISPSighting, MISPShadowAttribute, MISPTag, MISPSharingGroup, MISPFeed, MISPServer
    from pymisp.tools import CSVLoader, DomainIPObject, ASNObject, GenericObjectGenerator
except ImportError:
    if sys.version_info < (3, 6):
        print('This test suite requires Python 3.6+, breaking.')
        sys.exit(0)
    else:
        raise

try:
    from keys import url, key
    verifycert = False
    travis_run = True
except ImportError as e:
    print(e)
    url = 'https://localhost:8443'
    key = 'K5yV0CcxdnklzDfCKlnPniIxrMX41utQ2dG13zZ3'
    verifycert = False
    travis_run = False


urllib3.disable_warnings()


class TestComprehensive(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.maxDiff = None
        # Connect as admin
        cls.admin_misp_connector = ExpandedPyMISP(url, key, verifycert, debug=False)
        # Creates an org
        organisation = MISPOrganisation()
        organisation.name = 'Test Org'
        cls.test_org = cls.admin_misp_connector.add_organisation(organisation)
        # Set the refault role (id 3 on the VM)
        cls.admin_misp_connector.set_default_role(3)
        # Creates a user
        user = MISPUser()
        user.email = 'testusr@user.local'
        user.org_id = cls.test_org.id
        cls.test_usr = cls.admin_misp_connector.add_user(user, pythonify=True)
        cls.user_misp_connector = ExpandedPyMISP(url, cls.test_usr.authkey, verifycert, debug=False)
        # Creates a publisher
        user = MISPUser()
        user.email = 'testpub@user.local'
        user.org_id = cls.test_org.id
        user.role_id = 4
        cls.test_pub = cls.admin_misp_connector.add_user(user, pythonify=True)
        cls.pub_misp_connector = ExpandedPyMISP(url, cls.test_pub.authkey, verifycert)
        # Update all json stuff
        cls.admin_misp_connector.update_object_templates()
        cls.admin_misp_connector.update_galaxies()
        cls.admin_misp_connector.update_noticelists()
        cls.admin_misp_connector.update_warninglists()
        cls.admin_misp_connector.update_taxonomies()

    @classmethod
    def tearDownClass(cls):
        # Delete publisher
        cls.admin_misp_connector.delete_user(cls.test_pub.id)
        # Delete user
        cls.admin_misp_connector.delete_user(cls.test_usr.id)
        # Delete org
        cls.admin_misp_connector.delete_organisation(cls.test_org.id)

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
        first_event.add_attribute('text', str(uuid4()))
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
        second_event.add_attribute('text', str(uuid4()))
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
        third_event.add_attribute('text', str(uuid4()))
        third_event.attributes[0].add_tag('tlp:amber___test')
        third_event.attributes[0].add_tag('foo_double___test')
        third_event.add_attribute('ip-src', '8.8.8.8')
        third_event.attributes[1].add_tag('tlp:amber___test')
        third_event.add_attribute('ip-dst', '9.9.9.9')

        # Create first and third event as admin
        # usr won't be able to see the first one
        first = self.admin_misp_connector.add_event(first_event)
        third = self.admin_misp_connector.add_event(third_event)
        # Create second event as user
        second = self.user_misp_connector.add_event(second_event)
        return first, second, third

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
            events = self.user_misp_connector.search(value=first.attributes[0].value, pythonify=True)
            self.assertEqual(len(events), 1)
            for e in events:
                self.assertIn(e.id, [second.id])
            # Non-existing value
            events = self.user_misp_connector.search(value=str(uuid4()), pythonify=True)
            self.assertEqual(events, [])
        finally:
            # Delete events
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)
            self.admin_misp_connector.delete_event(third.id)

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
            attributes = self.user_misp_connector.search(controller='attributes', value=first.attributes[0].value, pythonify=True)
            self.assertEqual(len(attributes), 1)
            for a in attributes:
                self.assertIn(a.event_id, [second.id])
            # Non-existing value
            attributes = self.user_misp_connector.search(controller='attributes', value=str(uuid4()), pythonify=True)
            self.assertEqual(attributes, [])
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)
            self.admin_misp_connector.delete_event(third.id)

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
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)
            self.admin_misp_connector.delete_event(third.id)

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
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)
            self.admin_misp_connector.delete_event(third.id)

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
            events = self.user_misp_connector.search(tags='tlp:white___test', pythonify=True)
            self.assertEqual(len(events), 2)
            for e in events:
                self.assertIn(e.id, [second.id, third.id])
            events = self.user_misp_connector.search(tags='tlp:amber___test', pythonify=True)
            self.assertEqual(len(events), 2)
            for e in events:
                self.assertIn(e.id, [second.id, third.id])
            events = self.user_misp_connector.search(tags='admin_only', pythonify=True)
            self.assertEqual(events, [])
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)
            self.admin_misp_connector.delete_event(third.id)

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
            attributes = self.user_misp_connector.search(controller='attributes', tags='tlp:white___test', pythonify=True)
            self.assertEqual(len(attributes), 4)
            attributes = self.user_misp_connector.search(controller='attributes', tags='tlp:amber___test', pythonify=True)
            self.assertEqual(len(attributes), 3)
            attributes = self.user_misp_connector.search(tags='admin_only', pythonify=True)
            self.assertEqual(attributes, [])
            attributes_tags_search = self.admin_misp_connector.build_complex_query(or_parameters=['tlp:amber___test'], not_parameters=['tlp:white___test'])
            attributes = self.user_misp_connector.search(controller='attributes', tags=attributes_tags_search, pythonify=True)
            self.assertEqual(len(attributes), 1)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)
            self.admin_misp_connector.delete_event(third.id)

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
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)
            self.admin_misp_connector.delete_event(third.id)

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
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)
            self.admin_misp_connector.delete_event(third.id)

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
            events = self.user_misp_connector.search(timestamp='4m', pythonify=True)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, second.id)
            self.assertEqual(events[0].timestamp.timestamp(), int(event_creation_timestamp_second.timestamp()))

            # # Test timestamp of 2nd event
            events = self.user_misp_connector.search(timestamp=event_creation_timestamp_second.timestamp(), pythonify=True)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, second.id)
            self.assertEqual(events[0].timestamp.timestamp(), int(event_creation_timestamp_second.timestamp()))

            # # Test interval -6 min -> -4 min
            events = self.user_misp_connector.search(timestamp=['6m', '4m'], pythonify=True)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, first.id)
            self.assertEqual(events[0].timestamp.timestamp(), int(event_creation_timestamp_first.timestamp()))
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)

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
            attributes = self.user_misp_connector.search(controller='attributes', timestamp='4m', pythonify=True)
            self.assertEqual(len(attributes), 1)
            self.assertEqual(attributes[0].event_id, second.id)
            self.assertEqual(attributes[0].timestamp.timestamp(), int(event_creation_timestamp_second.timestamp()))

            # # Test timestamp of 2nd event
            attributes = self.user_misp_connector.search(controller='attributes', timestamp=event_creation_timestamp_second.timestamp(), pythonify=True)
            self.assertEqual(len(attributes), 1)
            self.assertEqual(attributes[0].event_id, second.id)
            self.assertEqual(attributes[0].timestamp.timestamp(), int(event_creation_timestamp_second.timestamp()))

            # # Test interval -6 min -> -4 min
            attributes = self.user_misp_connector.search(controller='attributes', timestamp=['6m', '4m'], pythonify=True)
            self.assertEqual(len(attributes), 1)
            self.assertEqual(attributes[0].event_id, first.id)
            self.assertEqual(attributes[0].timestamp.timestamp(), int(event_creation_timestamp_first.timestamp()))
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)

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
            first = self.pub_misp_connector.update_event(first)
            self.assertTrue(first.published)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)

    def test_search_publish_timestamp(self):
        '''Search for a specific publication timestamp, an interval, and invalid values.'''
        # Creating event 1
        first = self.create_simple_event()
        first.publish()
        # Creating event 2
        second = self.create_simple_event()
        second.publish()
        try:
            first = self.pub_misp_connector.add_event(first)
            time.sleep(10)
            second = self.pub_misp_connector.add_event(second)
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
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)

    def test_default_distribution(self):
        '''The default distributions on the VM are This community only for the events and Inherit from event for attr/obj)'''
        if travis_run:
            return
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
            attribute = self.user_misp_connector.add_attribute(first.id, {'type': 'comment', 'value': 'bar'}, pythonify=True)
            self.assertEqual(attribute.value, 'bar', attribute.to_json())
            self.assertEqual(attribute.distribution, Distribution.inherit.value, attribute.to_json())
            # Object - add
            o = MISPObject('file')
            o.add_attribute('filename', value='blah.exe')
            new_obj = self.user_misp_connector.add_object(first.id, o)
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
            self.admin_misp_connector.delete_event(first.id)

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
        second.set_date('2018-09-01')
        second.add_attribute('ip-src', '8.8.8.8')
        # second has two attributes: text and ip-src
        try:
            first = self.user_misp_connector.add_event(first)
            second = self.user_misp_connector.add_event(second)
            timeframe = [first.timestamp.timestamp() - 5, first.timestamp.timestamp() + 5]
            # Search event we just created in multiple ways. Make sure it doesn't catch it when it shouldn't
            events = self.user_misp_connector.search(timestamp=timeframe, pythonify=True)
            self.assertEqual(len(events), 2)
            self.assertEqual(events[0].id, first.id)
            self.assertEqual(events[1].id, second.id)
            events = self.user_misp_connector.search(timestamp=timeframe, value='nothere', pythonify=True)
            self.assertEqual(events, [])
            events = self.user_misp_connector.search(timestamp=timeframe, value=first.attributes[0].value, pythonify=True)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, first.id)
            events = self.user_misp_connector.search(timestamp=[first.timestamp.timestamp() - 50,
                                                                first.timestamp.timestamp() - 10],
                                                     value=first.attributes[0].value, pythonify=True)
            self.assertEqual(events, [])

            # Test return content
            events = self.user_misp_connector.search(timestamp=timeframe, metadata=False, pythonify=True)
            self.assertEqual(len(events), 2)
            self.assertEqual(len(events[0].attributes), 1)
            self.assertEqual(len(events[1].attributes), 2)
            events = self.user_misp_connector.search(timestamp=timeframe, metadata=True, pythonify=True)
            self.assertEqual(len(events), 2)
            self.assertEqual(len(events[0].attributes), 0)
            self.assertEqual(len(events[1].attributes), 0)

            # other things
            events = self.user_misp_connector.search(timestamp=timeframe, published=True, pythonify=True)
            self.assertEqual(events, [])
            events = self.user_misp_connector.search(timestamp=timeframe, published=False, pythonify=True)
            self.assertEqual(len(events), 2)
            events = self.user_misp_connector.search(eventid=first.id, pythonify=True)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, first.id)
            events = self.user_misp_connector.search(uuid=first.uuid, pythonify=True)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, first.id)
            events = self.user_misp_connector.search(org=first.orgc_id, pythonify=True)
            self.assertEqual(len(events), 2)

            # test like search
            events = self.user_misp_connector.search(timestamp=timeframe, value='%{}%'.format(first.attributes[0].value.split('-')[2]), pythonify=True)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, first.id)
            events = self.user_misp_connector.search(timestamp=timeframe, eventinfo='%bar blah%', pythonify=True)
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
            events = self.user_misp_connector.search(timestamp=timeframe, date_from=date.today().isoformat(), pythonify=True)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, first.id)
            events = self.user_misp_connector.search(timestamp=timeframe, date_from='2018-09-01', pythonify=True)
            self.assertEqual(len(events), 2)
            events = self.user_misp_connector.search(timestamp=timeframe, date_from='2018-09-01', date_to='2018-09-02', pythonify=True)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, second.id)

            # Category
            events = self.user_misp_connector.search(timestamp=timeframe, category='Network activity', pythonify=True)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, second.id)

            # toids
            events = self.user_misp_connector.search(timestamp=timeframe, to_ids='0', pythonify=True)
            self.assertEqual(len(events), 2)
            events = self.user_misp_connector.search(timestamp=timeframe, to_ids='1', pythonify=True)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, second.id)
            self.assertEqual(len(events[0].attributes), 1)

            # deleted
            second.attributes[1].delete()
            self.user_misp_connector.update_event(second)
            events = self.user_misp_connector.search(eventid=second.id, pythonify=True)
            self.assertEqual(len(events[0].attributes), 1)
            events = self.user_misp_connector.search(eventid=second.id, deleted=True, pythonify=True)
            self.assertEqual(len(events[0].attributes), 1)

            # include_event_uuid
            attributes = self.user_misp_connector.search(controller='attributes', eventid=second.id, include_event_uuid=True, pythonify=True)
            self.assertEqual(attributes[0].event_uuid, second.uuid)

            # event_timestamp
            time.sleep(1)
            second.add_attribute('ip-src', '8.8.8.9')
            second = self.user_misp_connector.update_event(second)
            events = self.user_misp_connector.search(event_timestamp=second.timestamp.timestamp(), pythonify=True)
            self.assertEqual(len(events), 1)

            # searchall
            second.add_attribute('text', 'This is a test for the full text search', comment='Test stuff comment')
            second = self.user_misp_connector.update_event(second)
            events = self.user_misp_connector.search(value='%for the full text%', searchall=True, pythonify=True)
            self.assertEqual(len(events), 1)

            # warninglist
            response = self.admin_misp_connector.toggle_warninglist(warninglist_name='%dns resolv%', force_enable=True)  # enable ipv4 DNS.
            self.assertDictEqual(response, {'saved': True, 'success': '3 warninglist(s) enabled'})
            second.add_attribute('ip-src', '1.11.71.4')
            second.add_attribute('ip-src', '9.9.9.9')
            second = self.user_misp_connector.update_event(second)

            events = self.user_misp_connector.search(eventid=second.id, pythonify=True)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, second.id)
            self.assertEqual(len(events[0].attributes), 5)

            events = self.user_misp_connector.search(eventid=second.id, enforce_warninglist=False, pythonify=True)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, second.id)
            self.assertEqual(len(events[0].attributes), 5)

            if not travis_run:
                # FIXME: This is failing on travis for no discernable reason...
                events = self.user_misp_connector.search(eventid=second.id, enforce_warninglist=True, pythonify=True)
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0].id, second.id)
                self.assertEqual(len(events[0].attributes), 3)
                response = self.admin_misp_connector.toggle_warninglist(warninglist_name='%dns resolv%')  # disable ipv4 DNS.
                self.assertDictEqual(response, {'saved': True, 'success': '3 warninglist(s) toggled'})

            # Page / limit
            attributes = self.user_misp_connector.search(controller='attributes', eventid=second.id, page=1, limit=3, pythonify=True)
            self.assertEqual(len(attributes), 3)

            attributes = self.user_misp_connector.search(controller='attributes', eventid=second.id, page=2, limit=3, pythonify=True)
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
            events = self.user_misp_connector.search_index(timestamp=first.timestamp.timestamp(),
                                                           pythonify=True)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].info, 'foo bar blah')
            self.assertEqual(events[0].attributes, [])

        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)

    def test_edit_attribute(self):
        first = self.create_simple_event()
        try:
            first.attributes[0].comment = 'This is the original comment'
            first = self.user_misp_connector.add_event(first)
            first.attributes[0].comment = 'This is the modified comment'
            attribute = self.user_misp_connector.update_attribute(first.attributes[0])
            self.assertEqual(attribute.comment, 'This is the modified comment')
            attribute = self.user_misp_connector.update_attribute({'comment': 'This is the modified comment, again'}, attribute.id)
            self.assertEqual(attribute.comment, 'This is the modified comment, again')
            attribute = self.user_misp_connector.update_attribute({'disable_correlation': True}, attribute.id)
            self.assertTrue(attribute.disable_correlation)
            attribute = self.user_misp_connector.update_attribute({'disable_correlation': False}, attribute.id)
            self.assertFalse(attribute.disable_correlation)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)

    def test_sightings(self):
        first = self.create_simple_event()
        second = self.create_simple_event()
        try:
            first = self.user_misp_connector.add_event(first)
            second = self.user_misp_connector.add_event(second)

            current_ts = int(time.time())
            r = self.user_misp_connector.add_sighting({'value': first.attributes[0].value})
            self.assertEqual(r['message'], 'Sighting added')

            s = MISPSighting()
            s.value = second.attributes[0].value
            s.source = 'Testcases'
            s.type = '1'
            r = self.user_misp_connector.add_sighting(s, second.attributes[0].id)
            self.assertEqual(r['message'], 'Sighting added')

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
            s = self.user_misp_connector.sightings(first, pythonify=True)
            self.assertTrue(isinstance(s, list))
            self.assertEqual(int(s[0].attribute_id), first.attributes[0].id)

            r = self.admin_misp_connector.add_sighting(s, second.attributes[0].id)
            self.assertEqual(r['message'], 'Sighting added')
            s = self.user_misp_connector.sightings(second.attributes[0], pythonify=True)
            self.assertEqual(len(s), 2)
            s = self.user_misp_connector.sightings(second.attributes[0], self.test_org.id, pythonify=True)
            self.assertEqual(len(s), 1)
            self.assertEqual(s[0].org_id, self.test_org.id)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)

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

            response = self.user_misp_connector.publish(first.id, alert=False)
            self.assertEqual(response['errors'][1]['message'], 'You do not have permission to use this functionality.')

            # Default search, attribute with to_ids == True
            first.attributes[0].to_ids = True
            first = self.user_misp_connector.update_event(first)
            self.admin_misp_connector.publish(first.id, alert=False)
            csv = self.user_misp_connector.search(return_format='csv', publish_timestamp=first.timestamp.timestamp(), pythonify=True)
            self.assertEqual(len(csv), 1)
            self.assertEqual(csv[0]['value'], first.attributes[0].value)

            # eventid
            csv = self.user_misp_connector.search(return_format='csv', eventid=first.id, pythonify=True)
            self.assertEqual(len(csv), 1)
            self.assertEqual(csv[0]['value'], first.attributes[0].value)

            # category
            csv = self.user_misp_connector.search(return_format='csv', publish_timestamp=first.timestamp.timestamp(), category='Other', pythonify=True)
            self.assertEqual(len(csv), 1)
            self.assertEqual(csv[0]['value'], first.attributes[0].value)
            csv = self.user_misp_connector.search(return_format='csv', publish_timestamp=first.timestamp.timestamp(), category='Person', pythonify=True)
            self.assertEqual(len(csv), 0)

            # type_attribute
            csv = self.user_misp_connector.search(return_format='csv', publish_timestamp=first.timestamp.timestamp(), type_attribute='text', pythonify=True)
            self.assertEqual(len(csv), 1)
            self.assertEqual(csv[0]['value'], first.attributes[0].value)
            csv = self.user_misp_connector.search(return_format='csv', publish_timestamp=first.timestamp.timestamp(), type_attribute='ip-src', pythonify=True)
            self.assertEqual(len(csv), 0)

            # context
            csv = self.user_misp_connector.search(return_format='csv', publish_timestamp=first.timestamp.timestamp(), include_context=True, pythonify=True)
            self.assertEqual(len(csv), 1)
            self.assertTrue('event_info' in csv[0])

            # date_from date_to
            csv = self.user_misp_connector.search(return_format='csv', date_from=date.today().isoformat(), pythonify=True)
            self.assertEqual(len(csv), 1)
            self.assertEqual(csv[0]['value'], first.attributes[0].value)
            csv = self.user_misp_connector.search(return_format='csv', date_from='2018-09-01', date_to='2018-09-02', pythonify=True)
            self.assertEqual(len(csv), 2)

            # headerless
            csv = self.user_misp_connector.search(return_format='csv', date_from='2018-09-01', date_to='2018-09-02', headerless=True)
            # FIXME: The header is here.
            # print(csv)
            # Expects 2 lines after removing the empty ones.
            # self.assertEqual(len(csv.strip().split('\n')), 2)

            # include_context
            csv = self.user_misp_connector.search(return_format='csv', date_from='2018-09-01', date_to='2018-09-02', include_context=True, pythonify=True)
            event_context_keys = ['event_info', 'event_member_org', 'event_source_org', 'event_distribution', 'event_threat_level_id', 'event_analysis', 'event_date', 'event_tag', 'event_timestamp']
            for k in event_context_keys:
                self.assertTrue(k in csv[0])

            # requested_attributes
            columns = ['value', 'event_id']
            csv = self.user_misp_connector.search(return_format='csv', date_from='2018-09-01', date_to='2018-09-02', requested_attributes=columns, pythonify=True)
            self.assertEqual(len(csv[0].keys()), 2)
            for k in columns:
                self.assertTrue(k in csv[0])

            # FIXME Publish is async, if we delete the event too fast, we have an empty one.
            # https://github.com/MISP/MISP/issues/4886
            time.sleep(10)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)

    def test_search_stix(self):
        first = self.create_simple_event()
        first.add_attribute('ip-src', '8.8.8.8')
        try:
            first = self.user_misp_connector.add_event(first)
            if not travis_run:
                stix = self.user_misp_connector.search(return_format='stix', eventid=first.id)
                found = re.findall('8.8.8.8', stix)
                self.assertTrue(found)
                stix2 = self.user_misp_connector.search(return_format='stix2', eventid=first.id)
                json.dumps(stix2, indent=2)
                self.assertEqual(stix2['objects'][-1]['pattern'], "[network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '8.8.8.8']")
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)

    @unittest.skip("Wait for https://github.com/MISP/MISP/issues/4848")
    def test_upload_sample(self):
        first = self.create_simple_event()
        second = self.create_simple_event()
        third = self.create_simple_event()
        try:
            # Simple, not executable
            first = self.user_misp_connector.add_event(first)
            response = self.user_misp_connector.add_sample_to_event(event_id=first.id, path_to_sample=Path('tests/testlive_comprehensive.py'))
            self.assertTrue('message' in response, "Content of response: {}".format(response))
            self.assertEqual(response['message'], 'Success, saved all attributes.')
            first = self.user_misp_connector.get_event(first.id)
            self.assertEqual(len(first.objects), 1)
            self.assertEqual(first.objects[0].name, 'file')
            # Simple, executable
            second = self.user_misp_connector.add_event(second)
            with open('tests/viper-test-files/test_files/whoami.exe', 'rb') as f:
                pseudofile = BytesIO(f.read())
            response = self.user_misp_connector.add_sample_to_event(event_id=second.id, filename='whoami.exe', pseudofile=pseudofile)
            self.assertEqual(response['message'], 'Success, saved all attributes.')
            second = self.user_misp_connector.get_event(second.id)
            self.assertEqual(len(second.objects), 1)
            self.assertEqual(second.objects[0].name, 'file')
            third = self.user_misp_connector.add_event(third)
            if not travis_run:
                # Advanced, executable
                response = self.user_misp_connector.add_sample_to_event(event_id=third.id, path_to_sample=Path('tests/viper-test-files/test_files/whoami.exe'), advanced_extraction=True)
                self.assertEqual(response['message'], 'Success, saved all attributes.')
                third = self.user_misp_connector.get_event(third.id)
                self.assertEqual(len(third.objects), 7)
                self.assertEqual(third.objects[0].name, 'pe-section')
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)
            self.admin_misp_connector.delete_event(third.id)

    def test_update_object(self):
        first = self.create_simple_event()
        ip_dom = MISPObject('domain-ip')
        ip_dom.add_attribute('domain', value='google.fr')
        ip_dom.add_attribute('ip', value='8.8.8.8')
        first.add_object(ip_dom)
        try:
            # Update with full event
            first = self.user_misp_connector.add_event(first)
            first.objects[0].add_attribute('ip', value='8.9.9.8')
            first.objects[0].add_attribute('ip', '8.9.9.10')
            first = self.user_misp_connector.update_event(first)
            self.assertEqual(first.objects[0].attributes[2].value, '8.9.9.8')
            self.assertEqual(first.objects[0].attributes[3].value, '8.9.9.10')
            # Update object only
            misp_object = self.user_misp_connector.get_object(first.objects[0].id)
            misp_object.attributes[2].value = '8.9.9.9'
            misp_object = self.user_misp_connector.update_object(misp_object)
            self.assertEqual(misp_object.attributes[2].value, '8.9.9.9')
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
            self.assertTrue(r['message'].endswith(f'successfully attached to Event({second.id}).'), r['message'])
            r = self.admin_misp_connector.untag(second, 'generic_tag_test')
            self.assertTrue(r['message'].endswith(f'successfully removed from Event({second.id}).'), r['message'])
            # NOTE: object tagging not supported yet
            # r = self.admin_misp_connector.tag(second.objects[0].uuid, 'generic_tag_test')
            # self.assertTrue(r['message'].endswith(f'successfully attached to Object({second.objects[0].id}).'), r['message'])
            # r = self.admin_misp_connector.untag(second.objects[0].uuid, 'generic_tag_test')
            # self.assertTrue(r['message'].endswith(f'successfully removed from Object({second.objects[0].id}).'), r['message'])
            r = self.admin_misp_connector.tag(second.objects[0].attributes[0].uuid, 'generic_tag_test')
            self.assertTrue(r['message'].endswith(f'successfully attached to Attribute({second.objects[0].attributes[0].id}).'), r['message'])
            r = self.admin_misp_connector.untag(second.objects[0].attributes[0].uuid, 'generic_tag_test')
            self.assertTrue(r['message'].endswith(f'successfully removed from Attribute({second.objects[0].attributes[0].id}).'), r['message'])

            # Delete tag to avoid polluting the db
            tags = self.admin_misp_connector.tags(pythonify=True)
            for t in tags:
                if t.name == 'generic_tag_test':
                    response = self.admin_misp_connector.delete_tag(t.id)
                    self.assertEqual(response['message'], 'Tag deleted.')

            # Test delete object
            r = self.user_misp_connector.delete_object(second.objects[0].id)
            self.assertEqual(r['message'], 'Object deleted')
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)

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
            self.admin_misp_connector.delete_event(first.id)

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
            self.admin_misp_connector.delete_event(first.id)

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
            self.admin_misp_connector.delete_event(first.id)

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
        tag = self.admin_misp_connector.get_tag(tag.id, pythonify=True)
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
        # Delete tag
        response = self.admin_misp_connector.delete_tag(new_tag.id)
        self.assertEqual(response['message'], 'Tag deleted.')

    def test_add_event_with_attachment_object_controller(self):
        first = self.create_simple_event()
        try:
            first = self.user_misp_connector.add_event(first)
            fo, peo, seos = make_binary_objects('tests/viper-test-files/test_files/whoami.exe')
            for s in seos:
                r = self.user_misp_connector.add_object(first.id, s)
                self.assertEqual(r.name, 'pe-section', r)

            r = self.user_misp_connector.add_object(first.id, peo)
            self.assertEqual(r.name, 'pe', r)
            for ref in peo.ObjectReference:
                r = self.user_misp_connector.add_object_reference(ref, pythonify=True)
                # FIXME: https://github.com/MISP/MISP/issues/4866
                # self.assertEqual(r.object_uuid, peo.uuid, r.to_json())

            r = self.user_misp_connector.add_object(first.id, fo)
            obj_attrs = r.get_attributes_by_relation('ssdeep')
            self.assertEqual(len(obj_attrs), 1, obj_attrs)
            self.assertEqual(r.name, 'file', r)
            r = self.user_misp_connector.add_object_reference(fo.ObjectReference[0], pythonify=True)
            # FIXME: https://github.com/MISP/MISP/issues/4866
            # self.assertEqual(r.object_uuid, fo.uuid, r.to_json())
            self.assertEqual(r.referenced_uuid, peo.uuid, r.to_json())
            r = self.user_misp_connector.delete_object_reference(r.id)
            self.assertEqual(r['message'], 'ObjectReference deleted')
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)

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
            self.assertEqual(first.objects[0].references[0].relationship_type, 'included-in')
            first = self.user_misp_connector.update_event(first)
            self.assertEqual(len(first.objects[0].references), 1)
            self.assertEqual(first.objects[0].references[0].relationship_type, 'included-in')
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)

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
        if not travis_run:
            r = self.admin_misp_connector.get_taxonomy(tax.id, pythonify=True)
            self.assertEqual(r.namespace, list_name_test)
            self.assertTrue('enabled' in r)
        r = self.admin_misp_connector.enable_taxonomy(tax.id)
        self.assertEqual(r['message'], 'Taxonomy enabled')
        r = self.admin_misp_connector.enable_taxonomy_tags(tax.id)
        # FIXME: https://github.com/MISP/MISP/issues/4865
        # self.assertEqual(r, [])
        r = self.admin_misp_connector.disable_taxonomy(tax.id)
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
        r = self.admin_misp_connector.get_warninglist(testwl.id, pythonify=True)
        self.assertEqual(r.name, list_name_test)
        self.assertTrue('WarninglistEntry' in r)
        r = self.admin_misp_connector.enable_warninglist(testwl.id)
        self.assertEqual(r['success'], '1 warninglist(s) enabled')
        # Check if a value is in a warning list
        md5_empty_file = 'd41d8cd98f00b204e9800998ecf8427e'
        r = self.user_misp_connector.values_in_warninglist([md5_empty_file])
        self.assertEqual(r[md5_empty_file][0]['name'], list_name_test)

        r = self.admin_misp_connector.disable_warninglist(testwl.id)
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
        r = self.admin_misp_connector.get_noticelist(testnl.id, pythonify=True)
        self.assertEqual(r.name, list_name_test)
        # FIXME: https://github.com/MISP/MISP/issues/4856
        self.assertTrue('NoticelistEntry' in r)
        r = self.admin_misp_connector.enable_noticelist(testnl.id)
        self.assertTrue(r['Noticelist']['enabled'], r)
        r = self.admin_misp_connector.disable_noticelist(testnl.id)
        self.assertFalse(r['Noticelist']['enabled'], r)

    def test_galaxies(self):
        if not travis_run:
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
            r = self.admin_misp_connector.get_galaxy(galaxy.id, pythonify=True)
            self.assertEqual(r.name, list_name_test)
            # FIXME: Fails due to https://github.com/MISP/MISP/issues/4855
            # self.assertTrue('GalaxyCluster' in r)

    def test_zmq(self):
        first = self.create_simple_event()
        try:
            first = self.user_misp_connector.add_event(first)
            if not travis_run:
                r = self.admin_misp_connector.push_event_to_ZMQ(first.id)
                self.assertEqual(r['message'], 'Event published to ZMQ')
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)

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
                new_object = self.user_misp_connector.add_object(first.id, o)
                self.assertEqual(len(new_object.attributes), 3)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)

    def test_user(self):
        # Get list
        users = self.admin_misp_connector.users(pythonify=True)
        self.assertTrue(isinstance(users, list))
        users_email = 'testusr@user.local'
        for user in users:
            if user.email == users_email:
                break
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
        organisation = self.admin_misp_connector.update_organisation(organisation)
        self.assertEqual(organisation.name, 'blah', organisation)

    def test_attribute(self):
        first = self.create_simple_event()
        second = self.create_simple_event()
        second.add_attribute('ip-src', '11.11.11.11')
        second.distribution = Distribution.all_communities
        try:
            first = self.user_misp_connector.add_event(first)
            # Get attribute
            attribute = self.user_misp_connector.get_attribute(first.attributes[0].id)
            self.assertEqual(first.attributes[0].uuid, attribute.uuid)
            # Add attribute
            new_attribute = MISPAttribute()
            new_attribute.value = '1.2.3.4'
            new_attribute.type = 'ip-dst'
            new_attribute = self.user_misp_connector.add_attribute(first.id, new_attribute)
            self.assertEqual(new_attribute.value, '1.2.3.4')
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
            new_proposal_update = self.user_misp_connector.update_attribute_proposal(new_attribute.id, {'to_ids': False}, pythonify=True)
            self.assertEqual(new_proposal_update.to_ids, False)
            # Delete attribute as proposal
            proposal_delete = self.user_misp_connector.delete_attribute_proposal(new_attribute.id)
            self.assertTrue(proposal_delete['saved'])
            # Get attribute proposal
            temp_new_proposal = self.user_misp_connector.get_attribute_proposal(new_proposal.id)
            self.assertEqual(temp_new_proposal.uuid, new_proposal.uuid)
            # Accept attribute proposal - New attribute
            self.user_misp_connector.accept_attribute_proposal(new_proposal.id)
            first = self.user_misp_connector.get_event(first.id)
            self.assertEqual(first.attributes[-1].value, '5.2.3.4')
            # Accept attribute proposal - Attribute update
            response = self.user_misp_connector.accept_attribute_proposal(new_proposal_update.id)
            self.assertEqual(response['message'], 'Proposed change accepted.')
            attribute = self.user_misp_connector.get_attribute(new_attribute.id)
            self.assertEqual(attribute.to_ids, False)
            # Discard attribute proposal
            new_proposal_update = self.user_misp_connector.update_attribute_proposal(new_attribute.id, {'to_ids': True})
            response = self.user_misp_connector.discard_attribute_proposal(new_proposal_update.id)
            self.assertEqual(response['message'], 'Proposal discarded.')
            attribute = self.user_misp_connector.get_attribute(new_attribute.id)
            self.assertEqual(attribute.to_ids, False)

            # Test fallback to proposal if the user doesn't own the event
            second = self.admin_misp_connector.add_event(second, pythonify=True)
            # FIXME: attribute needs to be a complete MISPAttribute: https://github.com/MISP/MISP/issues/4868
            prop_attr = MISPAttribute()
            prop_attr.from_dict(**{'type': 'ip-dst', 'value': '123.43.32.21'})
            attribute = self.user_misp_connector.add_attribute(second.id, prop_attr)
            self.assertTrue(isinstance(attribute, MISPShadowAttribute))
            attribute = self.user_misp_connector.update_attribute({'comment': 'blah'}, second.attributes[0].id)
            self.assertTrue(isinstance(attribute, MISPShadowAttribute))
            self.assertEqual(attribute.value, second.attributes[0].value)
            response = self.user_misp_connector.delete_attribute(second.attributes[1].id)
            self.assertTrue(response['success'])
            response = self.admin_misp_connector.delete_attribute(second.attributes[1].id)
            self.assertEqual(response['message'], 'Attribute deleted.')
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)

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
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)
            self.admin_misp_connector.delete_event(third.id)

    def test_search_logs(self):
        # FIXME: https://github.com/MISP/MISP/issues/4872
        r = self.admin_misp_connector.search_logs(model='User', created=date.today(), pythonify=True)
        for entry in r[-2:]:
            self.assertEqual(entry.action, 'add')

    def test_live_acl(self):
        missing_acls = self.admin_misp_connector.remote_acl
        self.assertEqual(missing_acls, [], msg=missing_acls)

    def test_roles(self):
        role = self.admin_misp_connector.set_default_role(4)
        self.assertEqual(role['message'], 'Default role set.')
        self.admin_misp_connector.set_default_role(3)
        roles = self.admin_misp_connector.roles(pythonify=True)
        self.assertTrue(isinstance(roles, list))

    def test_describe_types(self):
        remote = self.admin_misp_connector.describe_types_remote
        local = self.admin_misp_connector.describe_types_local
        self.assertDictEqual(remote, local)

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
            to_test = {'tags': {'tlp:white___test': '1'}, 'taxonomies': {'workflow': 0}}
            tags_stats = self.admin_misp_connector.tags_statistics()
            self.assertDictEqual(tags_stats, to_test)
            to_test = {'tags': {'tlp:white___test': '100%'}, 'taxonomies': {'workflow': '0%'}}
            tags_stats = self.admin_misp_connector.tags_statistics(percentage=True, name_sort=True)
            self.assertDictEqual(tags_stats, to_test)
            # Users
            to_test = {'stats': {'event_count': 3, 'event_count_month': 3, 'attribute_count': 8,
                                 'attribute_count_month': 8, 'attributes_per_event': 3, 'correlation_count': 1,
                                 'proposal_count': 0, 'user_count': 3, 'user_count_pgp': 0, 'org_count': 2,
                                 'local_org_count': 2, 'average_user_per_org': 1.5, 'thread_count': 0,
                                 'thread_count_month': 0, 'post_count': 0, 'post_count_month': 0}}
            users_stats = self.admin_misp_connector.users_statistics(context='data')
            self.assertDictEqual(users_stats, to_test)

            users_stats = self.admin_misp_connector.users_statistics(context='orgs')
            self.assertTrue('ORGNAME' in list(users_stats.keys()))

            users_stats = self.admin_misp_connector.users_statistics(context='users')
            self.assertEqual(list(users_stats.keys()), ['user', 'org_local', 'org_external'])

            users_stats = self.admin_misp_connector.users_statistics(context='tags')
            self.assertEqual(list(users_stats.keys()), ['flatData', 'treemap'])

            # FIXME: https://github.com/MISP/MISP/issues/4880
            # users_stats = self.admin_misp_connector.users_statistics(context='attributehistogram')

            self.user_misp_connector.add_sighting({'value': first.attributes[0].value})
            users_stats = self.user_misp_connector.users_statistics(context='sightings')
            self.assertEqual(list(users_stats.keys()), ['toplist', 'eventids'])

            users_stats = self.admin_misp_connector.users_statistics(context='galaxyMatrix')
            self.assertTrue('matrix' in users_stats)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)
            self.admin_misp_connector.delete_event(third.id)

    def test_direct(self):
        try:
            r = self.user_misp_connector.direct_call('events/add', data={'info': 'foo'})
            event = MISPEvent()
            event.from_dict(**r)
            r = self.user_misp_connector.direct_call(f'events/view/{event.id}')
            event_get = MISPEvent()
            event_get.from_dict(**r)
            self.assertDictEqual(event.to_dict(), event_get.to_dict())
        finally:
            self.admin_misp_connector.delete_event(event.id)

    def test_freetext(self):
        first = self.create_simple_event()
        try:
            self.admin_misp_connector.toggle_warninglist(warninglist_name='%dns resolv%', force_enable=True)
            first = self.user_misp_connector.add_event(first)
            r = self.user_misp_connector.freetext(first.id, '1.1.1.1 foo@bar.de', adhereToWarninglists=False,
                                                  distribution=2, returnMetaAttributes=False, pythonify=True)
            self.assertTrue(isinstance(r, list))
            self.assertEqual(r[0].value, '1.1.1.1')

            # FIXME: https://github.com/MISP/MISP/issues/4881
            # r_wl = self.user_misp_connector.freetext(first.id, '8.8.8.8 foo@bar.de', adhereToWarninglists=True,
            #                                         distribution=2, returnMetaAttributes=False)
            # print(r_wl)
            r = self.user_misp_connector.freetext(first.id, '1.1.1.1 foo@bar.de', adhereToWarninglists=True,
                                                  distribution=2, returnMetaAttributes=True)
            self.assertTrue(isinstance(r, list))
            self.assertTrue(isinstance(r[0]['types'], dict))
            # NOTE: required, or the attributes are inserted *after* the event is deleted
            # FIXME: https://github.com/MISP/MISP/issues/4886
            time.sleep(10)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)

    def test_sharing_groups(self):
        # add
        sg = MISPSharingGroup()
        sg.name = 'Testcases SG'
        sg.releasability = 'Testing'
        sharing_group = self.admin_misp_connector.add_sharing_group(sg, pythonify=True)
        self.assertEqual(sharing_group.name, 'Testcases SG')
        self.assertEqual(sharing_group.releasability, 'Testing')
        # add org
        # FIXME: https://github.com/MISP/MISP/issues/4884
        # r = self.admin_misp_connector.add_org_to_sharing_group(sharing_group.id,
        #                                                       self.test_org.id, extend=True)

        # delete org
        # FIXME: https://github.com/MISP/MISP/issues/4884
        # r = self.admin_misp_connector.remove_org_from_sharing_group(sharing_group.id,
        #                                                       self.test_org.id)

        # Get list
        sharing_groups = self.admin_misp_connector.sharing_groups(pythonify=True)
        self.assertTrue(isinstance(sharing_groups, list))
        self.assertEqual(sharing_groups[0].name, 'Testcases SG')

        # Use the SG

        first = self.create_simple_event()
        try:
            first = self.user_misp_connector.add_event(first)
            first = self.admin_misp_connector.change_sharing_group_on_entity(first, sharing_group.id)
            self.assertEqual(first.SharingGroup['name'], 'Testcases SG')
            # FIXME https://github.com/MISP/MISP/issues/4891
            # first_attribute = self.admin_misp_connector.change_sharing_group_on_entity(first.attributes[0], sharing_group.id)
            # self.assertEqual(first_attribute.SharingGroup['name'], 'Testcases SG')
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)

        # delete
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
        r = self.admin_misp_connector.delete_feed(feed.id)
        self.assertEqual(r['message'], 'Feed deleted.')
        # List
        feeds = self.admin_misp_connector.feeds(pythonify=True)
        self.assertTrue(isinstance(feeds, list))
        for feed in feeds:
            if feed.name == 'The Botvrij.eu Data':
                break
        # Get
        botvrij = self.admin_misp_connector.get_feed(feed.id, pythonify=True)
        self.assertEqual(botvrij.url, "http://www.botvrij.eu/data/feed-osint")
        # Enable
        # MISP OSINT
        print(feeds[0].id)
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
        r = self.admin_misp_connector.cache_feed(botvrij.id)
        self.assertEqual(r['message'], 'Feed caching job initiated.')
        # Fetch
        # Cannot test that, it fetches all the events.
        # r = self.admin_misp_connector.fetch_feed(botvrij.id)
        # FIXME https://github.com/MISP/MISP/issues/4834#issuecomment-511889274
        # self.assertEqual(r['message'], 'Feed caching job initiated.')

        # Cache all enabled feeds
        r = self.admin_misp_connector.cache_all_feeds()
        self.assertEqual(r['message'], 'Feed caching job initiated.')
        # Compare all enabled feeds
        r = self.admin_misp_connector.compare_feeds()
        # FIXME: https://github.com/MISP/MISP/issues/4834#issuecomment-511890466
        # self.assertEqual(r['message'], 'Feed caching job initiated.')
        time.sleep(30)
        # Disable both feeds
        feed = self.admin_misp_connector.disable_feed(feeds[0].id, pythonify=True)
        self.assertFalse(feed.enabled)
        feed = self.admin_misp_connector.disable_feed(botvrij.id, pythonify=True)
        self.assertFalse(feed.enabled)
        feed = self.admin_misp_connector.disable_feed_cache(feeds[0].id, pythonify=True)
        self.assertFalse(feed.enabled)
        feed = self.admin_misp_connector.disable_feed_cache(botvrij.id, pythonify=True)
        self.assertFalse(feed.enabled)

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
        server = self.admin_misp_connector.delete_server(server.id)
        # FIXME: https://github.com/MISP/MISP/issues/4889

    @unittest.skipIf(sys.version_info < (3, 6), 'Not supported on python < 3.6')
    def test_expansion(self):
        first = self.create_simple_event()
        try:
            with open('tests/viper-test-files/test_files/whoami.exe', 'rb') as f:
                first.add_attribute('malware-sample', value='whoami.exe', data=BytesIO(f.read()), expand='binary')
            first.run_expansions()
            first = self.admin_misp_connector.add_event(first)
            self.assertEqual(len(first.objects), 7)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)

    def test_upload_stix(self):
        # FIXME https://github.com/MISP/MISP/issues/4892
        pass


if __name__ == '__main__':
    unittest.main()
