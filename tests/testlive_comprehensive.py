#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest

from pymisp import ExpandedPyMISP, MISPEvent, MISPOrganisation, MISPUser, Distribution, ThreatLevel, Analysis
from datetime import datetime, timedelta

import time

try:
    from keys import url, key
except ImportError as e:
    print(e)
    url = 'http://localhost:8080'
    key = 'fk5BodCZw8owbscW8pQ4ykMASLeJ4NYhuAbshNjo'

from uuid import uuid4


class TestComprehensive(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.maxDiff = None
        # Connect as admin
        cls.admin_misp_connector = ExpandedPyMISP(url, key)
        # Creates an org
        org = cls.admin_misp_connector.add_organisation(name='Test Org')
        cls.test_org = MISPOrganisation()
        cls.test_org.from_dict(**org)
        # Creates a user
        usr = cls.admin_misp_connector.add_user(email='testusr@user.local', org_id=cls.test_org.id, role_id=3)
        cls.test_usr = MISPUser()
        cls.test_usr.from_dict(**usr)
        cls.user_misp_connector = ExpandedPyMISP(url, cls.test_usr.authkey)
        # Creates a publisher
        pub = cls.admin_misp_connector.add_user(email='testpub@user.local', org_id=cls.test_org.id, role_id=4)
        cls.test_pub = MISPUser()
        cls.test_pub.from_dict(**pub)
        cls.pub_misp_connector = ExpandedPyMISP(url, cls.test_pub.authkey)

    @classmethod
    def tearDownClass(cls):
        # Delete publisher
        cls.admin_misp_connector.delete_user(user_id=cls.test_pub.id)
        # Delete user
        cls.admin_misp_connector.delete_user(user_id=cls.test_usr.id)
        # Delete org
        cls.admin_misp_connector.delete_organisation(org_id=cls.test_org.id)

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
            events = self.admin_misp_connector.search(value=first.attributes[0].value)
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
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)
            self.admin_misp_connector.delete_event(third.id)

    def test_search_value_attribute(self):
        try:
            first, second, third = self.environment()
            # Search as admin
            attributes = self.admin_misp_connector.search(controller='attributes', value=first.attributes[0].value)
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
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)
            self.admin_misp_connector.delete_event(third.id)

    # @unittest.skip("Currently failing")
    def test_search_type_event(self):
        try:
            first, second, third = self.environment()
            # Search as admin
            events = self.admin_misp_connector.search(timestamp=first.timestamp.timestamp())
            self.assertEqual(len(events), 3)
            for e in events:
                self.assertIn(e.id, [first.id, second.id, third.id])
            attributes_types_search = self.admin_misp_connector.build_complex_query(or_parameters=['ip-src', 'ip-dst'])
            events = self.admin_misp_connector.search(timestamp=first.timestamp.timestamp(),
                                                      type_attribute=attributes_types_search)
            self.assertEqual(len(events), 2)
            for e in events:
                self.assertIn(e.id, [second.id, third.id])
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)
            self.admin_misp_connector.delete_event(third.id)

    def test_search_type_attribute(self):
        try:
            first, second, third = self.environment()
            # Search as admin
            attributes = self.admin_misp_connector.search(controller='attributes',
                                                          timestamp=first.timestamp.timestamp())
            self.assertEqual(len(attributes), 8)
            for a in attributes:
                self.assertIn(a.event_id, [first.id, second.id, third.id])
            # Search as user
            attributes_types_search = self.admin_misp_connector.build_complex_query(or_parameters=['ip-src', 'ip-dst'])
            attributes = self.admin_misp_connector.search(controller='attributes',
                                                          timestamp=first.timestamp.timestamp(),
                                                          type_attribute=attributes_types_search)
            self.assertEqual(len(attributes), 3)
            for a in attributes:
                self.assertIn(a.event_id, [second.id, third.id])
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)
            self.admin_misp_connector.delete_event(third.id)

    def test_search_tag_event(self):
        try:
            first, second, third = self.environment()
            # Search as admin
            events = self.admin_misp_connector.search(tags='tlp:white___test')
            self.assertEqual(len(events), 3)
            for e in events:
                self.assertIn(e.id, [first.id, second.id, third.id])
            events = self.admin_misp_connector.search(tags='tlp:amber___test')
            self.assertEqual(len(events), 1)
            for e in events:
                self.assertIn(e.id, [third.id])
            events = self.admin_misp_connector.search(tags='admin_only')
            self.assertEqual(len(events), 1)
            for e in events:
                self.assertIn(e.id, [first.id])
            # Search as user
            events = self.user_misp_connector.search(tags='tlp:white___test')
            self.assertEqual(len(events), 2)
            for e in events:
                self.assertIn(e.id, [second.id, third.id])
            events = self.user_misp_connector.search(tags='tlp:amber___test')
            self.assertEqual(len(events), 1)
            for e in events:
                self.assertIn(e.id, [third.id])
            events = self.user_misp_connector.search(tags='admin_only')
            self.assertEqual(events, [])
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)
            self.admin_misp_connector.delete_event(third.id)

    def test_search_tag_attribute(self):
        try:
            first, second, third = self.environment()
            # Search as admin
            attributes = self.admin_misp_connector.search(controller='attributes', tags='tlp:white___test')
            self.assertEqual(len(attributes), 5)
            attributes = self.admin_misp_connector.search(controller='attributes', tags='tlp:amber___test')
            self.assertEqual(len(attributes), 2)
            attributes = self.admin_misp_connector.search(tags='admin_only')
            self.assertEqual(len(attributes), 1)
            # Search as user
            attributes = self.user_misp_connector.search(controller='attributes', tags='tlp:white___test')
            self.assertEqual(len(attributes), 4)
            attributes = self.user_misp_connector.search(controller='attributes', tags='tlp:amber___test')
            self.assertEqual(len(attributes), 2)
            attributes = self.user_misp_connector.search(tags='admin_only')
            self.assertEqual(attributes, [])
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)
            self.admin_misp_connector.delete_event(third.id)

    def test_search_tag_advanced_event(self):
        try:
            first, second, third = self.environment()
            complex_query = self.admin_misp_connector.build_complex_query(or_parameters=['tlp:white___test'],
                                                                          not_parameters=['tlp:amber___test',
                                                                                          'foo_double___test'])
            events = self.admin_misp_connector.search(tags=complex_query)
            self.assertEqual(len(events), 3)
            for e in events:
                self.assertIn(e.id, [first.id, second.id, third.id])
                for a in e.attributes:
                    self.assertEqual([t for t in a.tags if t.name == 'tlp:amber___test'], [])
                for a in e.attributes:
                    self.assertEqual([t for t in a.tags if t.name == 'foo_double___test'], [])

            complex_query = self.admin_misp_connector.build_complex_query(or_parameters=['unique___test'],
                                                                          not_parameters=['tlp:white___test'])
            events = self.admin_misp_connector.search(tags=complex_query)
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
        try:
            first, second, third = self.environment()
            complex_query = self.admin_misp_connector.build_complex_query(or_parameters=['tlp:white___test'],
                                                                          not_parameters=['tlp:amber___test',
                                                                                          'foo_double___test'])
            attributes = self.admin_misp_connector.search(controller='attributes', tags=complex_query)
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
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)

    def test_search_timestamp_attribute(self):
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
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)

    def test_user_perms(self):
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

    # @unittest.skip("Uncomment when adding new tests, it has a 10s sleep")
    def test_search_publish_timestamp(self):
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
            events = self.pub_misp_connector.search(publish_timestamp='5x')
            self.assertEqual(events, [])
            events = self.pub_misp_connector.search(publish_timestamp='ad')
            self.assertEqual(events, [])
            events = self.pub_misp_connector.search(publish_timestamp='aaad')
            self.assertEqual(events, [])
            # Test - last 4 min
            events = self.pub_misp_connector.search(publish_timestamp='5s')
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, second.id)

            # Test 5 sec before timestamp of 2nd event
            events = self.pub_misp_connector.search(publish_timestamp=(second.publish_timestamp.timestamp()))
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, second.id)

            # Test interval -6 min -> -4 min
            events = self.pub_misp_connector.search(publish_timestamp=[first.publish_timestamp.timestamp() - 5,
                                                                       second.publish_timestamp.timestamp() - 5])
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, first.id)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)

    def test_simple_event(self):
        first = self.create_simple_event()
        first.info = 'foo bar blah'
        try:
            first = self.user_misp_connector.add_event(first)
            timeframe = [first.timestamp.timestamp() - 5, first.timestamp.timestamp() + 5]
            # Search event we just created in multiple ways. Make sure it doesn't catch it when it shouldn't
            events = self.user_misp_connector.search(timestamp=timeframe)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, first.id)
            events = self.user_misp_connector.search(timestamp=timeframe, value='nothere')
            self.assertEqual(events, [])
            events = self.user_misp_connector.search(timestamp=timeframe, value=first.attributes[0].value)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].id, first.id)
            events = self.user_misp_connector.search(timestamp=[first.timestamp.timestamp() - 50,
                                                                first.timestamp.timestamp() - 10],
                                                     value=first.attributes[0].value)
            self.assertEqual(events, [])
            # Test return content
            events = self.user_misp_connector.search(timestamp=timeframe, metadata=False)
            self.assertEqual(len(events), 1)
            self.assertEqual(len(events[0].attributes), 1)
            events = self.user_misp_connector.search(timestamp=timeframe, metadata=True)
            self.assertEqual(len(events), 1)
            self.assertEqual(len(events[0].attributes), 0)
            # other things
            events = self.user_misp_connector.search(timestamp=timeframe, published=True)
            self.assertEqual(events, [])
            events = self.user_misp_connector.search(timestamp=timeframe, published=False)
            self.assertEqual(len(events), 1)
            events = self.user_misp_connector.search(eventid=first.id)
            self.assertEqual(len(events), 1)
            events = self.user_misp_connector.search(uuid=first.uuid)
            self.assertEqual(len(events), 1)
            events = self.user_misp_connector.search(org=first.orgc_id)
            self.assertEqual(len(events), 1)
            # test like search
            events = self.user_misp_connector.search(timestamp=timeframe, value='%{}%'.format(first.attributes[0].value.split('-')[2]))
            self.assertEqual(len(events), 1)
            events = self.user_misp_connector.search(timestamp=timeframe, eventinfo='%bar blah%')
            self.assertEqual(len(events), 1)

        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)

    def test_edit_attribute(self):
        first = self.create_simple_event()
        try:
            first.attributes[0].comment = 'This is the original comment'
            first = self.user_misp_connector.add_event(first)
            first.attributes[0].comment = 'This is the modified comment'
            attribute = self.user_misp_connector.update_attribute(first.attributes[0])
            self.assertEqual(attribute.comment, 'This is the modified comment')
            attribute = self.user_misp_connector.change_comment(first.attributes[0].uuid, 'This is the modified comment, again')
            self.assertEqual(attribute['Attribute']['comment'], 'This is the modified comment, again')
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)


if __name__ == '__main__':
    unittest.main()
