#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest

from pymisp import ExpandedPyMISP, MISPEvent, MISPOrganisation, MISPUser, Distribution, ThreatLevel, Analysis, MISPAttribute
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

    def create_event_org_only(self, force_timestamps=False):
        mispevent = MISPEvent(force_timestamps=force_timestamps)
        mispevent.info = 'This is a test'
        mispevent.distribution = Distribution.your_organisation_only
        mispevent.threat_level_id = ThreatLevel.low
        mispevent.analysis = Analysis.completed
        mispevent.set_date("2017-12-31")  # test the set date method
        mispevent.add_attribute('text', str(uuid4()))
        return mispevent

    def create_event_with_tags(self):
        mispevent = self.create_event_org_only()
        mispevent.add_tag('tlp:white___test')
        mispevent.attributes[0].add_tag('tlp:amber___test')
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
            response = self.admin_misp_connector.search(value=first.attributes[0].value)
            self.assertEqual(len(response), 2)
            # Search as user
            response = self.user_misp_connector.search(value=first.attributes[0].value)
            self.assertEqual(len(response), 1)
            # Non-existing value
            response = self.user_misp_connector.search(value=str(uuid4()))
            self.assertEqual(response, [])
        finally:
            # Delete events
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)
            self.admin_misp_connector.delete_event(third.id)

    def test_search_value_attribute(self):
        try:
            first, second, third = self.environment()
            # Search as admin
            response = self.admin_misp_connector.search(controller='attributes', value=first.attributes[0].value)
            self.assertEqual(len(response), 2)
            # Search as user
            response = self.user_misp_connector.search(controller='attributes', value=first.attributes[0].value)
            self.assertEqual(len(response), 1)
            # Non-existing value
            response = self.user_misp_connector.search(controller='attributes', value=str(uuid4()))
            self.assertEqual(response, [])
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)
            self.admin_misp_connector.delete_event(third.id)

    @unittest.skip("Currently failing")
    def test_search_type_event(self):
        try:
            first, second, third = self.environment()
            # Search as admin
            response = self.admin_misp_connector.search(timestamp=first.timestamp.timestamp())
            self.assertEqual(len(response), 3)
            attrubutes_types_search = self.admin_misp_connector.build_complex_query(or_parameters=['ip-src', 'ip-dst'])
            response = self.admin_misp_connector.search(controller='events', timestamp=first.timestamp.timestamp(),
                                                        type_attribute=attrubutes_types_search)
            self.assertEqual(len(response), 2)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)
            self.admin_misp_connector.delete_event(third.id)

    def test_search_type_attribute(self):
        try:
            first, second, third = self.environment()
            # Search as admin
            response = self.admin_misp_connector.search(controller='attributes', timestamp=first.timestamp.timestamp())
            self.assertEqual(len(response), 7)
            attrubutes_types_search = self.admin_misp_connector.build_complex_query(or_parameters=['ip-src', 'ip-dst'])
            response = self.admin_misp_connector.search(controller='attributes', timestamp=first.timestamp.timestamp(),
                                                        type_attribute=attrubutes_types_search)
            self.assertEqual(len(response), 3)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)
            self.admin_misp_connector.delete_event(third.id)

    def test_search_tag_event(self):
        try:
            first, second, third = self.environment()
            # Search as admin
            response = self.admin_misp_connector.search(tags='tlp:white___test')
            self.assertEqual(len(response), 2)
            response = self.admin_misp_connector.search(tags='tlp:amber___test')
            self.assertEqual(len(response), 1)
            # Search as user
            response = self.user_misp_connector.search(tags='tlp:white___test')
            self.assertEqual(len(response), 1)
            response = self.user_misp_connector.search(tags='tlp:amber___test')
            self.assertEqual(len(response), 0)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)
            self.admin_misp_connector.delete_event(third.id)

    def test_search_tag_attribute(self):
        try:
            first, second, third = self.environment()
            # Search as admin
            response = self.admin_misp_connector.search(controller='attributes', tags='tlp:white___test')
            self.assertEqual(len(response), 4)
            response = self.admin_misp_connector.search(controller='attributes', tags='tlp:amber___test')
            self.assertEqual(len(response), 1)
            # Search as user
            response = self.user_misp_connector.search(controller='attributes', tags='tlp:white___test')
            self.assertEqual(len(response), 1)
            response = self.user_misp_connector.search(controller='attributes', tags='tlp:amber___test')
            self.assertEqual(len(response), 0)
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
            for e in events:
                for a in e.attributes:
                    self.assertEqual([t for t in a.tags if t.name == 'tlp:amber___test'], [])
                for a in e.attributes:
                    self.assertEqual([t for t in a.tags if t.name == 'foo_double___test'], [])
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
            for a in attributes:
                self.assertEqual([t for t in a.tags if t.name == 'tlp:amber___test'], [])
            for a in attributes:
                self.assertEqual([t for t in a.tags if t.name == 'foo_double___test'], [])
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first.id)
            self.admin_misp_connector.delete_event(second.id)
            self.admin_misp_connector.delete_event(third.id)

    @unittest.skip("temp")
    def test_search_timestamp_event(self):
        # Creating event 1 - timestamp 5 min ago
        first = self.create_event_org_only(force_timestamps=True)
        event_creation_timestamp_first = datetime.now() - timedelta(minutes=5)
        first.timestamp = event_creation_timestamp_first
        # Creating event 2 - timestamp 2 min ago
        second = self.create_event_org_only(force_timestamps=True)
        event_creation_timestamp_second = datetime.now() - timedelta(minutes=2)
        second.timestamp = event_creation_timestamp_second
        # Connect as user
        user_misp_connector = ExpandedPyMISP(url, self.test_usr.authkey)
        first_created_event = user_misp_connector.add_event(first)
        first_to_delete = MISPEvent()
        first_to_delete.load(first_created_event)
        second_created_event = user_misp_connector.add_event(second)
        second_to_delete = MISPEvent()
        second_to_delete.load(second_created_event)
        try:
            # Search as user
            # # Test - last 4 min
            response = user_misp_connector.search(timestamp='4m')
            self.assertEqual(len(response), 1)
            received_event = response[0]
            self.assertEqual(received_event.timestamp.timestamp(), int(event_creation_timestamp_second.timestamp()))

            # # Test timestamp of 2nd event
            response = user_misp_connector.search(timestamp=event_creation_timestamp_second.timestamp())
            self.assertEqual(len(response), 1)
            received_event = response[0]
            self.assertEqual(received_event.timestamp.timestamp(), int(event_creation_timestamp_second.timestamp()))

            # # Test interval -6 min -> -4 min
            response = user_misp_connector.search(timestamp=['6m', '4m'])
            self.assertEqual(len(response), 1)
            received_event = response[0]
            self.assertEqual(received_event.timestamp.timestamp(), int(event_creation_timestamp_first.timestamp()))
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first_to_delete.id)
            self.admin_misp_connector.delete_event(second_to_delete.id)

    @unittest.skip("temp")
    def test_user_perms(self):
        first = self.create_event_org_only()
        first.publish()
        user_misp_connector = ExpandedPyMISP(url, self.test_usr.authkey)
        try:
            # Add event as user, no publish rights
            first_created_event = user_misp_connector.add_event(first)
            first_to_delete = MISPEvent()
            first_to_delete.load(first_created_event)
            self.assertFalse(first_to_delete.published)
            # Add event as publisher
            first_to_delete.publish()
            publisher_misp_connector = ExpandedPyMISP(url, self.test_pub.authkey)
            first_created_event = publisher_misp_connector.update(first_to_delete)
            first_to_delete = MISPEvent()
            first_to_delete.load(first_created_event)
            self.assertTrue(first_to_delete.published)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first_to_delete.id)

    @unittest.skip("Uncomment when adding new tests, it has a 10s sleep")
    def test_search_publish_timestamp_event(self):
        # Creating event 1
        first = self.create_event_org_only()
        first.publish()
        # Creating event 2
        second = self.create_event_org_only()
        second.publish()
        # Connect as user
        pub_misp_connector = ExpandedPyMISP(url, self.test_pub.authkey)
        first_created_event = pub_misp_connector.add_event(first)
        first_to_delete = MISPEvent()
        first_to_delete.load(first_created_event)
        time.sleep(10)
        second_created_event = pub_misp_connector.add_event(second)
        second_to_delete = MISPEvent()
        second_to_delete.load(second_created_event)
        try:
            # Test invalid query
            response = pub_misp_connector.search(publish_timestamp='5x')
            self.assertEqual(len(response), 0)
            response = pub_misp_connector.search(publish_timestamp='ad')
            self.assertEqual(len(response), 0)
            response = pub_misp_connector.search(publish_timestamp='aaad')
            self.assertEqual(len(response), 0)
            # Search as user
            # # Test - last 4 min
            response = pub_misp_connector.search(publish_timestamp='5s')
            self.assertEqual(len(response), 1)

            # # Test 5 sec before timestamp of 2nd event
            response = pub_misp_connector.search(publish_timestamp=(second_to_delete.publish_timestamp.timestamp()))
            self.assertEqual(len(response), 1)

            # # Test interval -6 min -> -4 min
            response = pub_misp_connector.search(publish_timestamp=[first_to_delete.publish_timestamp.timestamp() - 5, second_to_delete.publish_timestamp.timestamp() - 5])
            self.assertEqual(len(response), 1)
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first_to_delete.id)
            self.admin_misp_connector.delete_event(second_to_delete.id)

    @unittest.skip("temp")
    def test_simple(self):
        event = self.create_event_org_only()
        event.info = 'foo bar blah'
        user_misp_connector = ExpandedPyMISP(url, self.test_usr.authkey)
        first_created_event = user_misp_connector.add_event(event)
        first_to_delete = MISPEvent()
        first_to_delete.load(first_created_event)
        timeframe = [first_to_delete.timestamp.timestamp() - 5, first_to_delete.timestamp.timestamp() + 5]
        try:
            # Search event we just created in multiple ways. Make sure it doesn't catchi it when it shouldn't
            response = user_misp_connector.search(timestamp=timeframe)
            self.assertEqual(len(response), 1)
            response = user_misp_connector.search(timestamp=timeframe, value='nothere')
            self.assertEqual(len(response), 0)
            response = user_misp_connector.search(timestamp=timeframe, value=first_to_delete.attributes[0].value)
            self.assertEqual(len(response), 1)
            response = user_misp_connector.search(timestamp=[first_to_delete.timestamp.timestamp() - 50, first_to_delete.timestamp.timestamp() - 10], value=first_to_delete.attributes[0].value)
            self.assertEqual(len(response), 0)
            # Test return content
            response = user_misp_connector.search(timestamp=timeframe, metadata=False)
            self.assertEqual(len(response), 1)
            t = response[0]
            self.assertEqual(len(t.attributes), 1)
            response = user_misp_connector.search(timestamp=timeframe, metadata=True)
            self.assertEqual(len(response), 1)
            t = response[0]
            self.assertEqual(len(t.attributes), 0)
            # other things
            response = user_misp_connector.search(timestamp=timeframe, published=True)
            self.assertEqual(len(response), 0)
            response = user_misp_connector.search(timestamp=timeframe, published=False)
            self.assertEqual(len(response), 1)
            response = user_misp_connector.search(eventid=first_to_delete.id)
            self.assertEqual(len(response), 1)
            response = user_misp_connector.search(uuid=first_to_delete.uuid)
            self.assertEqual(len(response), 1)
            response = user_misp_connector.search(org=first_to_delete.orgc_id)
            self.assertEqual(len(response), 1)
            # test like search
            response = user_misp_connector.search(timestamp=timeframe, value='%{}%'.format(first_to_delete.attributes[0].value.split('-')[2]))
            self.assertEqual(len(response), 1)
            response = user_misp_connector.search(timestamp=timeframe, eventinfo='%bar blah%')
            self.assertEqual(len(response), 1)

        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first_to_delete.id)

    @unittest.skip("temp")
    def test_edit_attribute(self):
        first = self.create_event_org_only()
        user_misp_connector = ExpandedPyMISP(url, self.test_usr.authkey, debug=False)
        try:
            first.attributes[0].comment = 'This is the original comment'
            first_created_event = user_misp_connector.add_event(first)
            first_to_delete = MISPEvent()
            first_to_delete.load(first_created_event)
            first_to_delete.attributes[0].comment = 'This is the modified comment'
            response = user_misp_connector.update_attribute(first_to_delete.attributes[0].id, first_to_delete.attributes[0])
            tmp_attr = MISPAttribute()
            tmp_attr.from_dict(**response)
            self.assertEqual(tmp_attr.comment, 'This is the modified comment')
            response = user_misp_connector.change_comment(first_to_delete.attributes[0].uuid, 'This is the modified comment, again')
            tmp_attr = MISPAttribute()
            tmp_attr.from_dict(**response)
            self.assertEqual(tmp_attr.comment, 'This is the modified comment, again')
        finally:
            # Delete event
            self.admin_misp_connector.delete_event(first_to_delete.id)


if __name__ == '__main__':
    unittest.main()
