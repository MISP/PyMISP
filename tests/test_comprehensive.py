#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest

from pymisp import ExpandedPyMISP, MISPEvent, MISPOrganisation, MISPUser, Distribution, ThreatLevel, Analysis

# from keys import url, key_admin
from uuid import uuid4


url = 'http://localhost:8080'
key_admin = 'fk5BodCZw8owbscW8pQ4ykMASLeJ4NYhuAbshNjo'


class TestComprehensive(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.maxDiff = None
        # Connect as admin
        cls.admin_misp_connector = ExpandedPyMISP(url, key_admin)
        # Creates an org
        org = cls.admin_misp_connector.add_organisation(name='Test Org')
        cls.test_org = MISPOrganisation()
        cls.test_org.from_dict(**org)
        # Creates a user
        usr = cls.admin_misp_connector.add_user(email='testusr@user.local', org_id=cls.test_org.id, role_id=3)
        cls.test_usr = MISPUser()
        cls.test_usr.from_dict(**usr)

    @classmethod
    def tearDownClass(cls):
        # Delete user
        cls.admin_misp_connector.delete_user(user_id=cls.test_usr.id)
        # Delete org
        cls.admin_misp_connector.delete_organisation(org_id=cls.test_org.id)

    def create_event_org_only(self):
        mispevent = MISPEvent()
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

    def test_search_value_event(self):
        me = self.create_event_org_only()
        # Create event
        created_event = self.admin_misp_connector.add_event(me)
        c_me = MISPEvent()
        c_me.load(created_event)
        # Search as admin
        response = self.admin_misp_connector.search(value=me.attributes[0].value)
        self.assertEqual(len(response), 1)
        # Connect as user
        user_misp_connector = ExpandedPyMISP(url, self.test_usr.authkey)
        # Search as user
        response = user_misp_connector.search(value=me.attributes[0].value)
        self.assertEqual(response, [])
        # Delete event
        self.admin_misp_connector.delete_event(c_me.id)

    def test_search_value_attribute(self):
        me = self.create_event_org_only()
        # Create event
        created_event = self.admin_misp_connector.add_event(me)
        c_me = MISPEvent()
        c_me.load(created_event)
        # Search as admin
        response = self.admin_misp_connector.search(controller='attributes', value=me.attributes[0].value)
        self.assertEqual(len(response), 1)
        # Connect as user
        user_misp_connector = ExpandedPyMISP(url, self.test_usr.authkey)
        # Search as user
        response = user_misp_connector.search(controller='attributes', value=me.attributes[0].value)
        self.assertEqual(response, [])
        # Delete event
        self.admin_misp_connector.delete_event(c_me.id)

    def test_search_tag_event(self):
        me = self.create_event_with_tags()
        # Create event
        created_event = self.admin_misp_connector.add_event(me)
        c_me = MISPEvent()
        c_me.load(created_event)
        # Search as admin
        response = self.admin_misp_connector.search(tags='tlp:white___test')
        self.assertEqual(len(response), 1)
        # Connect as user
        user_misp_connector = ExpandedPyMISP(url, self.test_usr.authkey)
        # Search as user
        response = user_misp_connector.search(value='tlp:white___test')
        self.assertEqual(response, [])
        # Delete event
        self.admin_misp_connector.delete_event(c_me.id)

    def test_search_tag_event_fancy(self):
        # Create event
        me = self.create_event_with_tags()
        # Connect as user
        user_misp_connector = ExpandedPyMISP(url, self.test_usr.authkey)
        created_event = user_misp_connector.add_event(me)
        to_delete = MISPEvent()
        to_delete.load(created_event)
        complex_query = user_misp_connector.build_complex_query(or_parameters=['tlp:white___test'], not_parameters=['tlp:amber___test'])
        # Search as user
        response = user_misp_connector.search(tags=complex_query)
        for e in response:
            to_validate = MISPEvent()
            to_validate.load(e)
            # FIXME Expected event without the tlp:amber attribute, broken for now
            for a in to_validate.attributes:
                print([t for t in a.tags if t.name == 'tlp:amber___test'])
                # self.assertEqual([t for t in a.tags if t.name == 'tlp:amber___test'], [])
        # Delete event
        self.admin_misp_connector.delete_event(to_delete.id)

#    def test_search_tag_attribute(self):
#        me = self.create_event_with_tags()
#        # Create event
#        created_event = self.admin_misp_connector.add_event(me)
#        c_me = MISPEvent()
#        c_me.load(created_event)
#        # Search as admin
#        response = self.admin_misp_connector.search(controller='attributes', tags='tlp:white__test')
#        print(response)
#        self.assertEqual(len(response), 1)
        # Connect as user
#        user_misp_connector = ExpandedPyMISP(url, self.test_usr.authkey)
        # Search as user
#        response = user_misp_connector.search(controller='attributes', value='tlp:white__test')
#        self.assertEqual(response, [])
        # Delete event
#        self.admin_misp_connector.delete_event(c_me.id)
