#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys


import unittest

from pymisp.tools import make_binary_objects
from datetime import datetime, timedelta, date, timezone
import json
from pathlib import Path
import time
import urllib3
from uuid import uuid4
from collections import defaultdict

import logging
logging.disable(logging.CRITICAL)
logger = logging.getLogger('pymisp')
import functools

try:
    from pymisp import register_user, PyMISP, MISPEvent, MISPOrganisation, MISPUser, Distribution, ThreatLevel, Analysis, MISPObject, MISPAttribute, MISPSighting, MISPShadowAttribute, MISPTag, MISPSharingGroup, MISPFeed, MISPServer, MISPUserSetting, MISPEventBlocklist
    from pymisp.exceptions import MISPServerError
except ImportError:
    if sys.version_info < (3, 6):
        print('This test suite requires Python 3.6+, breaking.')
        sys.exit(0)
    else:
        raise

try:
    from keys import misp_url as url, misp_key as key  # type: ignore
    verifycert = False
except ImportError as e:
    print(e)
    url = 'https://localhost:8443'
    key = 'd6OmdDFvU3Seau3UjwvHS1y3tFQbaRNhJhDX0tjh'
    verifycert = False

urllib3.disable_warnings()

fast_mode = True

def setup_report_env(func):
    @functools.wraps(func)
    def wrapper(self,*args,**kwargs):
        try:
            event = MISPEvent()
            event.info = 'Test event report'
            event.distribution = Distribution.this_community_only
            event.threat_level_id = ThreatLevel.low
            event.analysis = Analysis.completed
            event.set_date("2017-12-31")
            self.event = self.popKey(self.admin_misp_connector.add_event(event))
            self.publish_event()
            self.testReport['event_id'] = self.event['id']
            func(self,*args,**kwargs)
        finally:
            self.admin_misp_connector.delete_event(event)
    return wrapper

def setup_full_report_env(func):
    @setup_report_env
    @functools.wraps(func)
    def wrapper(self,*args,**kwargs):
        try:
            sg = MISPSharingGroup()
            sg.name = 'Testcases SG'
            sg.releasability = 'Testing'
            self.sharing_group = self.admin_misp_connector.add_sharing_group(sg, pythonify=True)
            self.assertEqual(self.sharing_group.name, 'Testcases SG')
            func(self,*args,**kwargs)
        finally:
            self.admin_misp_connector.delete_sharing_group(self.sharing_group.id)
    return wrapper

class TestEventReportComprehensive(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.maxDiff = None
        # Connect as admin
        cls.admin_misp_connector = PyMISP(url, key, verifycert, debug=False)
        cls.admin_misp_connector.set_server_setting('Security.allow_self_registration', True, force=True)
        if not fast_mode:
            r = cls.admin_misp_connector.update_misp()
            print(r)
        # Creates an org
        organisation = MISPOrganisation()
        organisation.name = 'Test Org'
        cls.test_org = cls.admin_misp_connector.add_organisation(organisation, pythonify=True)
        # Creates a user
        user = MISPUser()
        user.email = 'testusr@user.local'
        user.org_id = cls.test_org.id
        cls.test_usr = cls.admin_misp_connector.add_user(user, pythonify=True)
        cls.user_misp_connector = PyMISP(url, cls.test_usr.authkey, verifycert, debug=True)
        cls.user_misp_connector.toggle_global_pythonify()

        cls.event = None
        cls.sharing_group = None
        cls.testReport = {
            'name': 'Test report',
            'content': 'Report content',
            'distribution': str(Distribution.this_community_only.value),
            'sharing_group_id': '0'
        }

    @classmethod
    def tearDownClass(cls):
        # Delete user
        cls.admin_misp_connector.delete_user(cls.test_usr)
        # Delete org
        cls.admin_misp_connector.delete_organisation(cls.test_org)

    def compare_report(self, base_report, report):
        to_check = ['uuid', 'name', 'content', 'distribution', 'sharing_group_id']
        for k in to_check:
            if k in base_report:
                self.assertEqual(base_report[k], report[k], msg=f'Field {k} is diferrent')

    @classmethod
    def popKey(cls, report, keyname = 'EventReport'):
        if type(report) is list:
            return [cls.popKey(r) for r in report]
        if keyname in report:
            return report[keyname]
        else:
            return report

    @setup_report_env
    def test_CRUD(self):
        self.assertTrue(self.get_event().published, msg='Event should be published')
        newReport = self.add_report(self.testReport)
        self.compare_report(self.testReport, newReport)
        self.assertFalse(self.get_event().published, msg='Event should have been unpublished')

        self.publish_event()
        self.assertTrue(self.get_event().published, msg='Event should be published')
        time.sleep(1.2)
        editedReport, returnedReport = self.edit_report(newReport)
        self.compare_report(editedReport, returnedReport)
        self.assertNotEqual(editedReport['timestamp'], returnedReport['timestamp'], msg='Timestamp should have been bumped')
        self.assertFalse(self.get_event().published, msg='Event should have been unpublished')

        self.publish_event()
        self.assertTrue(self.get_event().published, msg='Event should be published')
        self.assertFalse(returnedReport['deleted'], msg='Report should not be already deleted')
        softDeletedReport = self.soft_delete_report(returnedReport)
        self.assertTrue(softDeletedReport['deleted'], msg='Report should have been soft deleted')
        self.assertFalse(self.get_event().published, msg='Event should have been unpublished')

        self.publish_event()
        self.assertTrue(self.get_event().published, msg='Event should be published')
        self.restore_report(softDeletedReport)
        restoredReport = self.get_report(softDeletedReport['id'])
        self.assertFalse(restoredReport['deleted'])
        self.assertFalse(self.get_event().published, msg='Event should have been unpublished')

        self.publish_event()
        self.assertTrue(self.get_event().published, msg='Event should be published')
        self.hard_delete_report(restoredReport)
        hardDeletedReport = self.get_report(restoredReport['id'])
        self.assertIn('errors', hardDeletedReport, msg='Report should have been hard deleted')
        self.assertFalse(self.get_event().published, msg='Event should have been unpublished')

    @setup_full_report_env
    def test_Distribution(self):
        report0 = {
            'name': 'report - org only',
            'distribution': str(Distribution.your_organisation_only.value),
            'content': 'foo',
            'event_id': self.event['id']
        }
        report1 = {
            'name': 'report - this community',
            'distribution': str(Distribution.this_community_only.value),
            'content': 'foo',
            'event_id': self.event['id']
        }
        report2 = {
            'name': 'report - connected',
            'distribution': str(Distribution.connected_communities.value),
            'content': 'foo',
            'event_id': self.event['id']
        }
        report3 = {
            'name': 'report - all community',
            'distribution': str(Distribution.all_communities.value),
            'content': 'foo',
            'event_id': self.event['id']
        }
        report4 = {
            'name': 'report - sharing group',
            'distribution': str(Distribution.sharing_group.value),
            'sharing_group_id': self.sharing_group.id,
            'content': 'foo',
            'event_id': self.event['id']
        }
        report5 = {
            'name': 'report - inherit event',
            'distribution': str(Distribution.inherit.value),
            'content': 'foo',
            'event_id': self.event['id']
        }
        reports = [report0, report1, report2, report3, report4, report5]
        addedReports = []
        for report in reports:
            addedReport = self.add_report(report)
            addedReports.append(addedReport)
            reportSeenByUser = self.get_report(addedReport['id'], self.user_misp_connector)
            if report['distribution'] == '0':
                self.assertIn('errors', reportSeenByUser, msg="User should not see org_only")
            elif report['distribution'] == '1':
                self.assertNotIn('errors', reportSeenByUser, msg="User should be able to see this community only")
            elif report['distribution'] == '2':
                self.assertNotIn('errors', reportSeenByUser, msg="User should be able to see connected community")
            elif report['distribution'] == '3':
                self.assertNotIn('errors', reportSeenByUser, msg="User should be able to see all community")
            elif report['distribution'] == '4':
                self.assertIn('errors', reportSeenByUser, msg="User should not see sharing group")
            elif report['distribution'] == '5':
                self.assertNotIn('errors', reportSeenByUser, msg="User should be able to see inherit")
        reportSeenByAdmin = self.get_index(self.event['id'], self.admin_misp_connector)
        self.assertEqual(len(reportSeenByAdmin), 6, msg="Admin should see all reports")
        reportSeenByUser = self.get_index(self.event['id'], self.user_misp_connector)
        self.assertEqual(len(reportSeenByUser), 4, msg="User should not see org_only and sharing group reports")
        for report in addedReports:
            self.hard_delete_report(report)

    @setup_report_env
    def test_ACL(self):
        addedReport = self.add_report(self.testReport, self.user_misp_connector)
        self.assertIn('errors', addedReport, msg="This user should not be able to add a report to an event he does not own")
        addedReport = self.add_report(self.testReport)
        editedReport, returnedReport = self.edit_report(addedReport, self.user_misp_connector)
        self.assertIn('errors', returnedReport, msg="This user should not be able to edit a report he does not own")
        deletedReport = self.soft_delete_report(addedReport, self.user_misp_connector)
        self.assertIn('errors', deletedReport, msg="This user should not be able to delete a report he does not own")

    def add_report(self, report, connector = None):
        relative_path = f"eventReports/add/{self.event['id']}"
        if connector is None:
            newReport = self.admin_misp_connector.direct_call(relative_path, data=report)
        else:
            newReport = connector.direct_call(relative_path, data=report)
        newReport = self.popKey(newReport)
        return newReport

    def edit_report(self, report, connector = None):
        relative_path = f"eventReports/edit/{report['id']}"
        report['name'] = 'Test report - name changed'
        report['content'] = 'Report content - content changed'
        report['distribution'] = str(Distribution.inherit.value)
        if connector is None:
            returnedReport = self.admin_misp_connector.direct_call(relative_path, data=report)
        else:
            returnedReport = connector.direct_call(relative_path, data=report)
        returnedReport = self.popKey(returnedReport)
        return report, returnedReport

    def soft_delete_report(self, report, connector = None):
        relative_path = f"eventReports/delete/{report['id']}"
        if connector is None:
            report = self.admin_misp_connector.direct_call(relative_path, data={})
        else:
            report = connector.direct_call(relative_path)
        report = self.popKey(report)
        return report

    def hard_delete_report(self, report, connector = None):
        relative_path = f"eventReports/delete/{report['id']}/1"
        if connector is None:
            report = self.admin_misp_connector.direct_call(relative_path, data={})
        else:
            report = connector.direct_call(relative_path)
        report = self.popKey(report)
        return report

    def restore_report(self, report, connector = None):
        relative_path = f"eventReports/restore/{report['id']}"
        if connector is None:
            report = self.admin_misp_connector.direct_call(relative_path, data={})
        else:
            report = connector.direct_call(relative_path)
        report = self.popKey(report)
        return report

    def get_report(self, reportID, connector = None):
        relative_path = f"eventReports/view/{reportID}"
        if connector is None:
            report = self.admin_misp_connector.direct_call(relative_path)
        else:
            report = connector.direct_call(relative_path)
        report = self.popKey(report)
        return report

    def get_index(self, eventID=None, connector = None):
        relative_path = f"eventReports/index"
        if eventID is not None:
            relative_path += f"/event_id:{eventID}"
        if connector is None:
            report = self.admin_misp_connector.direct_call(relative_path)
        else:
            report = connector.direct_call(relative_path)
        report = self.popKey(report)
        return report

    def publish_event(self):
        result = self.admin_misp_connector.publish(self.event)
        self.event = self.popKey(result, keyname='Event')

    def get_event(self):
        return self.popKey(self.admin_misp_connector.get_event(self.event['id'], pythonify=True), keyname='Event')
