#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pymisp import PyMISP, __version__
try:
    from keys import url, key
except ImportError as e:
    print(e)
    url = 'http://localhost:8080'
    key = 'fk5BodCZw8owbscW8pQ4ykMASLeJ4NYhuAbshNjo'

import time

import unittest


class TestBasic(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        self.misp = PyMISP(url, key, True, 'json')
        self.live_describe_types = self.misp.get_live_describe_types()

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
                               u'attribute_count': u'0', 'disable_correlation': False, u'analysis': u'0',
                               u'ShadowAttribute': [], u'published': False,
                               u'distribution': u'0', u'event_creator_email': u'admin@admin.test', u'Attribute': [], u'proposal_email_lock': False,
                               u'extends_uuid': '',
                               u'Object': [], u'Org': {u'name': u'ORGNAME'},
                               u'Orgc': {u'name': u'ORGNAME'},
                               u'Galaxy': [],
                               u'threat_level_id': u'1'}}
        self.assertEqual(event, to_check, 'Failed at creating a new Event')
        return int(event_id)

    def add_hashes(self, eventid):
        r = self.misp.get_event(eventid)
        event = r.json()
        event = self.misp.add_hashes(event,
                                     category='Payload installation',
                                     filename='dll_installer.dll',
                                     md5='0a209ac0de4ac033f31d6ba9191a8f7a',
                                     sha1='1f0ae54ac3f10d533013f74f48849de4e65817a7',
                                     sha256='003315b0aea2fcb9f77d29223dd8947d0e6792b3a0227e054be8eb2a11f443d9',
                                     ssdeep=None,
                                     comment='Fanny modules',
                                     to_ids=False,
                                     distribution=2,
                                     proposal=False)
        self._clean_event(event)
        to_check = {u'Event': {u'info': u'This is a test', u'locked': False,
                               u'attribute_count': u'3', u'analysis': u'0',
                               u'ShadowAttribute': [], u'published': False, u'distribution': u'0', u'event_creator_email': u'admin@admin.test',
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
                               u'ShadowAttribute': [], u'published': True, u'distribution': u'0', u'event_creator_email': u'admin@admin.test',
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
                            u'ShadowAttribute': [], u'published': False, u'distribution': u'0', u'event_creator_email': u'admin@admin.test',
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

    def add_user(self):
        email = 'test@misp.local'
        role_id = '5'
        org_id = '1'
        password = 'Password1234!'
        external_auth_required = False
        external_auth_key = ''
        enable_password = False
        nids_sid = '1238717'
        server_id = '1'
        gpgkey = ''
        certif_public = ''
        autoalert = False
        contactalert = False
        disabled = False
        change_pw = '0'
        termsaccepted = False
        newsread = '0'
        authkey = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        to_check = {'User': {'email': email, 'org_id': org_id, 'role_id': role_id,
                             'password': password, 'external_auth_required': external_auth_required,
                             'external_auth_key': external_auth_key, 'enable_password': enable_password,
                             'nids_sid': nids_sid, 'server_id': server_id, 'gpgkey': gpgkey,
                             'certif_public': certif_public, 'autoalert': autoalert,
                             'contactalert': contactalert, 'disabled': disabled,
                             'change_pw': change_pw, 'termsaccepted': termsaccepted,
                             'newsread': newsread, 'authkey': authkey}}
        user = self.misp.add_user(email=email,
                                  role_id=role_id,
                                  org_id=org_id,
                                  password=password,
                                  external_auth_required=external_auth_required,
                                  external_auth_key=external_auth_key,
                                  enable_password=enable_password,
                                  nids_sid=nids_sid,
                                  server_id=server_id,
                                  gpgkey=gpgkey,
                                  certif_public=certif_public,
                                  autoalert=autoalert,
                                  contactalert=contactalert,
                                  disabled=disabled,
                                  change_pw=change_pw,
                                  termsaccepted=termsaccepted,
                                  newsread=newsread,
                                  authkey=authkey)
        # delete user to allow reuse of test
        uid = user.get('User').get('id')
        self.misp.delete_user(uid)
        # ----------------------------------
        # test interesting keys only (some keys are modified(password) and some keys are added (lastlogin)
        tested_keys = ['email', 'org_id', 'role_id', 'server_id', 'autoalert',
                       'authkey', 'gpgkey', 'certif_public', 'nids_sid', 'termsaccepted',
                       'newsread', 'contactalert', 'disabled']
        for k in tested_keys:
            self.assertEqual(user.get('User').get(k), to_check.get('User').get(k), "Failed to match input with output on key: {}".format(k))

    def add_organisation(self):
        name = 'Organisation tests'
        description = 'This is a test organisation'
        orgtype = 'Type is a string'
        nationality = 'French'
        sector = 'Bank sector'
        uuid = '16fd2706-8baf-433b-82eb-8c7fada847da'
        contacts = 'Text field with no limitations'
        local = False
        to_check = {'Organisation': {'name': name, 'description': description,
                                     'type': orgtype, 'nationality': nationality,
                                     'sector': sector, 'uuid': uuid, 'contacts': contacts,
                                     'local': local}}
        org = self.misp.add_organisation(name=name,
                                         description=description,
                                         type=orgtype,
                                         nationality=nationality,
                                         sector=sector,
                                         uuid=uuid,
                                         contacts=contacts,
                                         local=local,
                                         )
        # delete organisation to allow reuse of test
        oid = org.get('Organisation').get('id')
        self.misp.delete_organisation(oid)
        # ----------------------------------
        tested_keys = ['anonymise', 'contacts', 'description', 'local', 'name',
                       'nationality', 'sector', 'type', 'uuid']
        for k in tested_keys:
            self.assertEqual(org.get('Organisation').get(k), to_check.get('Organisation').get(k), "Failed to match input with output on key: {}".format(k))

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

    def test_create_user(self):
        self.add_user()

    def test_create_organisation(self):
        self.add_organisation()

    def test_describeTypes_sane_default(self):
        sane_default = self.live_describe_types['sane_defaults']
        self.assertEqual(sorted(sane_default.keys()), sorted(self.live_describe_types['types']))

    def test_describeTypes_categories(self):
        category_type_mappings = self.live_describe_types['category_type_mappings']
        self.assertEqual(sorted(category_type_mappings.keys()), sorted(self.live_describe_types['categories']))

    def test_describeTypes_types_in_categories(self):
        category_type_mappings = self.live_describe_types['category_type_mappings']
        for category, types in category_type_mappings.items():
                existing_types = [t for t in types if t in self.live_describe_types['types']]
                self.assertEqual(sorted(existing_types), sorted(types))

    def test_describeTypes_types_have_category(self):
        category_type_mappings = self.live_describe_types['category_type_mappings']
        all_types = set()
        for category, types in category_type_mappings.items():
            all_types.update(types)
        self.assertEqual(sorted(list(all_types)), sorted(self.live_describe_types['types']))

    def test_describeTypes_sane_default_valid_category(self):
        sane_default = self.live_describe_types['sane_defaults']
        categories = self.live_describe_types['categories']
        for t, sd in sane_default.items():
            self.assertTrue(sd['to_ids'] in [0, 1])
            self.assertTrue(sd['default_category'] in categories)

    def test_describeTypes_uptodate(self):
        local_describe = self.misp.get_local_describe_types()
        for temp_key in local_describe.keys():
            if isinstance(local_describe[temp_key], list):
                self.assertEqual(sorted(self.live_describe_types[temp_key]), sorted(local_describe[temp_key]))
            else:
                self.assertEqual(self.live_describe_types[temp_key], local_describe[temp_key])

    def test_live_acl(self):
        query_acl = self.misp.get_live_query_acl()
        self.assertEqual(query_acl['response'], [])

    def test_recommended_pymisp_version(self):
        response = self.misp.get_recommended_api_version()
        recommended_version_tup = tuple(int(x) for x in response['version'].split('.'))
        pymisp_version_tup = tuple(int(x) for x in __version__.split('.'))[:3]
        self.assertEqual(recommended_version_tup, pymisp_version_tup)


if __name__ == '__main__':
    unittest.main()
