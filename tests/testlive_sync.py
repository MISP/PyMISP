#!/usr/bin/env python3

from __future__ import annotations

import time
import unittest
import subprocess

import urllib3
import logging
logging.disable(logging.CRITICAL)

try:
    from pymisp import PyMISP, MISPOrganisation, MISPUser, MISPEvent, MISPObject, MISPSharingGroup, Distribution
except ImportError:
    raise

key = 'eYQdGTEWZJ8C2lm9EpnMqxQGwGiPNyoR75JvLdlE'
verifycert = False


urllib3.disable_warnings()

'''
Static IP config

auto eth1
iface eth1 inet static
address 192.168.1.XXX
netmask 255.255.255.0
network 192.168.1.0
broadcast 192.168.1.255
'''

misp_instances = [
    {
        'url': 'https://localhost:8643',
        'external_baseurl': 'https://192.168.1.1',
        'key': key,
        'orgname': 'First org',
        'email_site_admin': 'first@site-admin.local',
        'email_admin': 'first@org-admin.local',
        'email_user': 'first@user.local'
    },
    {
        'url': 'https://localhost:8644',
        'external_baseurl': 'https://192.168.1.2',
        'key': key,
        'orgname': 'Second org',
        'email_site_admin': 'second@site-admin.local',
        'email_admin': 'second@org-admin.local',
        'email_user': 'second@user.local'
    },
    {
        'url': 'https://localhost:8645',
        'external_baseurl': 'https://192.168.1.3',
        'key': key,
        'orgname': 'Third org',
        'email_site_admin': 'third@site-admin.local',
        'email_admin': 'third@org-admin.local',
        'email_user': 'third@user.local'
    },
]

# Assumes the VMs are already started, doesn't shut them down
fast_mode = True


class MISPInstance():

    def __init__(self, params):
        self.initial_user_connector = PyMISP(params['url'], params['key'], ssl=False, debug=False)
        # Git pull
        self.initial_user_connector.update_misp()
        # Set the default role (id 3 on the VM is normal user)
        self.initial_user_connector.set_default_role(3)
        # Restart workers
        self.initial_user_connector.restart_workers()
        if not fast_mode:
            # Load submodules
            self.initial_user_connector.update_object_templates()
            self.initial_user_connector.update_galaxies()
            self.initial_user_connector.update_noticelists()
            self.initial_user_connector.update_warninglists()
            self.initial_user_connector.update_taxonomies()

        self.initial_user_connector.toggle_global_pythonify()

        # Create organisation
        organisation = MISPOrganisation()
        organisation.name = params['orgname']
        self.test_org = self.initial_user_connector.add_organisation(organisation)
        print(self.test_org.name, self.test_org.uuid)
        # Create Site admin in new org
        user = MISPUser()
        user.email = params['email_site_admin']
        user.org_id = self.test_org.id
        user.role_id = 1  # Site admin
        self.test_site_admin = self.initial_user_connector.add_user(user)
        self.site_admin_connector = PyMISP(params['url'], self.test_site_admin.authkey, ssl=False, debug=False)
        self.site_admin_connector.toggle_global_pythonify()
        # Create org admin
        user = MISPUser()
        user.email = params['email_admin']
        user.org_id = self.test_org.id
        user.role_id = 2  # Org admin
        self.test_org_admin = self.site_admin_connector.add_user(user)
        self.org_admin_connector = PyMISP(params['url'], self.test_org_admin.authkey, ssl=False, debug=False)
        self.org_admin_connector.toggle_global_pythonify()
        # Create user
        user = MISPUser()
        user.email = params['email_user']
        user.org_id = self.test_org.id
        self.test_usr = self.org_admin_connector.add_user(user)
        self.user_connector = PyMISP(params['url'], self.test_usr.authkey, ssl=False, debug=False)
        self.user_connector.toggle_global_pythonify()

        # Setup external_baseurl
        self.site_admin_connector.set_server_setting('MISP.external_baseurl', params['external_baseurl'], force=True)
        # Setup baseurl
        self.site_admin_connector.set_server_setting('MISP.baseurl', params['url'], force=True)
        # Setup host org
        self.site_admin_connector.set_server_setting('MISP.host_org_id', self.test_org.id)

        self.external_base_url = params['external_baseurl']
        self.sync = []
        self.sync_servers = []

    def __repr__(self):
        return f'<{self.__class__.__name__}(external={self.external_base_url})'

    def create_sync_user(self, organisation):
        sync_org = self.site_admin_connector.add_organisation(organisation)
        short_org_name = sync_org.name.lower().replace(' ', '-')
        user = MISPUser()
        user.email = f"sync_user@{short_org_name}.local"
        user.org_id = sync_org.id
        user.role_id = 5  # Org admin
        sync_user = self.site_admin_connector.add_user(user)
        sync_user_connector = PyMISP(self.site_admin_connector.root_url, sync_user.authkey, ssl=False, debug=False)
        sync_server_config = sync_user_connector.get_sync_config(pythonify=True)
        self.sync.append((sync_org, sync_user, sync_server_config))

    def create_sync_server(self, name, server):
        server = self.site_admin_connector.import_server(server)
        server.self_signed = True
        server.pull = True  # Not automatic, but allows to do a pull
        server = self.site_admin_connector.update_server(server)
        r = self.site_admin_connector.test_server(server)
        if r['status'] != 1:
            raise Exception(f'Sync test failed: {r}')
        self.sync_servers.append(server)

    def cleanup(self):
        for org, user, _ in self.sync:
            self.site_admin_connector.delete_user(user)  # Delete user from other org
            self.site_admin_connector.delete_organisation(org)

        # Delete sync servers
        for server in self.site_admin_connector.servers():
            self.site_admin_connector.delete_server(server)

        # Delete users
        self.org_admin_connector.delete_user(self.test_usr.id)
        self.site_admin_connector.delete_user(self.test_org_admin.id)
        self.initial_user_connector.delete_user(self.test_site_admin.id)
        # Delete org
        self.initial_user_connector.delete_organisation(self.test_org.id)

        # Make sure the instance is back to a clean state
        if self.initial_user_connector.events():
            raise Exception(f'Events still on the instance {self.external_base_url}')
        if self.initial_user_connector.attributes():
            raise Exception(f'Attributes still on the instance {self.external_base_url}')
        if self.initial_user_connector.attribute_proposals():
            raise Exception(f'AttributeProposals still on the instance {self.external_base_url}')
        if self.initial_user_connector.sightings():
            raise Exception(f'Sightings still on the instance {self.external_base_url}')
        if self.initial_user_connector.servers():
            raise Exception(f'Servers still on the instance {self.external_base_url}')
        if self.initial_user_connector.sharing_groups():
            raise Exception(f'SharingGroups still on the instance {self.external_base_url}')
        if len(self.initial_user_connector.organisations()) > 1:
            raise Exception(f'Organisations still on the instance {self.external_base_url}')
        if len(self.initial_user_connector.users()) > 1:
            raise Exception(f'Users still on the instance {self.external_base_url}')


class TestSync(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not fast_mode:
            subprocess.Popen(['VBoxHeadless', '-s', 'Test Sync 1'])
            subprocess.Popen(['VBoxHeadless', '-s', 'Test Sync 2'])
            subprocess.Popen(['VBoxHeadless', '-s', 'Test Sync 3'])
            time.sleep(30)
        cls.maxDiff = None
        cls.instances = []
        for misp_instance in misp_instances:
            mi = MISPInstance(misp_instance)
            cls.instances.append(mi)

        # Create all sync users
        test_orgs = [i.test_org for i in cls.instances]

        for instance in cls.instances:
            for test_org in test_orgs:
                if instance.test_org.name == test_org.name:
                    continue
                instance.create_sync_user(test_org)

        # Create all sync links
        sync_identifiers = [i.sync for i in cls.instances]
        for instance in cls.instances:
            for sync_identifier in sync_identifiers:
                for org, user, sync_server_config in sync_identifier:
                    if org.name != instance.test_org.name:
                        continue
                    instance.create_sync_server(name=f'Sync with {sync_server_config.url}',
                                                server=sync_server_config)

        ready = False
        while not ready:
            ready = True
            for i in cls.instances:
                settings = i.site_admin_connector.server_settings()
                if (not settings['workers']['default']['ok']
                        or not settings['workers']['prio']['ok']):
                    print(f'Not ready: {i}')
                    ready = False
            time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        for i in cls.instances:
            i.cleanup()
        if not fast_mode:
            subprocess.Popen(['VBoxManage', 'controlvm', 'Test Sync 1', 'poweroff'])
            subprocess.Popen(['VBoxManage', 'controlvm', 'Test Sync 2', 'poweroff'])
            subprocess.Popen(['VBoxManage', 'controlvm', 'Test Sync 3', 'poweroff'])
            time.sleep(20)
            subprocess.Popen(['VBoxManage', 'snapshot', 'Test Sync 1', 'restore', 'WithRefresh'])
            subprocess.Popen(['VBoxManage', 'snapshot', 'Test Sync 2', 'restore', 'WithRefresh'])
            subprocess.Popen(['VBoxManage', 'snapshot', 'Test Sync 3', 'restore', 'WithRefresh'])

    def test_simple_sync(self):
        '''Test simple event, push to one server'''
        event = MISPEvent()
        event.info = 'Event created on first instance - test_simple_sync'
        event.distribution = Distribution.all_communities
        event.add_attribute('ip-src', '1.1.1.1')
        try:
            source = self.instances[0]
            dest = self.instances[1]
            event = source.org_admin_connector.add_event(event)
            source.org_admin_connector.publish(event)
            source.site_admin_connector.server_push(source.sync_servers[0], event)
            time.sleep(10)
            dest_event = dest.org_admin_connector.get_event(event.uuid)
            self.assertEqual(event.attributes[0].value, dest_event.attributes[0].value)

        finally:
            source.org_admin_connector.delete_event(event)
            dest.site_admin_connector.delete_event(dest_event)

    def test_sync_community(self):
        '''Simple event, this community only, pull from member of the community'''
        event = MISPEvent()
        event.info = 'Event created on first instance - test_sync_community'
        event.distribution = Distribution.this_community_only
        event.add_attribute('ip-src', '1.1.1.1')
        try:
            source = self.instances[0]
            dest = self.instances[1]
            event = source.org_admin_connector.add_event(event)
            source.org_admin_connector.publish(event)
            dest.site_admin_connector.server_pull(dest.sync_servers[0])
            time.sleep(10)
            dest_event = dest.org_admin_connector.get_event(event.uuid)
            self.assertEqual(dest_event.distribution, 0)
        finally:
            source.org_admin_connector.delete_event(event)
            dest.site_admin_connector.delete_event(dest_event)

    def test_sync_all_communities(self):
        '''Simple event, all communities, enable automatic push on two sub-instances'''
        event = MISPEvent()
        event.info = 'Event created on first instance - test_sync_all_communities'
        event.distribution = Distribution.all_communities
        event.add_attribute('ip-src', '1.1.1.1')
        try:
            source = self.instances[0]
            server = source.site_admin_connector.update_server({'push': True}, source.sync_servers[0].id)
            self.assertTrue(server.push)
            middle = self.instances[1]
            middle.site_admin_connector.update_server({'push': True}, middle.sync_servers[1].id)  # Enable automatic push to 3rd instance
            last = self.instances[2]
            event = source.user_connector.add_event(event)
            source.org_admin_connector.publish(event)
            source.site_admin_connector.server_push(source.sync_servers[0])
            time.sleep(30)
            middle_event = middle.user_connector.get_event(event.uuid)
            self.assertEqual(event.attributes[0].value, middle_event.attributes[0].value)
            last_event = last.user_connector.get_event(event.uuid)
            self.assertEqual(event.attributes[0].value, last_event.attributes[0].value)
        finally:
            source.org_admin_connector.delete_event(event)
            middle.site_admin_connector.delete_event(middle_event)
            last.site_admin_connector.delete_event(last_event)
            source.site_admin_connector.update_server({'push': False}, source.sync_servers[0].id)
            middle.site_admin_connector.update_server({'push': False}, middle.sync_servers[1].id)

    def create_complex_event(self):
        event = MISPEvent()
        event.info = 'Complex Event'
        event.distribution = Distribution.all_communities
        event.add_tag('tlp:white')

        event.add_attribute('ip-src', '8.8.8.8')
        event.add_attribute('ip-dst', '8.8.8.9')
        event.add_attribute('domain', 'google.com')
        event.add_attribute('md5', '3c656da41f4645f77e3ec3281b63dd43')

        event.attributes[0].distribution = Distribution.your_organisation_only
        event.attributes[1].distribution = Distribution.this_community_only
        event.attributes[2].distribution = Distribution.connected_communities

        event.attributes[0].add_tag('tlp:red')
        event.attributes[1].add_tag('tlp:amber')
        event.attributes[2].add_tag('tlp:green')

        obj = MISPObject('file')

        obj.distribution = Distribution.connected_communities
        obj.add_attribute('filename', 'testfile')
        obj.add_attribute('md5', '3c656da41f4645f77e3ec3281b63dd44')
        obj.attributes[0].distribution = Distribution.your_organisation_only

        event.add_object(obj)

        return event

    def test_complex_event_push_pull(self):
        '''Test automatic push'''
        event = self.create_complex_event()
        try:
            source = self.instances[0]
            source.site_admin_connector.update_server({'push': True}, source.sync_servers[0].id)
            middle = self.instances[1]
            middle.site_admin_connector.update_server({'push': True}, middle.sync_servers[1].id)  # Enable automatic push to 3rd instance
            last = self.instances[2]

            event = source.org_admin_connector.add_event(event)
            source.org_admin_connector.publish(event)
            time.sleep(15)
            event_middle = middle.user_connector.get_event(event.uuid)
            event_last = last.user_connector.get_event(event.uuid)
            self.assertEqual(len(event_middle.attributes), 2)  # attribute 3 and 4
            self.assertEqual(len(event_middle.objects[0].attributes), 1)  # attribute 2
            self.assertEqual(len(event_last.attributes), 1)  # attribute 4
            self.assertFalse(event_last.objects)
            # Test if event is properly sanitized
            event_middle_as_site_admin = middle.site_admin_connector.get_event(event.uuid)
            self.assertEqual(len(event_middle_as_site_admin.attributes), 2)  # attribute 3 and 4
            self.assertEqual(len(event_middle_as_site_admin.objects[0].attributes), 1)  # attribute 2
            # FIXME https://github.com/MISP/MISP/issues/4975
            # Force pull from the last one
            # last.site_admin_connector.server_pull(last.sync_servers[0])
            # time.sleep(6)
            # event_last = last.user_connector.get_event(event.uuid)
            # self.assertEqual(len(event_last.objects[0].attributes), 1)  # attribute 2
            # self.assertEqual(len(event_last.attributes), 2)  # attribute 3 and 4
            # Force pull from the middle one
            # middle.site_admin_connector.server_pull(last.sync_servers[0])
            # time.sleep(6)
            # event_middle = middle.user_connector.get_event(event.uuid)
            # self.assertEqual(len(event_middle.attributes), 3)  # attribute 2, 3 and 4
            # Force pull from the last one
            # last.site_admin_connector.server_pull(last.sync_servers[0])
            # time.sleep(6)
            # event_last = last.user_connector.get_event(event.uuid)
            # self.assertEqual(len(event_last.attributes), 2)  # attribute 3 and 4
        finally:
            source.org_admin_connector.delete_event(event)
            middle.site_admin_connector.delete_event(event_middle)
            last.site_admin_connector.delete_event(event_last)
            source.site_admin_connector.update_server({'push': False}, source.sync_servers[0].id)
            middle.site_admin_connector.update_server({'push': False}, middle.sync_servers[1].id)

    def test_complex_event_pull(self):
        '''Test pull'''
        event = self.create_complex_event()
        try:
            source = self.instances[0]
            middle = self.instances[1]
            last = self.instances[2]

            event = source.org_admin_connector.add_event(event)
            source.org_admin_connector.publish(event)
            middle.site_admin_connector.server_pull(middle.sync_servers[0])
            time.sleep(6)
            last.site_admin_connector.server_pull(last.sync_servers[1])
            time.sleep(6)
            event_middle = middle.user_connector.get_event(event.uuid)
            event_last = last.user_connector.get_event(event.uuid)
            self.assertEqual(len(event_middle.attributes), 3)  # attribute 2, 3 and 4
            self.assertEqual(len(event_middle.objects[0].attributes), 1)  # attribute 2
            self.assertEqual(len(event_last.attributes), 2)  # attribute 3, 4
            self.assertEqual(len(event_last.objects[0].attributes), 1)
            # Test if event is properly sanitized
            event_middle_as_site_admin = middle.site_admin_connector.get_event(event.uuid)
            self.assertEqual(len(event_middle_as_site_admin.attributes), 3)  # attribute 2, 3 and 4
            self.assertEqual(len(event_middle_as_site_admin.objects[0].attributes), 1)  # attribute 2
        finally:
            source.org_admin_connector.delete_event(event)
            middle.site_admin_connector.delete_event(event_middle)
            last.site_admin_connector.delete_event(event_last)

    def test_sharing_group(self):
        '''Test Sharing Group'''
        event = self.create_complex_event()
        try:
            source = self.instances[0]
            source.site_admin_connector.update_server({'push': True}, source.sync_servers[0].id)
            middle = self.instances[1]
            middle.site_admin_connector.update_server({'push': True}, middle.sync_servers[1].id)  # Enable automatic push to 3rd instance
            last = self.instances[2]

            sg = MISPSharingGroup()
            sg.name = 'Testcases SG'
            sg.releasability = 'Testing'
            sharing_group = source.site_admin_connector.add_sharing_group(sg)
            source.site_admin_connector.add_org_to_sharing_group(sharing_group, middle.test_org.uuid)
            source.site_admin_connector.add_server_to_sharing_group(sharing_group, 0)  # Add local server
            # NOTE: the data on that sharing group *won't be synced anywhere*

            a = event.add_attribute('text', 'SG only attr')
            a.distribution = Distribution.sharing_group
            a.sharing_group_id = sharing_group.id

            event = source.org_admin_connector.add_event(event)
            source.org_admin_connector.publish(event)
            time.sleep(60)

            event_middle = middle.user_connector.get_event(event)
            self.assertTrue(isinstance(event_middle, MISPEvent), event_middle)
            self.assertEqual(len(event_middle.attributes), 2, event_middle)
            self.assertEqual(len(event_middle.objects), 1, event_middle)
            self.assertEqual(len(event_middle.objects[0].attributes), 1, event_middle)

            event_last = last.user_connector.get_event(event)
            self.assertTrue(isinstance(event_last, MISPEvent), event_last)
            self.assertEqual(len(event_last.attributes), 1)
            # Test if event is properly sanitized
            event_middle_as_site_admin = middle.site_admin_connector.get_event(event.uuid)
            self.assertEqual(len(event_middle_as_site_admin.attributes), 2)
            event_last_as_site_admin = last.site_admin_connector.get_event(event.uuid)
            self.assertEqual(len(event_last_as_site_admin.attributes), 1)
            # Get sharing group from middle instance
            sgs = middle.site_admin_connector.sharing_groups()
            self.assertEqual(len(sgs), 0)

            # TODO: Update sharing group so the attribute is pushed
            # self.assertEqual(sgs[0].name, 'Testcases SG')
            # middle.site_admin_connector.delete_sharing_group(sgs[0])
        finally:
            source.org_admin_connector.delete_event(event)
            middle.site_admin_connector.delete_event(event)
            last.site_admin_connector.delete_event(event)
            source.site_admin_connector.delete_sharing_group(sharing_group.id)
            middle.site_admin_connector.delete_sharing_group(sharing_group.id)
            source.site_admin_connector.update_server({'push': False}, source.sync_servers[0].id)
            middle.site_admin_connector.update_server({'push': False}, middle.sync_servers[1].id)
