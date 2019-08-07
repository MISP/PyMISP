#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import sys
import unittest
import subprocess

import urllib3
import logging
logging.disable(logging.CRITICAL)

try:
    from pymisp import ExpandedPyMISP, MISPOrganisation, MISPUser, MISPServer
except ImportError:
    if sys.version_info < (3, 6):
        print('This test suite requires Python 3.6+, breaking.')
        sys.exit(0)
    else:
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
        'email_admin': 'first@admin.local',
        'email_user': 'first@user.local'
    },
    {
        'url': 'https://localhost:8644',
        'external_baseurl': 'https://192.168.1.2',
        'key': key,
        'orgname': 'Second org',
        'email_admin': 'second@admin.local',
        'email_user': 'second@user.local'
    },
    {
        'url': 'https://localhost:8645',
        'external_baseurl': 'https://192.168.1.3',
        'key': key,
        'orgname': 'Third org',
        'email_admin': 'third@admin.local',
        'email_user': 'third@user.local'
    },
]

# Assumes the VMs are already started, doesn't shut them down
fast_mode = True


class MISPInstance():

    def __init__(self, params):
        self.site_admin_connector = ExpandedPyMISP(params['url'], params['key'], ssl=False, debug=False)
        # Set the default role (id 3 on the VM is normal user)
        self.site_admin_connector.set_default_role(3)
        if not fast_mode:
            # Git pull
            self.site_admin_connector.update_misp()
            # Load submodules
            self.site_admin_connector.update_object_templates()
            self.site_admin_connector.update_galaxies()
            self.site_admin_connector.update_noticelists()
            self.site_admin_connector.update_warninglists()
            self.site_admin_connector.update_taxonomies()

        self.site_admin_connector.toggle_global_pythonify()

        # Create organisation
        organisation = MISPOrganisation()
        organisation.name = params['orgname']
        self.test_org = self.site_admin_connector.add_organisation(organisation)
        print(self.test_org.name, self.test_org.uuid)
        # Create org admin
        user = MISPUser()
        user.email = params['email_admin']
        user.org_id = self.test_org.id
        user.role_id = 2  # Org admin
        self.test_admin = self.site_admin_connector.add_user(user)
        self.org_admin_connector = ExpandedPyMISP(params['url'], self.test_admin.authkey, ssl=False, debug=False)
        self.org_admin_connector.toggle_global_pythonify()
        # Create user
        user = MISPUser()
        user.email = params['email_user']
        user.org_id = self.test_org.id
        self.test_usr = self.org_admin_connector.add_user(user)
        self.usr_connector = ExpandedPyMISP(params['url'], self.test_admin.authkey, ssl=False, debug=False)
        self.usr_connector.toggle_global_pythonify()

        # Setup external_baseurl
        self.site_admin_connector.set_server_setting('MISP.external_baseurl', params['external_baseurl'], force=True)

        self.external_base_url = params['external_baseurl']
        self.sync = []

    def create_sync_user(self, organisation):
        sync_org = self.site_admin_connector.add_organisation(organisation)
        short_org_name = sync_org.name.lower().replace(' ', '-')
        user = MISPUser()
        user.email = f"sync_user@{short_org_name}.local"
        user.org_id = sync_org.id
        user.role_id = 5  # Org admin
        sync_user = self.site_admin_connector.add_user(user)
        self.sync.append((sync_org, sync_user, self.external_base_url))

    def create_sync_server(self, name, remote_url, authkey, organisation):
        server = MISPServer()
        server.name = name
        server.self_signed = True
        server.url = remote_url
        server.authkey = authkey
        server.remote_org_id = organisation.id
        server = self.site_admin_connector.add_server(server)
        r = self.site_admin_connector.test_server(server)
        print(r)

    def cleanup(self):
        for org, user, remote_url in self.sync:
            self.site_admin_connector.delete_user(user)  # Delete user from other org
            self.site_admin_connector.delete_organisation(org)

        # Delete sync servers
        for server in self.site_admin_connector.servers():
            self.site_admin_connector.delete_server(server)

        # Delete users
        self.org_admin_connector.delete_user(self.test_usr.id)
        self.site_admin_connector.delete_user(self.test_admin.id)
        # Delete org
        self.site_admin_connector.delete_organisation(self.test_org.id)


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
                for org, user, remote_url in sync_identifier:
                    if org.name != instance.test_org.name:
                        continue
                    instance.create_sync_server(name=f'Sync with {remote_url}',
                                                remote_url=remote_url,
                                                authkey=user.authkey,
                                                organisation=instance.test_org)

    @classmethod
    def tearDownClass(cls):
        for i in cls.instances:
            i.cleanup()
        if not fast_mode:
            subprocess.Popen(['VBoxManage', 'controlvm', 'Test Sync 1', 'poweroff'])
            subprocess.Popen(['VBoxManage', 'controlvm', 'Test Sync 2', 'poweroff'])
            subprocess.Popen(['VBoxManage', 'controlvm', 'Test Sync 3', 'poweroff'])
            time.sleep(20)
            subprocess.Popen(['VBoxManage', 'snapshot', 'Test Sync 1', 'restore', 'Snapshot 1'])
            subprocess.Popen(['VBoxManage', 'snapshot', 'Test Sync 2', 'restore', 'Snapshot 1'])
            subprocess.Popen(['VBoxManage', 'snapshot', 'Test Sync 3', 'restore', 'Snapshot 1'])

    def test_simple_sync(self):
        server = MISPServer()
        server.name = 'Second Instance'
        server.url = misp_instances[1]['external_baseurl']
