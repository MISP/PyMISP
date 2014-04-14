#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Python API for MISP """

import requests


class PyMISP(object):
    """ Python API for MISP, you will need the URL
    of the instnce you want to query,  and the auth key of your user."""

    def __init__(self, url, key, out_type='json'):
        self.url = url + '/events'
        self.key = key
        self.out_type = out_type
        self.rest = self.url + '/{}'

    def __prepare_session(self, force_out=None):
        """
            Prepare the headers of the session
        """
        if force_out is not None:
            out = force_out
        else:
            out = self.out_type
        session = requests.Session()
        session.headers.update(
            {'Authorization': self.key,
             'Accept': 'application/' + out,
             'content-type': 'text/' + out})
        return session

    # ############### REST API ################

    def get_index(self):
        """
            Return the index.

            Warning, there's a limit on the number of results
        """
        session = self.__prepare_session()
        return session.get(self.rest, verify=False)

    def get_event(self, event_id):
        """
            Get an event
        """
        session = self.__prepare_session()
        return session.get(self.rest.format(event_id), verify=False)

    def add_event(self, event):
        """
            Add a new event
        """
        session = self.__prepare_session()
        return session.post(self.url, data=event, verify=False)

    def update_event(self, event_id, event):
        """
            Update an event
        """
        session = self.__prepare_session()
        return session.post(self.rest.format(event_id), data=event,
                            verify=False)

    def delete_event(self, event_id):
        """
            Delete an event
        """
        session = self.__prepare_session()
        return session.delete(self.rest.format(event_id), verify=False)

    # ######## REST Search #########

    def __prepare_rest_search(self, values, not_values):
        """
            Prepare a search
        """
        to_return = ''
        if values is not None:
            if not isinstance(values, list):
                to_return += values
            else:
                to_return += '&&'.join(values)
        if not_values is not None:
            if len(to_return) > 0:
                to_return += '&&!'
            else:
                to_return += '!'
            if not isinstance(values, list):
                to_return += not_values
            else:
                to_return += '&&!'.join(not_values)
        return to_return

    def search(self, values=None, not_values=None, type_attribute=None,
               category=None, org=None, tags=None, not_tags=None):
        """
            Search via the Rest API
        """
        search = self.url + '/restSearch/download/{}/{}/{}/{}/{}'
        val = self.__prepare_rest_search(values, not_values).replace('/', '|')
        tag = self.__prepare_rest_search(tags, not_tags).replace(':', ';')
        if len(val) == 0:
            val = 'null'
        if len(tag) == 0:
            tag = 'null'
        if type_attribute is None:
            type_attribute = 'null'
        if category is None:
            category = 'null'
        if org is None:
            org = 'null'

        session = self.__prepare_session()
        return session.get(search.format(val, type_attribute,
                                         category, org, tag), verify=False)

    def get_attachement(self, event_id):
        """
            Get attachement of an event (not sample)
        """
        attach = self.url + '/attributes/downloadAttachment/download/{}'
        session = self.__prepare_session()
        return session.get(attach.format(event_id), verify=False)

    # ############## Export ###############

    def download_all(self):
        """
            Download all event from the instance
        """
        xml = self.url + '/xml/download'
        session = self.__prepare_session('xml')
        return session.get(xml, verify=False)

    def download(self, event_id, with_attachement=False):
        """
            Download one event in XML
        """
        template = self.url + '/events/xml/download/{}/{}'
        if with_attachement:
            attach = 'true'
        else:
            attach = 'false'
        session = self.__prepare_session('xml')
        return session.get(template.format(event_id, attach), verify=False)

    ##########################################
