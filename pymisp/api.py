#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Python API using the REST interface of MISP """

import requests


class PyMISP(object):
    """
        Python API for MISP

        :param url: URL of the MISP instance you want to connect to
        :param key: API key of the user you want to use
        :param ssl: can be True or False (to check ot not the validity
                    of the certificate. Or a CA_BUNDLE in case of self
                    signed certiifcate (the concatenation of all the
                    *.crt of the chain)
        :param out_type: Type of object (json or xml)
    """

    def __init__(self, url, key, ssl=True, out_type='json'):
        self.url = url + '/events'
        self.key = key
        self.ssl = ssl
        self.out_type = out_type
        self.rest = self.url + '/{}'

    def __prepare_session(self, force_out=None):
        """
            Prepare the headers of the session

            :param force_out: force the type of the expect output
                              (overwrite the constructor)

        """
        if force_out is not None:
            out = force_out
        else:
            out = self.out_type
        session = requests.Session()
        session.verify = self.ssl
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
        return session.get(self.rest)

    def get_event(self, event_id):
        """
            Get an event

            :param event_id: Event id to get
        """
        session = self.__prepare_session()
        return session.get(self.rest.format(event_id))

    def add_event(self, event):
        """
            Add a new event

            :param event: Event object to add
        """
        session = self.__prepare_session()
        return session.post(self.url, data=event)

    def update_event(self, event_id, event):
        """
            Update an event

            :param event_id: Event id to update
            :param event: Elements to add
        """
        session = self.__prepare_session()
        return session.post(self.rest.format(event_id), data=event,
                            verify=self.ssl)

    def delete_event(self, event_id):
        """
            Delete an event

            :param event_id: Event id to delete
        """
        session = self.__prepare_session()
        return session.delete(self.rest.format(event_id))

    # ######## REST Search #########

    def __prepare_rest_search(self, values, not_values):
        """
            Prepare a search, generate the chain processed by the server

            :param values: Values to search
            :param not_values: Values that should not be in the response
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

            :param values: values to search for
            :param not_values: values *not* to search for
            :param type_attribute: Type of attribute
            :param category: Category to search
            :param org: Org reporting the event
            :param tags: Tags to search for
            :param not_tags: Tags *not* to search for

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
                                         category, org, tag))

    def get_attachement(self, event_id):
        """
            Get attachement of an event (not sample)

            :param event_id: Event id from where the attachements will
                             be fetched
        """
        attach = self.url + '/attributes/downloadAttachment/download/{}'
        session = self.__prepare_session()
        return session.get(attach.format(event_id))

    # ############## Export ###############

    def download_all(self):
        """
            Download all event from the instance
        """
        xml = self.url + '/xml/download'
        session = self.__prepare_session('xml')
        return session.get(xml)

    def download(self, event_id, with_attachement=False):
        """
            Download one event in XML

            :param event_id: Event id of the event to download (same as get)
        """
        template = self.url + '/events/xml/download/{}/{}'
        if with_attachement:
            attach = 'true'
        else:
            attach = 'false'
        session = self.__prepare_session('xml')
        return session.get(template.format(event_id, attach))

    ##########################################
