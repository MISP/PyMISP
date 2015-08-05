#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Python API using the REST interface of MISP """

import json
import datetime
import requests
import os
import base64


class PyMISPError(Exception):
    def __init__(self, message):
        super(PyMISPError, self).__init__(message)
        self.message = message


class NewEventError(PyMISPError):
    pass


class NewAttributeError(PyMISPError):
    pass


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
             'content-type': 'application/' + out})
        return session

    def __query(self, session, path, query):
        if query.get('error') is not None:
            return query
        url = self.rest.format(path)
        query = {'request': query}
        r = session.post(url, data=json.dumps(query))
        return r.json()

    # ############### REST API ################

    def get_index(self):
        """
            Return the index.

            Warning, there's a limit on the number of results
        """
        session = self.__prepare_session()
        return session.get(self.url)

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

            :param event: Event as JSON object / string or XML to add
        """
        session = self.__prepare_session()
        if self.out_type == 'json':
            if isinstance(event, basestring):
                return session.post(self.url, data=event)
            else:
                return session.post(self.url, data=json.dumps(event))
        else:
            return session.post(self.url, data=event)

    def update_event(self, event_id, event):
        """
            Update an event

            :param event_id: Event id to update
            :param event: Event as JSON object / string or XML to add
        """
        session = self.__prepare_session()
        if self.out_type == 'json':
            if isinstance(event, basestring):
                return session.post(self.rest.format(event_id), data=event)
            else:
                return session.post(self.rest.format(event_id), data=json.dumps(event))
        else:
            return session.post(self.rest.format(event_id), data=event)

    def delete_event(self, event_id):
        """
            Delete an event

            :param event_id: Event id to delete
        """
        session = self.__prepare_session()
        return session.delete(self.rest.format(event_id))

    # ######### Create/update events through the API #########

    def _create_event(self, distribution, threat_level_id, analysis, info):
        # Setup details of a new event
        if distribution not in [0, 1, 2, 3]:
            raise NewEventError('{} is invalid, the distribution has to be in 0, 1, 2, 3'.format(distribution))
        if threat_level_id not in [0, 1, 2, 3]:
            raise NewEventError('{} is invalid, the threat_level_id has to be in 0, 1, 2, 3'.format(threat_level_id))
        if analysis not in [0, 1, 2]:
            raise NewEventError('{} is invalid, the analysis has to be in 0, 1, 2'.format(analysis))
        return {'distribution': int(distribution), 'info': info,
                'threat_level_id': int(threat_level_id), 'analysis': analysis}

    def prepare_attribute(self, event_id, distribution, to_ids, category, info,
                          analysis, threat_level_id):
        to_post = {'request': {'files': []}}
        if not isinstance(event_id, int):
            # New event
            postcontent = self._create_event(distribution, threat_level_id,
                                             analysis, info)
            to_post['request'].update(postcontent)
        else:
            to_post['request'].update({'event_id': int(event_id)})

        if to_ids not in [True, False]:
            raise NewAttributeError('{} is invalid, to_ids has to be True or False'.format(analysis))
        to_post['request'].update({'to_ids': to_ids})

        if category not in ['Payload delivery', 'Artifacts dropped',
                            'Payload Installation', 'External Analysis']:
            raise NewAttributeError('{} is invalid, category has to be in {}'.format(analysis, (', '.join(['Payload delivery', 'Artifacts dropped', 'Payload Installation', 'External Analysis']))))
        to_post['request'].update({'category': category})

        return to_post

    def prepare_sample(self, filename, filepath):
        with open(filepath, 'rb') as f:
            return {'files': [{'filename': filename, 'data': base64.b64encode(f.read())}]}

    def prepare_samplelist(self, filepaths):
        files = []
        for path in filepaths:
            if not os.path.isfile(path):
                continue
            files.append({'filename': os.path.basename(path), 'data': path})
        return {'files': files}

    def upload_sample(self, filename, filepath, event_id, distribution, to_ids,
                      category, info, analysis, threat_level_id):
        to_post = self.prepare_attribute(event_id, distribution, to_ids, category,
                                         info, analysis, threat_level_id)
        to_post['request'].update(self.prepare_sample(filename, filepath))

        return self._upload_sample(to_post)

    def upload_samplelist(self, filepaths, event_id, distribution, to_ids, category,
                          info, analysis, threat_level_id):
        to_post = self.prepare_attribute(event_id, distribution, to_ids, category,
                                         info, analysis, threat_level_id)
        to_post['request'].update(self.prepare_samplelist(filepaths))

        return self._upload_sample(to_post)

    def _upload_sample(self, to_post):
        session = self.__prepare_session()
        return session.post(self.rest.format('upload_sample'), data=json.dumps(to_post))

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
               category=None, org=None, tags=None, not_tags=None, date_from=None,
               date_to=None, last=None):
        """
            Search via the Rest API

            :param values: values to search for
            :param not_values: values *not* to search for
            :param type_attribute: Type of attribute
            :param category: Category to search
            :param org: Org reporting the event
            :param tags: Tags to search for
            :param not_tags: Tags *not* to search for
            :param date_from: First date
            :param date_to: Last date
            :param last: Last updated events (for example 5d or 12h or 30m)

        """
        val = self.__prepare_rest_search(values, not_values).replace('/', '|')
        tag = self.__prepare_rest_search(tags, not_tags).replace(':', ';')
        query = {}
        if len(val) != 0:
            query['value'] = val
        if len(tag) != 0:
            query['tags'] = tag
        if type_attribute is not None:
            query['type'] = type_attribute
        if category is not None:
            query['category'] = category
        if org is not None:
            query['org'] = org
        if date_from is not None:
            if isinstance(date_from, datetime.date) or isinstance(date_to, datetime.datetime):
                query['from'] = date_from.strftime('%Y-%m-%d')
            else:
                query['from'] = date_from
        if date_to is not None:
            if isinstance(date_to, datetime.date) or isinstance(date_to, datetime.datetime):
                query['to'] = date_to.strftime('%Y-%m-%d')
            else:
                query['to'] = date_to
        if last is not None:
            query['last'] = last

        session = self.__prepare_session()
        return self.__query(session, 'restSearch/download', query)

    def get_attachement(self, event_id):
        """
            Get attachement of an event (not sample)

            :param event_id: Event id from where the attachements will
                             be fetched
        """
        attach = self.url + '/attributes/downloadAttachment/download/{}'
        session = self.__prepare_session()
        return session.get(attach.format(event_id))

    def download_last(self, last):
        """
            Download the last updated events.

            :param last: can be defined in days, hours, minutes (for example 5d or 12h or 30m)
        """
        return self.search(last=last)

    # ############## Export ###############

    def download_all(self):
        """
            Download all event from the instance
        """
        xml = self.url + '/xml/download'
        session = self.__prepare_session('xml')
        return session.get(xml)

    def download_all_suricata(self):
        """
            Download all suricata rules events.
        """
        suricata_rules = self.url + '/nids/suricata/download'
        session = self.__prepare_session('rules')
        return session.get(suricata_rules)

    def download_suricata_rule_event(self, event_id):
        """
            Download one suricata rule event.

            :param event_id: ID of the event to download (same as get)
        """
        template = self.url + '/nids/suricata/download/{}'
        session = self.__prepare_session('rules')
        return session.get(template.format(event_id))

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
