#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Python API using the REST interface of MISP """

import json
import datetime
import requests
import os
import base64
from urlparse import urljoin
import StringIO
import zipfile
import warnings
import functools


class PyMISPError(Exception):
    def __init__(self, message):
        super(PyMISPError, self).__init__(message)
        self.message = message


class NewEventError(PyMISPError):
    pass


class NewAttributeError(PyMISPError):
    pass


def deprecated(func):
    '''This is a decorator which can be used to mark functions
    as deprecated. It will result in a warning being emitted
    when the function is used.'''

    @functools.wraps(func)
    def new_func(*args, **kwargs):
        warnings.warn_explicit(
            "Call to deprecated function {}.".format(func.__name__),
            category=DeprecationWarning,
            filename=func.func_code.co_filename,
            lineno=func.func_code.co_firstlineno + 1
        )
        return func(*args, **kwargs)
    return new_func


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
        self.root_url = url
        self.key = key
        self.ssl = ssl
        self.out_type = out_type

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
        url = urljoin(self.root_url, 'events/{}'.format(path.lstrip('/')))
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
        url = urljoin(self.root_url, 'events')
        return session.get(url)

    def get_event(self, event_id):
        """
            Get an event

            :param event_id: Event id to get
        """
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'events/{}'.format(event_id))
        return session.get(url)

    def add_event(self, event):
        """
            Add a new event

            :param event: Event as JSON object / string or XML to add
        """
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'events')
        if self.out_type == 'json':
            if isinstance(event, basestring):
                return session.post(url, data=event)
            else:
                return session.post(url, data=json.dumps(event))
        else:
            return session.post(url, data=event)

    def update_event(self, event_id, event):
        """
            Update an event

            :param event_id: Event id to update
            :param event: Event as JSON object / string or XML to add
        """
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'events/{}'.format(event_id))
        if self.out_type == 'json':
            if isinstance(event, basestring):
                return session.post(url, data=event)
            else:
                return session.post(url, data=json.dumps(event))
        else:
            return session.post(url, data=event)

    def delete_event(self, event_id):
        """
            Delete an event

            :param event_id: Event id to delete
        """
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'events/{}'.format(event_id))
        return session.delete(url)

    def delete_attribute(self, attribute_id):
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'attributes/{}'.format(attribute_id))
        return session.delete(url)

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
        to_post = {'request': {}}
        if not isinstance(event_id, int):
            # New event
            to_post['request'].update(self._create_event(distribution, threat_level_id,
                                                         analysis, info))
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

    # ############ Samples ############

    def _encode_file_to_upload(self, path):
        with open(path, 'rb') as f:
            return base64.b64encode(f.read())

    def upload_sample(self, filename, filepath, event_id, distribution, to_ids,
                      category, info, analysis, threat_level_id):
        to_post = self.prepare_attribute(event_id, distribution, to_ids, category,
                                         info, analysis, threat_level_id)
        to_post['request']['files'] = [{'filename': filename, 'data': self._encode_file_to_upload(filepath)}]
        return self._upload_sample(to_post)

    def upload_samplelist(self, filepaths, event_id, distribution, to_ids, category,
                          info, analysis, threat_level_id):
        to_post = self.prepare_attribute(event_id, distribution, to_ids, category,
                                         info, analysis, threat_level_id)
        files = []
        for path in filepaths:
            if not os.path.isfile(path):
                continue
            files.append({'filename': os.path.basename(path), 'data': self._encode_file_to_upload(path)})
        to_post['request']['files'] = files
        return self._upload_sample(to_post)

    def _upload_sample(self, to_post):
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'events/upload_sample')
        return session.post(url, data=json.dumps(to_post))

    # ######## REST Search #########

    def search_all(self, value):
        query = {'value': value, 'searchall': 1}
        session = self.__prepare_session()
        return self.__query(session, 'restSearch/download', query)

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
        attach = urljoin(self.root_url, 'attributes/downloadAttachment/download/{}'.format(event_id))
        session = self.__prepare_session()
        return session.get(attach)

    def get_yara(self, event_id):
        to_post = {'request': {'eventid': event_id, 'type': 'yara'}}
        session = self.__prepare_session()
        response = session.post(urljoin(self.root_url, 'attributes/restSearch'), data=json.dumps(to_post))
        result = response.json()
        if response.status_code != 200:
            return False, result.get('message')
        if not result.get('response') and result.get('message'):
            return False, result.get('message')
        rules = '\n\n'.join([a['value'] for a in result['response']['Attribute']])
        return True, rules

    def download_samples(self, sample_hash=None, event_id=None, all_samples=False):
        to_post = {'request': {'hash': sample_hash, 'eventID': event_id, 'allSamples': all_samples}}
        session = self.__prepare_session()
        response = session.post(urljoin(self.root_url, 'attributes/downloadSample'), data=json.dumps(to_post))
        result = response.json()
        if response.status_code != 200:
            return False, result.get('message')
        if not result.get('result') and result.get('message'):
            return False, result.get('message')
        details = []
        for f in result['result']:
            zipped = StringIO.StringIO(base64.b64decode(f['base64']))
            archive = zipfile.ZipFile(zipped)
            try:
                # New format
                unzipped = StringIO.StringIO(archive.open(f['md5'], pwd='infected').read())
            except KeyError:
                # Old format
                unzipped = StringIO.StringIO(archive.open(f['filename'], pwd='infected').read())
            details.append([f['event_id'], f['filename'], unzipped])
        return True, details

    def download_last(self, last):
        """
            Download the last updated events.

            :param last: can be defined in days, hours, minutes (for example 5d or 12h or 30m)
        """
        return self.search(last=last)

    # ############## Suricata ###############

    def download_all_suricata(self):
        """
            Download all suricata rules events.
        """
        suricata_rules = urljoin(self.root_url, 'events/nids/suricata/download')
        session = self.__prepare_session('rules')
        return session.get(suricata_rules)

    def download_suricata_rule_event(self, event_id):
        """
            Download one suricata rule event.

            :param event_id: ID of the event to download (same as get)
        """
        template = urljoin(self.root_url, 'events/nids/suricata/download/{}'.format(event_id))
        session = self.__prepare_session('rules')
        return session.get(template)

    # ############## Deprecated (Pure XML API should not be used) ##################

    @deprecated
    def download_all(self):
        """
            Download all event from the instance
        """
        xml = urljoin(self.root_url, 'events/xml/download')
        session = self.__prepare_session('xml')
        return session.get(xml)

    @deprecated
    def download(self, event_id, with_attachement=False):
        """
            Download one event in XML

            :param event_id: Event id of the event to download (same as get)
        """
        if with_attachement:
            attach = 'true'
        else:
            attach = 'false'
        template = urljoin(self.root_url, 'events/xml/download/{}/{}'.format(event_id, attach))
        session = self.__prepare_session('xml')
        return session.get(template)

    ##########################################
