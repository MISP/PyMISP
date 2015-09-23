#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Python API using the REST interface of MISP """

import json
import datetime
import os
import base64
import re

try:
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin
from io import BytesIO
import zipfile
import warnings
import functools

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from . import __version__

# Least dirty way to support python 2 and 3
try:
    basestring
except NameError:
    basestring = str


class PyMISPError(Exception):
    def __init__(self, message):
        super(PyMISPError, self).__init__(message)
        self.message = message


class NewEventError(PyMISPError):
    pass


class NewAttributeError(PyMISPError):
    pass


class MissingDependency(PyMISPError):
    pass


class NoURL(PyMISPError):
    pass


class NoKey(PyMISPError):
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
            filename=func.__code__.co_filename,
            lineno=func.__code__.co_firstlineno + 1
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
        if not url:
            raise NoURL('Please provide the URL of your MISP instance.')
        if not key:
            raise NoKey('Please provide your authorization key.')

        self.root_url = url
        self.key = key
        self.ssl = ssl
        self.out_type = out_type

        self.categories = ['Internal reference', 'Targeting data', 'Antivirus detection',
                           'Payload delivery', 'Payload installation', 'Artifacts dropped',
                           'Persistence mechanism', 'Network activity', 'Payload type',
                           'Attribution', 'External analysis', 'Other']
        self.types = ['md5', 'sha1', 'sha256', 'filename', 'filename|md5', 'filename|sha1',
                      'filename|sha256', 'ip-src', 'ip-dst', 'hostname', 'domain', 'url',
                      'user-agent', 'http-method', 'regkey', 'regkey|value', 'AS', 'snort',
                      'pattern-in-file', 'pattern-in-traffic', 'pattern-in-memory', 'named pipe', 'mutex',
                      'vulnerability', 'attachment', 'malware-sample', 'link', 'comment', 'text', 'other']

        try:
            # Make sure the MISP instance is working and the URL is valid
            self.get_version()
        except Exception as e:
            raise PyMISPError('Unable to connect to MISP ({}). Please make sure the API key and the URL are correct (http/https is required): {}'.format(self.root_url, e))

    def __prepare_session(self, force_out=None):
        """
            Prepare the headers of the session

            :param force_out: force the type of the expect output
                              (overwrite the constructor)

        """
        if not HAVE_REQUESTS:
            raise MissingDependency('Missing dependency, install requests (`pip install requests`)')
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

    def _check_response(self, response):
        if response.status_code >= 500:
            response.raise_for_status()
        to_return = response.json()
        if 400 <= response.status_code < 500:
            if to_return.get('error') is None:
                to_return['error'] = to_return.get('message')
        return to_return

    # ################################################
    # ############### Simple REST API ################
    # ################################################

    def get_index(self, force_out=None):
        """
            Return the index.

            Warning, there's a limit on the number of results
        """
        session = self.__prepare_session(force_out)
        url = urljoin(self.root_url, 'events')
        return session.get(url)

    def get_event(self, event_id, force_out=None):
        """
            Get an event

            :param event_id: Event id to get
        """
        session = self.__prepare_session(force_out)
        url = urljoin(self.root_url, 'events/{}'.format(event_id))
        return session.get(url)

    def add_event(self, event, force_out=None):
        """
            Add a new event

            :param event: Event as JSON object / string or XML to add
        """
        session = self.__prepare_session(force_out)
        url = urljoin(self.root_url, 'events')
        if self.out_type == 'json':
            if isinstance(event, basestring):
                return session.post(url, data=event)
            else:
                return session.post(url, data=json.dumps(event))
        else:
            return session.post(url, data=event)

    def update_event(self, event_id, event, force_out=None):
        """
            Update an event

            :param event_id: Event id to update
            :param event: Event as JSON object / string or XML to add
        """
        session = self.__prepare_session(force_out)
        url = urljoin(self.root_url, 'events/{}'.format(event_id))
        if self.out_type == 'json':
            if isinstance(event, basestring):
                return session.post(url, data=event)
            else:
                return session.post(url, data=json.dumps(event))
        else:
            return session.post(url, data=event)

    def delete_event(self, event_id, force_out=None):
        """
            Delete an event

            :param event_id: Event id to delete
        """
        session = self.__prepare_session(force_out)
        url = urljoin(self.root_url, 'events/{}'.format(event_id))
        return session.delete(url)

    def delete_attribute(self, attribute_id, force_out=None):
        session = self.__prepare_session(force_out)
        url = urljoin(self.root_url, 'attributes/{}'.format(attribute_id))
        return session.delete(url)

    # ##############################################
    # ######### Event handling (Json only) #########
    # ##############################################

    def _prepare_full_event(self, distribution, threat_level_id, analysis, info, date=None, published=False):
        to_return = {'Event': {}}
        # Setup details of a new event
        if distribution not in [0, 1, 2, 3]:
            raise NewEventError('{} is invalid, the distribution has to be in 0, 1, 2, 3'.format(distribution))
        if threat_level_id not in [1, 2, 3, 4]:
            raise NewEventError('{} is invalid, the threat_level_id has to be in 1, 2, 3, 4'.format(threat_level_id))
        if analysis not in [0, 1, 2]:
            raise NewEventError('{} is invalid, the analysis has to be in 0, 1, 2'.format(analysis))
        if date is None:
            date = datetime.date.today().isoformat()
        if published not in [True, False]:
            raise NewEventError('{} is invalid, published has to be True or False'.format(published))
        to_return['Event'] = {'distribution': distribution, 'info': info, 'date': date, 'published': published,
                              'threat_level_id': threat_level_id, 'analysis': analysis}
        return to_return

    def _prepare_full_attribute(self, category, type_value, value, to_ids, comment=None, distribution=None):
        to_return = {}
        if category not in self.categories:
            raise NewAttributeError('{} is invalid, category has to be in {}'.format(category, (', '.join(self.categories))))
        to_return['category'] = category

        if type_value not in self.types:
            raise NewAttributeError('{} is invalid, type_value has to be in {}'.format(type_value, (', '.join(self.types))))
        to_return['type'] = type_value

        if to_ids not in [True, False]:
            raise NewAttributeError('{} is invalid, to_ids has to be True or False'.format(to_ids))
        to_return['to_ids'] = to_ids

        if distribution is not None:
            distribution = int(distribution)
        # If None: take the default value of the event
        if distribution not in [None, 0, 1, 2, 3]:
            raise NewAttributeError('{} is invalid, the distribution has to be in 0, 1, 2, 3 or None'.format(distribution))
        if distribution is not None:
            to_return['distribution'] = distribution

        to_return['value'] = value

        if comment is not None:
            to_return['comment'] = comment

        return to_return

    def _prepare_update(self, event):
        # Cleanup the received event to make it publishable
        event['Event'].pop('locked', None)
        event['Event'].pop('attribute_count', None)
        event['Event'].pop('RelatedEvent', None)
        event['Event'].pop('orgc', None)
        event['Event'].pop('ShadowAttribute', None)
        event['Event'].pop('org', None)
        event['Event'].pop('proposal_email_lock', None)
        event['Event'].pop('publish_timestamp', None)
        event['Event'].pop('published', None)
        event['Event'].pop('timestamp', None)
        event['Event']['id'] = int(event['Event']['id'])
        return event

    # ########## Helpers ##########

    def get(self, eid):
        response = self.get_event(int(eid), 'json')
        return self._check_response(response)

    def update(self, event):
        eid = event['Event']['id']
        response = self.update_event(eid, event, 'json')
        return self._check_response(response)

    def new_event(self, distribution=None, threat_level_id=None, analysis=None, info=None, date=None, published=False):
        data = self._prepare_full_event(distribution, threat_level_id, analysis, info, date, published)
        response = self.add_event(data, 'json')
        return self._check_response(response)

    def publish(self, event):
        if event['Event']['published']:
            return {'error': 'Already published'}
        event = self._prepare_update(event)
        event['Event']['published'] = True
        response = self.update_event(event['Event']['id'], event, 'json')
        return self._check_response(response)

    # ##### File attributes #####

    def _send_attributes(self, event, attributes):
        event = self._prepare_update(event)
        for a in attributes:
            if a.get('distribution') is None:
                a['distribution'] = event['Event']['distribution']
        event['Event']['Attribute'] = attributes
        response = self.update_event(event['Event']['id'], event, 'json')
        return self._check_response(response)

    def add_hashes(self, event, category='Artifacts dropped', filename=None, md5=None, sha1=None, sha256=None, comment=None, to_ids=True, distribution=None):
        categories = ['Payload delivery', 'Artifacts dropped', 'Payload installation', 'External analysis']
        if category not in categories:
            raise NewAttributeError('{} is invalid, category has to be in {}'.format(category, (', '.join(categories))))

        attributes = []
        type_value = '{}'
        value = '{}'
        if filename:
            type_value = 'filename|{}'
            value = filename + '|{}'
        if md5:
            attributes.append(self._prepare_full_attribute(category, type_value.format('md5'), value.format(md5),
                                                           to_ids, comment, distribution))
        if sha1:
            attributes.append(self._prepare_full_attribute(category, type_value.format('sha1'), value.format(sha1),
                                                           to_ids, comment, distribution))
        if sha256:
            attributes.append(self._prepare_full_attribute(category, type_value.format('sha256'), value.format(sha256),
                                                           to_ids, comment, distribution))

        return self._send_attributes(event, attributes)

    def add_regkey(self, event, regkey, rvalue=None, category='Artifacts dropped', to_ids=True, comment=None, distribution=None):
        type_value = '{}'
        value = '{}'
        if rvalue:
            type_value = 'regkey|value'
            value = '{}|{}'.format(regkey, rvalue)
        else:
            type_value = 'regkey'
            value = regkey

        attributes = []
        attributes.append(self._prepare_full_attribute(category, type_value, value, to_ids, comment, distribution))
        return self._send_attributes(event, attributes)

    def add_pattern(self, event, pattern, in_file=True, in_memory=False, category='Artifacts dropped', to_ids=True, comment=None, distribution=None):
        attributes = []
        if in_file:
            attributes.append(self._prepare_full_attribute(category, 'pattern-in-file', pattern, to_ids, comment, distribution))
        if in_memory:
            attributes.append(self._prepare_full_attribute(category, 'pattern-in-memory', pattern, to_ids, comment, distribution))

        return self._send_attributes(event, attributes)

    def add_pipe(self, event, named_pipe, category='Artifacts dropped', to_ids=True, comment=None, distribution=None):
        attributes = []
        if not named_pipe.startswith('\\.\\pipe\\'):
            named_pipe = '\\.\\pipe\\{}'.format(named_pipe)
        attributes.append(self._prepare_full_attribute(category, 'named pipe', named_pipe, to_ids, comment, distribution))
        return self._send_attributes(event, attributes)

    def add_mutex(self, event, mutex, category='Artifacts dropped', to_ids=True, comment=None, distribution=None):
        attributes = []
        if not mutex.startswith('\\BaseNamedObjects\\'):
            mutex = '\\BaseNamedObjects\\{}'.format(mutex)
        attributes.append(self._prepare_full_attribute(category, 'mutex', mutex, to_ids, comment, distribution))
        return self._send_attributes(event, attributes)

    # ##### Network attributes #####

    def add_ipdst(self, event, ipdst, category='Network activity', to_ids=True, comment=None, distribution=None):
        attributes = []
        attributes.append(self._prepare_full_attribute(category, 'ip-dst', ipdst, to_ids, comment, distribution))
        return self._send_attributes(event, attributes)

    def add_hostname(self, event, hostname, category='Network activity', to_ids=True, comment=None, distribution=None):
        attributes = []
        attributes.append(self._prepare_full_attribute(category, 'hostname', hostname, to_ids, comment, distribution))
        return self._send_attributes(event, attributes)

    def add_domain(self, event, domain, category='Network activity', to_ids=True, comment=None, distribution=None):
        attributes = []
        attributes.append(self._prepare_full_attribute(category, 'domain', domain, to_ids, comment, distribution))
        return self._send_attributes(event, attributes)

    def add_url(self, event, url, category='Network activity', to_ids=True, comment=None, distribution=None):
        attributes = []
        attributes.append(self._prepare_full_attribute(category, 'url', url, to_ids, comment, distribution))
        return self._send_attributes(event, attributes)

    def add_useragent(self, event, useragent, category='Network activity', to_ids=True, comment=None, distribution=None):
        attributes = []
        attributes.append(self._prepare_full_attribute(category, 'user-agent', useragent, to_ids, comment, distribution))
        return self._send_attributes(event, attributes)

    def add_traffic_pattern(self, event, pattern, category='Network activity', to_ids=True, comment=None, distribution=None):
        attributes = []
        attributes.append(self._prepare_full_attribute(category, 'pattern-in-traffic', pattern, to_ids, comment, distribution))
        return self._send_attributes(event, attributes)

    def add_snort(self, event, snort, category='Network activity', to_ids=True, comment=None, distribution=None):
        attributes = []
        attributes.append(self._prepare_full_attribute(category, 'snort', snort, to_ids, comment, distribution))
        return self._send_attributes(event, attributes)

    # ##################################################
    # ######### Upload samples through the API #########
    # ##################################################

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
        authorized_categs = ['Payload delivery', 'Artifacts dropped', 'Payload Installation', 'External Analysis']

        if event_id is not None:
            try:
                event_id = int(event_id)
            except:
                pass
        if not isinstance(event_id, int):
            # New event
            to_post['request'] = self._create_event(distribution, threat_level_id, analysis, info)
        else:
            to_post['request']['event_id'] = int(event_id)

        if to_ids not in [True, False]:
            raise NewAttributeError('{} is invalid, to_ids has to be True or False'.format(to_ids))
        to_post['request']['to_ids'] = to_ids

        if category not in authorized_categs:
            raise NewAttributeError('{} is invalid, category has to be in {}'.format(category, (', '.join(authorized_categs))))
        to_post['request']['category'] = category

        return to_post

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
        session = self.__prepare_session('json')
        url = urljoin(self.root_url, 'events/upload_sample')
        response = session.post(url, data=json.dumps(to_post))
        return self._check_response(response)

    # ##############################
    # ######## REST Search #########
    # ##############################

    def __query(self, session, path, query):
        if query.get('error') is not None:
            return query
        url = urljoin(self.root_url, 'events/{}'.format(path.lstrip('/')))
        query = {'request': query}
        response = session.post(url, data=json.dumps(query))
        return self._check_response(response)

    def search_all(self, value):
        query = {'value': value, 'searchall': 1}
        session = self.__prepare_session('json')
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

        session = self.__prepare_session('json')
        return self.__query(session, 'restSearch/download', query)

    def get_attachement(self, event_id):
        """
            Get attachement of an event (not sample)

            :param event_id: Event id from where the attachements will
                             be fetched
        """
        attach = urljoin(self.root_url, 'attributes/downloadAttachment/download/{}'.format(event_id))
        session = self.__prepare_session('json')
        return session.get(attach)

    def get_yara(self, event_id):
        to_post = {'request': {'eventid': event_id, 'type': 'yara'}}
        session = self.__prepare_session('json')
        response = session.post(urljoin(self.root_url, 'attributes/restSearch'), data=json.dumps(to_post))
        result = self._check_response(response)
        if result.get('error') is not None:
            return False, result.get('error')
        if not result.get('response'):
            return False, result.get('message')
        rules = '\n\n'.join([a['value'] for a in result['response']['Attribute']])
        return True, rules

    def download_samples(self, sample_hash=None, event_id=None, all_samples=False):
        to_post = {'request': {'hash': sample_hash, 'eventID': event_id, 'allSamples': all_samples}}
        session = self.__prepare_session('json')
        response = session.post(urljoin(self.root_url, 'attributes/downloadSample'), data=json.dumps(to_post))
        result = self._check_response(response)
        if result.get('error') is not None:
            return False, result.get('error')
        if not result.get('result'):
            return False, result.get('message')
        details = []
        for f in result['result']:
            decoded = base64.b64decode(f['base64'])
            zipped = BytesIO(decoded)
            try:
                archive = zipfile.ZipFile(zipped)
                try:
                    # New format
                    unzipped = BytesIO(archive.open(f['md5'], pwd='infected').read())
                except KeyError:
                    # Old format
                    unzipped = BytesIO(archive.open(f['filename'], pwd='infected').read())
                details.append([f['event_id'], f['filename'], unzipped])
            except zipfile.BadZipfile:
                # In case the sample isn't zipped
                details.append([f['event_id'], f['filename'], zipped])

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

    # ########## Version ##########

    def get_api_version(self):
        """
            Returns the current version of PyMISP installed on the system
        """
        return {'version': __version__}

    def get_api_version_master(self):
        """
            Get the most recent version of PyMISP from github
        """
        r = requests.get('https://raw.githubusercontent.com/MISP/PyMISP/master/pymisp/__init__.py')
        if r.status_code == 200:
            version = re.findall("__version__ = '(.*)'", r.text)
            return {'version': version[0]}
        else:
            return {'error': 'Impossible to retrieve the version of the master branch.'}

    def get_version(self):
        """
            Returns the version of the instance.
        """
        session = self.__prepare_session('json')
        url = urljoin(self.root_url, 'servers/getVersion')
        response = session.get(url)
        return self._check_response(response)

    def get_version_master(self):
        """
            Get the most recent version from github
        """
        r = requests.get('https://raw.githubusercontent.com/MISP/MISP/master/VERSION.json')
        if r.status_code == 200:
            master_version = json.loads(r.text)
            return {'version': '{}.{}.{}'.format(master_version['major'], master_version['minor'], master_version['hotfix'])}
        else:
            return {'error': 'Impossible to retrieve the version of the master branch.'}

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
