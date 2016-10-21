#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Python API using the REST interface of MISP"""

import json
import datetime
import os
import base64
import re
import warnings

try:
    warnings.warn("You're using python 2, it is strongly recommended to use python >=3.3")
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin
from io import BytesIO
import zipfile

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from . import __version__
from .exceptions import PyMISPError, SearchError, MissingDependency, NoURL, NoKey
from .mispevent import MISPEvent, MISPAttribute, EncodeUpdate


# Least dirty way to support python 2 and 3
try:
    warnings.warn("You're using python 2, it is strongly recommended to use python >=3.3")
    basestring
except NameError:
    basestring = str


class distributions(object):
    """Enumeration of the available distributions."""
    your_organization = 0
    this_community = 1
    connected_communities = 2
    all_communities = 3


class threat_level(object):
    """Enumeration of the available threat levels."""
    high = 1
    medium = 2
    low = 3
    undefined = 4


class analysis(object):
    """Enumeration of the available analysis statuses."""
    initial = 0
    ongoing = 1
    completed = 2


class PyMISP(object):
    """
        Python API for MISP

        :param url: URL of the MISP instance you want to connect to
        :param key: API key of the user you want to use
        :param ssl: can be True or False (to check ot not the validity
                    of the certificate. Or a CA_BUNDLE in case of self
                    signed certiifcate (the concatenation of all the
                    *.crt of the chain)
        :param out_type: Type of object (json) NOTE: XML output isn't supported anymore, keeping the flag for compatibility reasons.
        :param debug: print all the messages received from the server
        :param proxies: Proxy dict as describes here: http://docs.python-requests.org/en/master/user/advanced/#proxies
        :param cert: Client certificate, as described there: http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification
    """

    # So it can may be accessed from the misp object.
    distributions = distributions
    threat_level = threat_level
    analysis = analysis

    def __init__(self, url, key, ssl=True, out_type='json', debug=False, proxies=None, cert=None):
        if not url:
            raise NoURL('Please provide the URL of your MISP instance.')
        if not key:
            raise NoKey('Please provide your authorization key.')

        self.root_url = url
        self.key = key
        self.ssl = ssl
        self.proxies = proxies
        self.cert = cert
        self.ressources_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'data')
        if out_type != 'json':
            raise PyMISPError('The only output type supported by PyMISP is JSON. If you still rely on XML, use PyMISP v2.4.49')
        self.debug = debug

        try:
            # Make sure the MISP instance is working and the URL is valid
            self.get_version()
        except Exception as e:
            raise PyMISPError('Unable to connect to MISP ({}). Please make sure the API key and the URL are correct (http/https is required): {}'.format(self.root_url, e))

        try:
            session = self.__prepare_session()
            response = session.get(urljoin(self.root_url, 'attributes/describeTypes.json'))
            describe_types = self._check_response(response)
            if describe_types.get('error'):
                for e in describe_types.get('error'):
                    raise PyMISPError('Failed: {}'.format(e))
            self.describe_types = describe_types['result']
            if not self.describe_types.get('sane_defaults'):
                raise PyMISPError('The MISP server your are trying to reach is outdated (<2.4.52). Please use PyMISP v2.4.51.1 (pip install -I PyMISP==v2.4.51.1) and/or contact your administrator.')
        except:
            describe_types = json.load(open(os.path.join(self.ressources_path, 'describeTypes.json'), 'r'))
            self.describe_types = describe_types['result']

        self.categories = self.describe_types['categories']
        self.types = self.describe_types['types']
        self.category_type_mapping = self.describe_types['category_type_mappings']
        self.sane_default = self.describe_types['sane_defaults']

    def __prepare_session(self, output='json'):
        """
            Prepare the headers of the session
        """
        if not HAVE_REQUESTS:
            raise MissingDependency('Missing dependency, install requests (`pip install requests`)')
        session = requests.Session()
        session.verify = self.ssl
        session.proxies = self.proxies
        session.cert = self.cert
        session.headers.update(
            {'Authorization': self.key,
             'Accept': 'application/{}'.format(output),
             'content-type': 'application/{}'.format(output),
             'User-Agent': 'PyMISP {}'.format(__version__)})
        return session

    def flatten_error_messages(self, response):
        messages = []
        if response.get('error'):
            if isinstance(response['error'], list):
                for e in response['errors']:
                    messages.append(e['error']['value'][0])
            else:
                messages.append(['error'])
        elif response.get('errors'):
            if isinstance(response['errors'], dict):
                for where, errors in response['errors'].items():
                    if isinstance(errors, dict):
                        for where, msg in errors.items():
                            if isinstance(msg, list):
                                for m in msg:
                                    messages.append('Error in {}: {}'.format(where, m))
                            else:
                                messages.append('Error in {}: {}'.format(where, msg))
                    else:
                        for e in errors:
                            if not e:
                                continue
                            if isinstance(e, str):
                                messages.append(e)
                                continue
                            for type_e, msgs in e.items():
                                for m in msgs:
                                    messages.append('Error in {}: {}'.format(where, m))
        return messages

    def _check_response(self, response):
        if response.status_code >= 500:
            response.raise_for_status()
        try:
            to_return = response.json()
        except:
            if self.debug:
                print(response.text)
            raise PyMISPError('Unknown error: {}'.format(response.text))

        errors = []
        if isinstance(to_return, list):
            to_return = {'response': to_return}
        if to_return.get('error'):
            if not isinstance(to_return['error'], list):
                errors.append(to_return['error'])
            else:
                errors += to_return['error']

        if 400 <= response.status_code < 500:
            if to_return.get('error') is None and to_return.get('message'):
                errors.append(to_return['message'])
            else:
                errors.append(basestring(response.status_code))
        errors += self.flatten_error_messages(to_return)
        if errors:
            to_return['errors'] = errors
        if self.debug:
            print(json.dumps(to_return, indent=4))
        return to_return

    # ################################################
    # ############### Simple REST API ################
    # ################################################

    def get_index(self, filters=None):
        """
            Return the index.

            Warning, there's a limit on the number of results
        """
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'events/index')
        if filters is not None:
            filters = json.dumps(filters)
            response = session.post(url, data=filters)
        else:
            response = session.get(url)
        return self._check_response(response)

    def get_event(self, event_id):
        """
            Get an event

            :param event_id: Event id to get
        """
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'events/{}'.format(event_id))
        response = session.get(url)
        return self._check_response(response)

    def get_stix_event(self, event_id=None, with_attachments=False, from_date=False, to_date=False, tags=False):
        """
            Get an event/events in STIX format
        """
        if tags:
            if isinstance(tags, list):
                tags = "&&".join(tags)

        session = self.__prepare_session()
        url = urljoin(self.root_url, "/events/stix/download/{}/{}/{}/{}/{}".format(
            event_id, with_attachments, tags, from_date, to_date))
        if self.debug:
            print("Getting STIX event from {}".format(url))
        response = session.get(url)
        return self._check_response(response)

    def add_event(self, event):
        """
            Add a new event

            :param event: Event as JSON object / string or XML to add
        """
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'events')
        if isinstance(event, basestring):
            response = session.post(url, data=event)
        else:
            response = session.post(url, data=json.dumps(event))
        return self._check_response(response)

    def update_event(self, event_id, event):
        """
            Update an event

            :param event_id: Event id to update
            :param event: Event as JSON object / string or XML to add
        """
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'events/{}'.format(event_id))
        if isinstance(event, basestring):
            response = session.post(url, data=event)
        else:
            response = session.post(url, data=json.dumps(event))
        return self._check_response(response)

    def delete_event(self, event_id):
        """
            Delete an event

            :param event_id: Event id to delete
        """
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'events/{}'.format(event_id))
        response = session.delete(url)
        return self._check_response(response)

    def delete_attribute(self, attribute_id):
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'attributes/{}'.format(attribute_id))
        response = session.delete(url)
        return self._check_response(response)

    # ##############################################
    # ######### Event handling (Json only) #########
    # ##############################################

    def _prepare_full_event(self, distribution, threat_level_id, analysis, info, date=None, published=False):
        misp_event = MISPEvent(self.describe_types)
        misp_event.set_all_values(info=info, distribution=distribution, threat_level_id=threat_level_id,
                                  analysis=analysis, date=date)
        if published:
            misp_event.publish()
        return misp_event

    def _prepare_full_attribute(self, category, type_value, value, to_ids, comment=None, distribution=5):
        misp_attribute = MISPAttribute(self.describe_types)
        misp_attribute.set_all_values(type=type_value, value=value, category=category,
                                      to_ids=to_ids, comment=comment, distribution=distribution)
        return misp_attribute

    def _one_or_more(self, value):
        """Returns a list/tuple of one or more items, regardless of input."""
        return value if isinstance(value, (tuple, list)) else (value,)

    # ########## Helpers ##########

    def get(self, eid):
        return self.get_event(eid)

    def get_stix(self, **kwargs):
        return self.get_stix_event(**kwargs)

    def update(self, event):
        eid = event['Event']['id']
        return self.update_event(eid, event)

    def publish(self, event):
        if event['Event']['published']:
            return {'error': 'Already published'}
        e = MISPEvent(self.describe_types)
        e.load(event)
        e.publish()
        return self.update_event(event['Event']['id'], json.dumps(e, cls=EncodeUpdate))

    def change_threat_level(self, event, threat_level_id):
        e = MISPEvent(self.describe_types)
        e.load(event)
        e.threat_level_id = threat_level_id
        return self.update_event(event['Event']['id'], json.dumps(e, cls=EncodeUpdate))

    def new_event(self, distribution=None, threat_level_id=None, analysis=None, info=None, date=None, published=False):
        misp_event = self._prepare_full_event(distribution, threat_level_id, analysis, info, date, published)
        return self.add_event(json.dumps(misp_event, cls=EncodeUpdate))

    def add_tag(self, event, tag):
        session = self.__prepare_session()
        to_post = {'request': {'Event': {'id': event['Event']['id'], 'tag': tag}}}
        response = session.post(urljoin(self.root_url, 'events/addTag'), data=json.dumps(to_post))
        return self._check_response(response)

    def remove_tag(self, event, tag):
        session = self.__prepare_session()
        to_post = {'request': {'Event': {'id': event['Event']['id'], 'tag': tag}}}
        response = session.post(urljoin(self.root_url, 'events/removeTag'), data=json.dumps(to_post))
        return self._check_response(response)

    # ##### File attributes #####

    def _send_attributes(self, event, attributes, proposal=False):
        if proposal:
            response = self.proposal_add(event['Event']['id'], attributes)
        else:
            e = MISPEvent(self.describe_types)
            e.load(event)
            e.attributes += attributes
            response = self.update_event(event['Event']['id'], json.dumps(e, cls=EncodeUpdate))
        return response

    def add_named_attribute(self, event, type_value, value, category=None, to_ids=False, comment=None, distribution=None, proposal=False):
        attributes = []
        for value in self._one_or_more(value):
            attributes.append(self._prepare_full_attribute(category, type_value, value, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_hashes(self, event, category='Artifacts dropped', filename=None, md5=None, sha1=None, sha256=None, ssdeep=None, comment=None, to_ids=True, distribution=None, proposal=False):

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
        if ssdeep:
            attributes.append(self._prepare_full_attribute(category, type_value.format('ssdeep'), value.format(ssdeep),
                                                           to_ids, comment, distribution))

        return self._send_attributes(event, attributes, proposal)

    def av_detection_link(self, event, link, category='Antivirus detection', to_ids=False, comment=None, distribution=None, proposal=False):
        attributes = []
        for link in self._one_or_more(link):
            attributes.append(self._prepare_full_attribute(category, 'link', link, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_detection_name(self, event, name, category='Antivirus detection', to_ids=False, comment=None, distribution=None, proposal=False):
        attributes = []
        for name in self._one_or_more(name):
            attributes.append(self._prepare_full_attribute(category, 'text', name, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_filename(self, event, filename, category='Artifacts dropped', to_ids=False, comment=None, distribution=None, proposal=False):
        attributes = []
        for filename in self._one_or_more(filename):
            attributes.append(self._prepare_full_attribute(category, 'filename', filename, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_regkey(self, event, regkey, rvalue=None, category='Artifacts dropped', to_ids=True, comment=None, distribution=None, proposal=False):
        if rvalue:
            type_value = 'regkey|value'
            value = '{}|{}'.format(regkey, rvalue)
        else:
            type_value = 'regkey'
            value = regkey

        attributes = []
        attributes.append(self._prepare_full_attribute(category, type_value, value, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_regkeys(self, event, regkeys_values, category='Artifacts dropped', to_ids=True, comment=None, distribution=None, proposal=False):
        attributes = []

        for regkey, rvalue in regkeys_values.items():
            if rvalue:
                type_value = 'regkey|value'
                value = '{}|{}'.format(regkey, rvalue)
            else:
                type_value = 'regkey'
                value = regkey

            attributes.append(self._prepare_full_attribute(category, type_value, value, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_pattern(self, event, pattern, in_file=True, in_memory=False, category='Artifacts dropped', to_ids=True, comment=None, distribution=None, proposal=False):
        attributes = []
        for pattern in self._one_or_more(pattern):
            if in_file:
                attributes.append(self._prepare_full_attribute(category, 'pattern-in-file', pattern, to_ids, comment, distribution))
            if in_memory:
                attributes.append(self._prepare_full_attribute(category, 'pattern-in-memory', pattern, to_ids, comment, distribution))

        return self._send_attributes(event, attributes, proposal)

    def add_pipe(self, event, named_pipe, category='Artifacts dropped', to_ids=True, comment=None, distribution=None, proposal=False):
        attributes = []
        for named_pipe in self._one_or_more(named_pipe):
            if not named_pipe.startswith('\\.\\pipe\\'):
                named_pipe = '\\.\\pipe\\{}'.format(named_pipe)
            attributes.append(self._prepare_full_attribute(category, 'named pipe', named_pipe, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_mutex(self, event, mutex, category='Artifacts dropped', to_ids=True, comment=None, distribution=None, proposal=False):
        attributes = []
        if not mutex.startswith('\\BaseNamedObjects\\'):
            mutex = '\\BaseNamedObjects\\{}'.format(mutex)
        attributes.append(self._prepare_full_attribute(category, 'mutex', mutex, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_yara(self, event, yara, category='Payload delivery', to_ids=False, comment=None, distribution=None, proposal=False):
        attributes = []
        for yara in self._one_or_more(yara):
            attributes.append(self._prepare_full_attribute(category, 'yara', yara, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    # ##### Network attributes #####

    def add_ipdst(self, event, ipdst, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False):
        attributes = []
        for ipdst in self._one_or_more(ipdst):
            attributes.append(self._prepare_full_attribute(category, 'ip-dst', ipdst, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_ipsrc(self, event, ipsrc, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False):
        attributes = []
        for ipsrc in self._one_or_more(ipsrc):
            attributes.append(self._prepare_full_attribute(category, 'ip-src', ipsrc, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_hostname(self, event, hostname, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False):
        attributes = []
        for hostname in self._one_or_more(hostname):
            attributes.append(self._prepare_full_attribute(category, 'hostname', hostname, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_domain(self, event, domain, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False):
        attributes = []
        for domain in self._one_or_more(domain):
            attributes.append(self._prepare_full_attribute(category, 'domain', domain, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_domain_ip(self, event, domain, ip, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False):
        attributes = []
        attributes.append(self._prepare_full_attribute(category, 'domain|ip', "%s|%s" % (domain, ip), to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_domains_ips(self, event, domain_ips, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False):
        attributes = []
        for domain, ip in domain_ips.items():
            attributes.append(self._prepare_full_attribute(category, 'domain|ip', "%s|%s" % (domain, ip), to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_url(self, event, url, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False):
        attributes = []
        for url in self._one_or_more(url):
            attributes.append(self._prepare_full_attribute(category, 'url', url, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_useragent(self, event, useragent, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False):
        attributes = []
        for useragent in self._one_or_more(useragent):
            attributes.append(self._prepare_full_attribute(category, 'user-agent', useragent, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_traffic_pattern(self, event, pattern, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False):
        attributes = []
        for pattern in self._one_or_more(pattern):
            attributes.append(self._prepare_full_attribute(category, 'pattern-in-traffic', pattern, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_snort(self, event, snort, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False):
        attributes = []
        for snort in self._one_or_more(snort):
            attributes.append(self._prepare_full_attribute(category, 'snort', snort, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_net_other(self, event, netother, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False):
        attributes = []
        attributes.append(self._prepare_full_attribute(category, 'other', netother, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    # ##### Email attributes #####

    def add_email_src(self, event, email, to_ids=True, comment=None, distribution=None, proposal=False):
        attributes = []
        for email in self._one_or_more(email):
            attributes.append(self._prepare_full_attribute('Payload delivery', 'email-src', email, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_email_dst(self, event, email, category='Payload delivery', to_ids=True, comment=None, distribution=None, proposal=False):
        attributes = []
        for email in self._one_or_more(email):
            attributes.append(self._prepare_full_attribute(category, 'email-dst', email, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_email_subject(self, event, email, to_ids=True, comment=None, distribution=None, proposal=False):
        attributes = []
        for email in self._one_or_more(email):
            attributes.append(self._prepare_full_attribute('Payload delivery', 'email-subject', email, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_email_attachment(self, event, email, to_ids=True, comment=None, distribution=None, proposal=False):
        attributes = []
        for email in self._one_or_more(email):
            attributes.append(self._prepare_full_attribute('Payload delivery', 'email-attachment', email, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    # ##### Target attributes #####

    def add_target_email(self, event, target, to_ids=True, comment=None, distribution=None, proposal=False):
        attributes = []
        for target in self._one_or_more(target):
            attributes.append(self._prepare_full_attribute('Targeting data', 'target-email', target, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_target_user(self, event, target, to_ids=True, comment=None, distribution=None, proposal=False):
        attributes = []
        for target in self._one_or_more(target):
            attributes.append(self._prepare_full_attribute('Targeting data', 'target-user', target, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_target_machine(self, event, target, to_ids=True, comment=None, distribution=None, proposal=False):
        attributes = []
        for target in self._one_or_more(target):
            attributes.append(self._prepare_full_attribute('Targeting data', 'target-machine', target, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_target_org(self, event, target, to_ids=True, comment=None, distribution=None, proposal=False):
        attributes = []
        for target in self._one_or_more(target):
            attributes.append(self._prepare_full_attribute('Targeting data', 'target-org', target, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_target_location(self, event, target, to_ids=True, comment=None, distribution=None, proposal=False):
        attributes = []
        for target in self._one_or_more(target):
            attributes.append(self._prepare_full_attribute('Targeting data', 'target-location', target, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_target_external(self, event, target, to_ids=True, comment=None, distribution=None, proposal=False):
        attributes = []
        for target in self._one_or_more(target):
            attributes.append(self._prepare_full_attribute('Targeting data', 'target-external', target, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    # ##### Attribution attributes #####

    def add_threat_actor(self, event, target, to_ids=True, comment=None, distribution=None, proposal=False):
        attributes = []
        for target in self._one_or_more(target):
            attributes.append(self._prepare_full_attribute('Attribution', 'threat-actor', target, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    # ##### Internal reference attributes #####

    def add_internal_link(self, event, reference, to_ids=False, comment=None, distribution=None, proposal=False):
        attributes = []
        for reference in self._one_or_more(reference):
            attributes.append(self._prepare_full_attribute('Internal reference', 'link', reference, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_internal_comment(self, event, reference, to_ids=False, comment=None, distribution=None, proposal=False):
        attributes = []
        for reference in self._one_or_more(reference):
            attributes.append(self._prepare_full_attribute('Internal reference', 'comment', reference, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_internal_text(self, event, reference, to_ids=False, comment=None, distribution=None, proposal=False):
        attributes = []
        for reference in self._one_or_more(reference):
            attributes.append(self._prepare_full_attribute('Internal reference', 'text', reference, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_internal_other(self, event, reference, to_ids=False, comment=None, distribution=None, proposal=False):
        attributes = []
        for reference in self._one_or_more(reference):
            attributes.append(self._prepare_full_attribute('Internal reference', 'other', reference, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    # ##################################################
    # ######### Upload samples through the API #########
    # ##################################################

    def _prepare_upload(self, event_id, distribution, to_ids, category, comment, info,
                        analysis, threat_level_id):
        to_post = {'request': {}}

        if event_id is not None:
            try:
                event_id = int(event_id)
            except:
                pass
        if not isinstance(event_id, int):
            # New event
            misp_event = self._prepare_full_event(distribution, threat_level_id, analysis, info)
            to_post['request']['distribution'] = misp_event.distribution
            to_post['request']['info'] = misp_event.info
            to_post['request']['analysis'] = misp_event.analysis
            to_post['request']['threat_level_id'] = misp_event.threat_level_id
        else:
            to_post['request']['event_id'] = int(event_id)

        default_values = self.sane_default['malware-sample']
        if to_ids is None or not isinstance(to_ids, bool):
            to_ids = bool(int(default_values['to_ids']))
        to_post['request']['to_ids'] = to_ids

        if category is None or category not in self.categories:
            category = default_values['default_category']
        to_post['request']['category'] = category

        to_post['request']['comment'] = comment
        return to_post

    def _encode_file_to_upload(self, path):
        with open(path, 'rb') as f:
            return str(base64.b64encode(f.read()))

    def upload_sample(self, filename, filepath, event_id, distribution=None,
                      to_ids=True, category=None, comment=None, info=None,
                      analysis=None, threat_level_id=None):
        to_post = self._prepare_upload(event_id, distribution, to_ids, category,
                                       comment, info, analysis, threat_level_id)
        to_post['request']['files'] = [{'filename': filename, 'data': self._encode_file_to_upload(filepath)}]
        return self._upload_sample(to_post)

    def upload_samplelist(self, filepaths, event_id, distribution=None,
                          to_ids=True, category=None, comment=None, info=None,
                          analysis=None, threat_level_id=None):
        to_post = self._prepare_upload(event_id, distribution, to_ids, category,
                                       comment, info, analysis, threat_level_id)
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
        response = session.post(url, data=json.dumps(to_post))
        return self._check_response(response)

    # ############################
    # ######## Proposals #########
    # ############################

    def __query_proposal(self, session, path, id, attribute=None):
        url = urljoin(self.root_url, 'shadow_attributes/{}/{}'.format(path, id))
        if path in ['add', 'edit']:
            query = {'request': {'ShadowAttribute': attribute}}
            response = session.post(url, data=json.dumps(query))
        elif path == 'view':
            response = session.get(url)
        else:  # accept or discard
            response = session.post(url)
        return self._check_response(response)

    def proposal_view(self, event_id=None, proposal_id=None):
        session = self.__prepare_session()
        if proposal_id is not None and event_id is not None:
            return {'error': 'You can only view an event ID or a proposal ID'}
        if event_id is not None:
            id = event_id
        else:
            id = proposal_id
        return self.__query_proposal(session, 'view', id)

    def proposal_add(self, event_id, attribute):
        session = self.__prepare_session()
        return self.__query_proposal(session, 'add', event_id, attribute)

    def proposal_edit(self, attribute_id, attribute):
        session = self.__prepare_session()
        return self.__query_proposal(session, 'edit', attribute_id, attribute)

    def proposal_accept(self, proposal_id):
        session = self.__prepare_session()
        return self.__query_proposal(session, 'accept', proposal_id)

    def proposal_discard(self, proposal_id):
        session = self.__prepare_session()
        return self.__query_proposal(session, 'discard', proposal_id)

    # ##############################
    # ######## REST Search #########
    # ##############################

    def __query(self, session, path, query, controller='events'):
        if query.get('error') is not None:
            return query
        if controller not in ['events', 'attributes']:
            raise Exception('Invalid controller. Can only be {}'.format(', '.join(['events', 'attributes'])))
        url = urljoin(self.root_url, '{}/{}'.format(controller, path.lstrip('/')))
        query = {'request': query}
        response = session.post(url, data=json.dumps(query))
        return self._check_response(response)

    def search_index(self, published=None, eventid=None, tag=None, datefrom=None,
                     dateto=None, eventinfo=None, threatlevel=None, distribution=None,
                     analysis=None, attribute=None, org=None):
        """
            Search only at the index level. Use ! infront of value as NOT, default OR

            :param published: Published (0,1)
            :param eventid: Evend ID(s) | str or list
            :param tag: Tag(s) | str or list
            :param datefrom: First date, in format YYYY-MM-DD
            :param datefrom: Last date, in format YYYY-MM-DD
            :param eventinfo: Event info(s) to match | str or list
            :param threatlevel: Threat level(s) (1,2,3,4) | str or list
            :param distribution: Distribution level(s) (0,1,2,3) | str or list
            :param analysis: Analysis level(s) (0,1,2) | str or list
            :param org: Organisation(s) | str or list

        """
        allowed = {'published': published, 'eventid': eventid, 'tag': tag, 'Dateto': dateto,
                   'Datefrom': datefrom, 'eventinfo': eventinfo, 'threatlevel': threatlevel,
                   'distribution': distribution, 'analysis': analysis, 'attribute': attribute,
                   'org': org}
        rule_levels = {'distribution': ["0", "1", "2", "3", "!0", "!1", "!2", "!3"],
                       'threatlevel': ["1", "2", "3", "4", "!1", "!2", "!3", "!4"],
                       'analysis': ["0", "1", "2", "!0", "!1", "!2"]}
        buildup_url = "events/index"

        for rule in allowed.keys():
            if allowed[rule] is not None:
                if not isinstance(allowed[rule], list):
                    allowed[rule] = [allowed[rule]]
                allowed[rule] = [x for x in map(str, allowed[rule])]
                if rule in rule_levels:
                    if not set(allowed[rule]).issubset(rule_levels[rule]):
                        raise SearchError('Values in your {} are invalid, has to be in {}'.format(rule, ', '.join(str(x) for x in rule_levels[rule])))
                if type(allowed[rule]) == list:
                    joined = '|'.join(str(x) for x in allowed[rule])
                    buildup_url += '/search{}:{}'.format(rule, joined)
                else:
                    buildup_url += '/search{}:{}'.format(rule, allowed[rule])
        session = self.__prepare_session()
        url = urljoin(self.root_url, buildup_url)
        response = session.get(url)
        return self._check_response(response)

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
               date_to=None, last=None, metadata=None, controller='events'):
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
            :param metadata: return onlymetadata if True

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
        if metadata is not None:
            query['metadata'] = metadata

        session = self.__prepare_session()
        return self.__query(session, 'restSearch/download', query, controller)

    def get_attachement(self, event_id):
        """
            Get attachement of an event (not sample)

            :param event_id: Event id from where the attachements will
                             be fetched
        """
        attach = urljoin(self.root_url, 'attributes/downloadAttachment/download/{}'.format(event_id))
        session = self.__prepare_session()
        response = session.get(attach)
        return self._check_response(response)

    def get_yara(self, event_id):
        to_post = {'request': {'eventid': event_id, 'type': 'yara'}}
        session = self.__prepare_session()
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
        session = self.__prepare_session()
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
                    unzipped = BytesIO(archive.open(f['md5'], pwd=b'infected').read())
                except KeyError:
                    # Old format
                    unzipped = BytesIO(archive.open(f['filename'], pwd=b'infected').read())
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
        response = session.get(suricata_rules)
        return response

    def download_suricata_rule_event(self, event_id):
        """
            Download one suricata rule event.

            :param event_id: ID of the event to download (same as get)
        """
        template = urljoin(self.root_url, 'events/nids/suricata/download/{}'.format(event_id))
        session = self.__prepare_session('rules')
        response = session.get(template)
        return response

    # ########## Tags ##########

    def get_all_tags(self, quiet=False):
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'tags')
        response = session.get(url)
        r = self._check_response(response)
        if not quiet or r.get('errors'):
            return r
        else:
            to_return = []
            for tag in r['Tag']:
                to_return.append(tag['name'])
            return to_return

    def new_tag(self, name=None, colour="#00ace6", exportable=False):
        to_post = {'Tag': {'name': name, 'colour': colour, 'exportable': exportable}}
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'tags/add')
        response = session.post(url, data=json.dumps(to_post))
        return self._check_response(response)

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
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'servers/getVersion.json')
        response = session.get(url)
        return self._check_response(response)

    def get_version_master(self):
        """
            Get the most recent version from github
        """
        r = requests.get('https://raw.githubusercontent.com/MISP/MISP/2.4/VERSION.json')
        if r.status_code == 200:
            master_version = json.loads(r.text)
            return {'version': '{}.{}.{}'.format(master_version['major'], master_version['minor'], master_version['hotfix'])}
        else:
            return {'error': 'Impossible to retrieve the version of the master branch.'}

    # ############## Export Attributes in text ####################################

    def get_all_attributes_txt(self, type_attr):

        session = self.__prepare_session('txt')
        url = urljoin(self.root_url, 'attributes/text/download/%s' % type_attr)
        response = session.get(url)
        return response

    # ############## Statistics ##################

    def get_attributes_statistics(self, context='type', percentage=None):
        """
            Get attributes statistics from the MISP instance
        """
        session = self.__prepare_session()
        if (context != 'category'):
            context = 'type'
        if percentage is not None:
            url = urljoin(self.root_url, 'attributes/attributeStatistics/{}/{}'.format(context, percentage))
        else:
            url = urljoin(self.root_url, 'attributes/attributeStatistics/{}'.format(context))
        response = session.get(url)
        return self._check_response(response)

    def get_tags_statistics(self, percentage=None, name_sort=None):
        """
        Get tags statistics from the MISP instance
        """
        session = self.__prepare_session()
        if percentage is not None:
            percentage = 'true'
        else:
            percentage = 'false'
        if name_sort is not None:
            name_sort = 'true'
        else:
            name_sort = 'false'
        url = urljoin(self.root_url, 'tags/tagStatistics/{}/{}'.format(percentage, name_sort))
        response = session.get(url)
        return self._check_response(response)

    # ############## Sightings ##################

    def sighting_per_id(self, attribute_id):
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'sightings/add/{}'.format(attribute_id))
        response = session.post(url)
        return self._check_response(response)

    def sighting_per_uuid(self, attribute_uuid):
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'sightings/add/{}'.format(attribute_uuid))
        response = session.post(url)
        return self._check_response(response)

    def sighting_per_json(self, json_file):
        session = self.__prepare_session()
        jdata = json.load(open(json_file))
        url = urljoin(self.root_url, 'sightings/add/')
        response = session.post(url, data=json.dumps(jdata))
        return self._check_response(response)

    # ############## Sharing Groups ##################

    def get_sharing_groups(self):
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'sharing_groups/index.json')
        response = session.get(url)
        return self._check_response(response)['response'][0]
