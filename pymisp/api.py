#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Python API using the REST interface of MISP"""

import sys
import json
import datetime
import os
import base64
import re
import warnings
import functools


try:
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin
    warnings.warn("You're using python 2, it is strongly recommended to use python >=3.4")
from io import BytesIO, open
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
    basestring
    unicode
    warnings.warn("You're using python 2, it is strongly recommended to use python >=3.4")
except NameError:
    basestring = str
    unicode = str


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
    """Python API for MISP

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
            pymisp_version = __version__.split('.')
            response = self.get_recommended_api_version()
            if not response.get('version'):
                warnings.warn("Unable to check the recommended PyMISP version (MISP <2.4.60), please upgrade.")
            else:
                recommended_pymisp_version = response['version'].split('.')
                for a, b in zip(pymisp_version, recommended_pymisp_version):
                    if a == b:
                        continue
                    elif a > b:
                        warnings.warn("The version of PyMISP recommended by the MISP instance ({}) is older than the one you're using now ({}). Please upgrade the MISP instance or use an older PyMISP version.".format(response['version'], __version__))
                    else:  # a < b
                        warnings.warn("The version of PyMISP recommended by the MISP instance ({}) is newer than the one you're using now ({}). Please upgrade PyMISP.".format(response['version'], __version__))

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
            with open(os.path.join(self.ressources_path, 'describeTypes.json'), 'r') as f:
                describe_types = json.load(f)
            self.describe_types = describe_types['result']

        self.categories = self.describe_types['categories']
        self.types = self.describe_types['types']
        self.category_type_mapping = self.describe_types['category_type_mappings']
        self.sane_default = self.describe_types['sane_defaults']

    def __prepare_session(self, output='json'):
        """Prepare the headers of the session"""

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
             'User-Agent': 'PyMISP {} - Python {}.{}.{}'.format(__version__, *sys.version_info)})
        return session

    # #####################
    # ### Core helpers ####
    # #####################

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
                            if isinstance(e, basestring):
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
        if to_return.get('errors'):
            if not isinstance(to_return['errors'], list):
                errors.append(to_return['errors'])
            else:
                errors += to_return['errors']

        if 400 <= response.status_code < 500:
            if not errors and to_return.get('message'):
                errors.append(to_return['message'])
            else:
                errors.append(basestring(response.status_code))
        errors += self.flatten_error_messages(to_return)
        if errors:
            to_return['errors'] = errors
        if self.debug:
            print(json.dumps(to_return, indent=4))
        return to_return

    def _one_or_more(self, value):
        """Returns a list/tuple of one or more items, regardless of input."""
        return value if isinstance(value, (tuple, list)) else (value,)

    def _make_mispevent(self, event):
        if not isinstance(event, MISPEvent):
            e = MISPEvent(self.describe_types)
            e.load(event)
        else:
            e = event
        return e

    def _prepare_full_event(self, distribution, threat_level_id, analysis, info, date=None, published=False, orgc_id=None, org_id=None, sharing_group_id=None):
        misp_event = MISPEvent(self.describe_types)
        misp_event.set_all_values(info=info, distribution=distribution, threat_level_id=threat_level_id,
                                  analysis=analysis, date=date, orgc_id=orgc_id, org_id=org_id, sharing_group_id=sharing_group_id)
        if published:
            misp_event.publish()
        return misp_event

    def _prepare_full_attribute(self, category, type_value, value, to_ids, comment=None, distribution=5, **kwargs):
        misp_attribute = MISPAttribute(self.describe_types)
        misp_attribute.set_all_values(type=type_value, value=value, category=category,
                                      to_ids=to_ids, comment=comment, distribution=distribution, **kwargs)
        return misp_attribute

    def _valid_uuid(self, uuid):
        """Test if uuid is valid
        Will test against CakeText's RFC 4122, i.e
        "the third group must start with a 4,
        and the fourth group must start with 8, 9, a or b."

        :param uuid: an uuid
        """
        regex = re.compile('^[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z', re.I)
        match = regex.match(uuid)
        return bool(match)

    # ################################################
    # ############### Simple REST API ################
    # ################################################

    def get_index(self, filters=None):
        """Return the index.

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
        """Get an event

        :param event_id: Event id to get
        """
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'events/{}'.format(event_id))
        response = session.get(url)
        return self._check_response(response)

    def add_event(self, event):
        """Add a new event

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
        """Update an event

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
        """Delete an event

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
    # ############### Event handling ###############
    # ##############################################

    def get(self, eid):
        return self.get_event(eid)

    def update(self, event):
        e = self._make_mispevent(event)
        if e.uuid:
            eid = e.uuid
        else:
            eid = e.id
        return self.update_event(eid, json.dumps(e, cls=EncodeUpdate))

    def publish(self, event):
        e = self._make_mispevent(event)
        if e.published:
            return {'error': 'Already published'}
        e.publish()
        return self.update(e)

    def change_threat_level(self, event, threat_level_id):
        e = self._make_mispevent(event)
        e.threat_level_id = threat_level_id
        return self.update(e)

    def change_sharing_group(self, event, sharing_group_id):
        e = self._make_mispevent(event)
        e.distribution = 4      # Needs to be 'Sharing group'
        e.sharing_group_id = sharing_group_id
        return self.update(e)

    def new_event(self, distribution=None, threat_level_id=None, analysis=None, info=None, date=None, published=False, orgc_id=None, org_id=None, sharing_group_id=None):
        misp_event = self._prepare_full_event(distribution, threat_level_id, analysis, info, date, published, orgc_id, org_id, sharing_group_id)
        return self.add_event(json.dumps(misp_event, cls=EncodeUpdate))

    def tag(self, uuid, tag):
        if not self._valid_uuid(uuid):
            raise PyMISPError('Invalid UUID')
        session = self.__prepare_session()
        to_post = {'uuid':uuid, 'tag':tag}
        path = 'tags/attachTagToObject'
        response = session.post(urljoin(self.root_url, path), data=json.dumps(to_post))
        return self._check_response(response)

    def untag(self, uuid, tag):
        if not self._valid_uuid(uuid):
            raise PyMISPError('Invalid UUID')
        session = self.__prepare_session()
        to_post = {'uuid':uuid, 'tag':tag}
        path = 'tags/removeTagFromObject'
        response = session.post(urljoin(self.root_url, path), data=json.dumps(to_post))
        return self._check_response(response)

    # ##### File attributes #####

    def _send_attributes(self, event, attributes, proposal=False):
        # FIXME: unable to send a proposal if we have a full event.
        if isinstance(event, MISPEvent):
            event.attributes += attributes
            response = self.update(event)
        elif isinstance(event, int) or (isinstance(event, str) and (event.isdigit() or self._valid_uuid(event))):
            # No full event, just an ID
            session = self.__prepare_session()
            url = urljoin(self.root_url, 'attributes/add/{}'.format(event))
            for a in attributes:
                if proposal:
                    response = self.proposal_add(event, json.dumps(a, cls=EncodeUpdate))
                else:
                    response = session.post(url, data=json.dumps(a, cls=EncodeUpdate))
        else:
            e = MISPEvent(self.describe_types)
            e.load(event)
            e.attributes += attributes
            response = self.update(e)
        return response

    def add_named_attribute(self, event, type_value, value, category=None, to_ids=False, comment=None, distribution=None, proposal=False, **kwargs):
        attributes = []
        for value in self._one_or_more(value):
            attributes.append(self._prepare_full_attribute(category, type_value, value, to_ids, comment, distribution, **kwargs))
        return self._send_attributes(event, attributes, proposal)

    def add_hashes(self, event, category='Artifacts dropped', filename=None, md5=None, sha1=None, sha256=None, ssdeep=None, comment=None, to_ids=True, distribution=None, proposal=False):

        attributes = []
        type_value = '{}'
        value = ''
        if filename:
            type_value = 'filename|{}'
            value = filename + '|'
        if md5:
            attributes.append(self._prepare_full_attribute(category, type_value.format('md5'), value + md5, to_ids, comment, distribution))
        if sha1:
            attributes.append(self._prepare_full_attribute(category, type_value.format('sha1'), value + sha1, to_ids, comment, distribution))
        if sha256:
            attributes.append(self._prepare_full_attribute(category, type_value.format('sha256'), value + sha256, to_ids, comment, distribution))
        if ssdeep:
            attributes.append(self._prepare_full_attribute(category, type_value.format('ssdeep'), value + ssdeep, to_ids, comment, distribution))

        return self._send_attributes(event, attributes, proposal)

    def av_detection_link(self, event, link, category='Antivirus detection', to_ids=False, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'link', link, category, to_ids, comment, distribution, proposal)

    def add_detection_name(self, event, name, category='Antivirus detection', to_ids=False, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'text', name, category, to_ids, comment, distribution, proposal)

    def add_filename(self, event, filename, category='Artifacts dropped', to_ids=False, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'filename', filename, category, to_ids, comment, distribution, proposal)

    def add_attachment(self, event, attachment, category='Artifacts dropped', to_ids=False, comment=None, distribution=None, proposal=False):
        """Add an attachment to the MISP event

        :param event: The event to add an attachment to
        :param attachment: Either a file handle or a path to a file - will be uploaded
        """
        if isinstance(attachment, basestring) and os.path.isfile(attachment):
            # We have a file to open
            filename = os.path.basename(attachment)
            with open(attachment, "rb") as f:
                fileData = f.read()
        elif hasattr(attachment, "read"):
            # It's a file handle - we can read it but it has no filename
            fileData = attachment.read()
            filename = 'attachment'
        elif isinstance(attachment, (tuple, list)):
            # tuple/list (filename, pseudofile)
            filename = attachment[0]
            if hasattr(attachment[1], "read"):
                # Pseudo file
                fileData = attachment[1].read()
            else:
                fileData = attachment[1]
        else:
            # Plain file content, no filename
            filename = 'attachment'
            fileData = attachment

        if not isinstance(fileData, bytes):
            fileData = fileData.encode()

        # by now we have a string for the file
        # we just need to b64 encode it and send it on its way
        # also, just decode it to utf-8 to avoid the b'string' format
        encodedData = base64.b64encode(fileData).decode("utf-8")

        # Send it on its way
        return self.add_named_attribute(event, 'attachment', filename, category, to_ids, comment, distribution, proposal, data=encodedData)

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
            if rvalue is not None:
                type_value = 'regkey|value'
                value = '{}|{}'.format(regkey, rvalue)
            else:
                type_value = 'regkey'
                value = regkey

            attributes.append(self._prepare_full_attribute(category, type_value, value, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_pattern(self, event, pattern, in_file=True, in_memory=False, category='Artifacts dropped', to_ids=True, comment=None, distribution=None, proposal=False):
        if not (in_file or in_memory):
            raise PyMISPError('Invalid pattern type: please use in_memory=True or in_file=True')
        itemtype = 'pattern-in-file' if in_file else 'pattern-in-memory'
        return self.add_named_attribute(event, itemtype, pattern, category, to_ids, comment, distribution, proposal)

    def add_pipe(self, event, named_pipe, category='Artifacts dropped', to_ids=True, comment=None, distribution=None, proposal=False):
        def scrub(s):
            if not s.startswith('\\.\\pipe\\'):
                s = '\\.\\pipe\\{}'.format(s)
            return s
        attributes = list(map(scrub, self._one_or_more(named_pipe)))
        return self.add_named_attribute(event, 'named pipe', attributes, category, to_ids, comment, distribution, proposal)

    def add_mutex(self, event, mutex, category='Artifacts dropped', to_ids=True, comment=None, distribution=None, proposal=False):
        def scrub(s):
            if not s.startswith('\\BaseNamedObjects\\'):
                s = '\\BaseNamedObjects\\{}'.format(s)
            return s
        attributes = list(map(scrub, self._one_or_more(mutex)))
        return self.add_named_attribute(event, 'mutex', attributes, category, to_ids, comment, distribution, proposal)

    def add_yara(self, event, yara, category='Payload delivery', to_ids=False, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'yara', yara, category, to_ids, comment, distribution, proposal)

    # ##### Network attributes #####

    def add_ipdst(self, event, ipdst, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'ip-dst', ipdst, category, to_ids, comment, distribution, proposal)

    def add_ipsrc(self, event, ipsrc, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'ip-src', ipsrc, category, to_ids, comment, distribution, proposal)

    def add_hostname(self, event, hostname, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'hostname', hostname, category, to_ids, comment, distribution, proposal)

    def add_domain(self, event, domain, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'domain', domain, category, to_ids, comment, distribution, proposal)

    def add_domain_ip(self, event, domain, ip, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False):
        composed = list(map(lambda x: '%s|%s' % (domain, x), ip))
        return self.add_named_attribute(event, 'domain|ip', composed, category, to_ids, comment, distribution, proposal)

    def add_domains_ips(self, event, domain_ips, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False):
        composed = list(map(lambda x: '%s|%s' % (x[0], x[1]), domain_ips.items()))
        return self.add_named_attribute(event, 'domain|ip', composed, category, to_ids, comment, distribution, proposal)

    def add_url(self, event, url, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'url', url, category, to_ids, comment, distribution, proposal)

    def add_useragent(self, event, useragent, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'user-agent', useragent, category, to_ids, comment, distribution, proposal)

    def add_traffic_pattern(self, event, pattern, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'pattern-in-traffic', pattern, category, to_ids, comment, distribution, proposal)

    def add_snort(self, event, snort, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'snort', snort, category, to_ids, comment, distribution, proposal)

    def add_net_other(self, event, netother, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'other', netother, category, to_ids, comment, distribution, proposal)

    # ##### Email attributes #####

    def add_email_src(self, event, email, category='Payload delivery', to_ids=True, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'email-src', email, category, to_ids, comment, distribution, proposal)

    def add_email_dst(self, event, email, category='Payload delivery', to_ids=True, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'email-dst', email, category, to_ids, comment, distribution, proposal)

    def add_email_subject(self, event, email, category='Payload delivery', to_ids=True, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'email-subject', email, category, to_ids, comment, distribution, proposal)

    def add_email_attachment(self, event, email, category='Payload delivery', to_ids=True, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'email-attachment', email, category, to_ids, comment, distribution, proposal)

    # ##### Target attributes #####

    def add_target_email(self, event, target, category='Targeting data', to_ids=True, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'target-email', target, category, to_ids, comment, distribution, proposal)

    def add_target_user(self, event, target, category='Targeting data', to_ids=True, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'target-user', target, category, to_ids, comment, distribution, proposal)

    def add_target_machine(self, event, target, category='Targeting data', to_ids=True, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'target-machine', target, category, to_ids, comment, distribution, proposal)

    def add_target_org(self, event, target, category='Targeting data', to_ids=True, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'target-org', target, category, to_ids, comment, distribution, proposal)

    def add_target_location(self, event, target, category='Targeting data', to_ids=True, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'target-location', target, category, to_ids, comment, distribution, proposal)

    def add_target_external(self, event, target, category='Targeting data', to_ids=True, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'target-external', target, category, to_ids, comment, distribution, proposal)

    # ##### Attribution attributes #####

    def add_threat_actor(self, event, target, category='Attribution', to_ids=True, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'threat-actor', target, category, to_ids, comment, distribution, proposal)

    # ##### Internal reference attributes #####

    def add_internal_link(self, event, reference, category='Internal reference', to_ids=False, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'link', reference, category, to_ids, comment, distribution, proposal)

    def add_internal_comment(self, event, reference, category='Internal reference', to_ids=False, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'comment', reference, category, to_ids, comment, distribution, proposal)

    def add_internal_text(self, event, reference, category='Internal reference', to_ids=False, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'text', reference, category, to_ids, comment, distribution, proposal)

    def add_internal_other(self, event, reference, category='Internal reference', to_ids=False, comment=None, distribution=None, proposal=False):
        return self.add_named_attribute(event, 'other', reference, category, to_ids, comment, distribution, proposal)

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
            return base64.b64encode(f.read()).decode()

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
    # ###### Attribute update ######
    # ##############################

    def change_toids(self, attribute_uuid, to_ids):
        if to_ids not in [0, 1]:
            raise Exception('to_ids can only be 0 or 1')
        query = {"to_ids": to_ids}
        session = self.__prepare_session()
        return self.__query(session, 'edit/{}'.format(attribute_uuid), query, controller='attributes')

    # ##############################
    # ######## REST Search #########
    # ##############################

    def __query(self, session, path, query, controller='events'):
        if query.get('error') is not None:
            return query
        if controller not in ['events', 'attributes']:
            raise Exception('Invalid controller. Can only be {}'.format(', '.join(['events', 'attributes'])))
        url = urljoin(self.root_url, '{}/{}'.format(controller, path.lstrip('/')))
        if self.debug:
            print('URL: ', url)
            print('Query: ', query)
        response = session.post(url, data=json.dumps(query))
        return self._check_response(response)

    def search_index(self, published=None, eventid=None, tag=None, datefrom=None,
                     dateuntil=None, eventinfo=None, threatlevel=None, distribution=None,
                     analysis=None, attribute=None, org=None):
        """Search only at the index level. Use ! infront of value as NOT, default OR

        :param published: Published (0,1)
        :param eventid: Evend ID(s) | str or list
        :param tag: Tag(s) | str or list
        :param datefrom: First date, in format YYYY-MM-DD
        :param dateuntil: Last date, in format YYYY-MM-DD
        :param eventinfo: Event info(s) to match | str or list
        :param threatlevel: Threat level(s) (1,2,3,4) | str or list
        :param distribution: Distribution level(s) (0,1,2,3) | str or list
        :param analysis: Analysis level(s) (0,1,2) | str or list
        :param org: Organisation(s) | str or list
        """
        allowed = {'published': published, 'eventid': eventid, 'tag': tag, 'Dateuntil': dateuntil,
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
        """Prepare a search, generate the chain processed by the server

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

    def search(self, controller='events', **kwargs):
        """Search via the Rest API

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
        :param eventid: Last date
        :param withAttachments: return events with or without the attachments
        :param uuid: search by uuid
        :param publish_timestamp: the publish timestamp
        :param timestamp: the creation timestamp
        :param enforceWarninglist: Enforce the warning lists
        :param searchall: full text search on the database
        :param metadata: return only metadata if True
        :param published: return only published events
        :param to_ids: return only the attributes with the to_ids flag set
        :param deleted: also return the deleted attributes
        """
        # Event:     array('value', 'type', 'category', 'org', 'tags', 'from', 'to', 'last', 'eventid', 'withAttachments', 'uuid', 'publish_timestamp', 'timestamp', 'enforceWarninglist', 'searchall', 'metadata', 'published');
        # Attribute: array('value', 'type', 'category', 'org', 'tags', 'from', 'to', 'last', 'eventid', 'withAttachments', 'uuid', 'publish_timestamp', 'timestamp', 'enforceWarninglist', 'to_ids', 'deleted');
        val = self.__prepare_rest_search(kwargs.get('values'), kwargs.get('not_values'))
        query = {}
        if len(val) != 0:
            query['value'] = val

        if kwargs.get('type_attribute'):
            query['type'] = kwargs.get('type_attribute')

        if kwargs.get('category'):
            query['category'] = kwargs.get('category')

        if kwargs.get('org') is not None:
            query['org'] = kwargs.get('org')

        tag = self.__prepare_rest_search(kwargs.get('tags'), kwargs.get('not_tags'))
        if len(tag) != 0:
            query['tags'] = tag

        if kwargs.get('date_from'):
            if isinstance(kwargs.get('date_from'), datetime.date) or isinstance(kwargs.get('date_from'), datetime.datetime):
                query['from'] = kwargs.get('date_from').strftime('%Y-%m-%d')
            else:
                query['from'] = kwargs.get('date_from')

        if kwargs.get('date_to'):
            if isinstance(kwargs.get('date_to'), datetime.date) or isinstance(kwargs.get('date_to'), datetime.datetime):
                query['to'] = kwargs.get('date_to').strftime('%Y-%m-%d')
            else:
                query['to'] = kwargs.get('date_to')

        if kwargs.get('last'):
            query['last'] = kwargs.get('last')

        if kwargs.get('eventid'):
            query['eventid'] = kwargs.get('eventid')

        if kwargs.get('withAttachments'):
            query['withAttachments'] = kwargs.get('withAttachments')

        if kwargs.get('uuid'):
            if self._valid_uuid(kwargs.get('uuid')):
                query['uuid'] = kwargs.get('uuid')
            else:
                return {'error': 'You must enter a valid uuid.'}

        if kwargs.get('publish_timestamp'):
            query['publish_timestamp'] = kwargs.get('publish_timestamp')

        if kwargs.get('timestamp'):
            query['timestamp'] = kwargs.get('timestamp')

        if kwargs.get('enforceWarninglist'):
            query['enforceWarninglist'] = kwargs.get('enforceWarninglist')

        if kwargs.get('to_ids') is not None:
            query['to_ids'] = kwargs.get('to_ids')

        if kwargs.get('deleted') is not None:
            query['deleted'] = kwargs.get('deleted')

        if controller == 'events':
            # Event search only:
            if kwargs.get('searchall'):
                query['searchall'] = kwargs.get('searchall')

            if kwargs.get('metadata') is not None:
                query['metadata'] = kwargs.get('metadata')

            if kwargs.get('published') is not None:
                query['published'] = kwargs.get('published')

        session = self.__prepare_session()
        return self.__query(session, 'restSearch/download', query, controller)

    def get_attachment(self, event_id):
        """Get attachement of an event (not sample)

        :param event_id: Event id from where the attachements will be fetched
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
                if f.get('md5'):
                    # New format
                    unzipped = BytesIO(archive.open(f['md5'], pwd=b'infected').read())
                else:
                    # Old format
                    unzipped = BytesIO(archive.open(f['filename'], pwd=b'infected').read())
                details.append([f['event_id'], f['filename'], unzipped])
            except zipfile.BadZipfile:
                # In case the sample isn't zipped
                details.append([f['event_id'], f['filename'], zipped])

        return True, details

    def download_last(self, last):
        """Download the last updated events.

        :param last: can be defined in days, hours, minutes (for example 5d or 12h or 30m)
        """
        return self.search(last=last)

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
        """Returns the current version of PyMISP installed on the system"""
        return {'version': __version__}

    def get_api_version_master(self):
        """Get the most recent version of PyMISP from github"""
        r = requests.get('https://raw.githubusercontent.com/MISP/PyMISP/master/pymisp/__init__.py')
        if r.status_code == 200:
            version = re.findall("__version__ = '(.*)'", r.text)
            return {'version': version[0]}
        else:
            return {'error': 'Impossible to retrieve the version of the master branch.'}

    def get_recommended_api_version(self):
        """Returns the recommended API version from the server"""
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'servers/getPyMISPVersion.json')
        response = session.get(url)
        return self._check_response(response)

    def get_version(self):
        """Returns the version of the instance."""
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'servers/getVersion.json')
        response = session.get(url)
        return self._check_response(response)

    def get_version_master(self):
        """Get the most recent version from github"""
        r = requests.get('https://raw.githubusercontent.com/MISP/MISP/2.4/VERSION.json')
        if r.status_code == 200:
            master_version = json.loads(r.text)
            return {'version': '{}.{}.{}'.format(master_version['major'], master_version['minor'], master_version['hotfix'])}
        else:
            return {'error': 'Impossible to retrieve the version of the master branch.'}

    # ############## Statistics ##################

    def get_attributes_statistics(self, context='type', percentage=None):
        """Get attributes statistics from the MISP instance"""
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
        """Get tags statistics from the MISP instance"""
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

    def set_sightings(self, sightings):
        if isinstance(sightings, dict):
            sightings = json.dumps(sightings)
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'sightings/add/')
        response = session.post(url, data=sightings)
        return self._check_response(response)

    def sighting_per_json(self, json_file):
        with open(json_file, 'r') as f:
            jdata = json.load(f)
            return self.set_sightings(jdata)

    # ############## Sharing Groups ##################

    def get_sharing_groups(self):
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'sharing_groups.json')
        response = session.get(url)
        return self._check_response(response)['response']

    # ############## Users ##################

    def _set_user_parameters(self, **kwargs):
        user = {}
        if kwargs.get('email'):
            user['email'] = kwargs.get('email')
        if kwargs.get('org_id'):
            user['org_id'] = kwargs.get('org_id')
        if kwargs.get('role_id'):
            user['role_id'] = kwargs.get('role_id')
        if kwargs.get('password'):
            user['password'] = kwargs.get('password')
        if kwargs.get('external_auth_required'):
            user['external_auth_required'] = kwargs.get('external_auth_required')
        if kwargs.get('external_auth_key'):
            user['external_auth_key'] = kwargs.get('external_auth_key')
        if kwargs.get('enable_password'):
            user['enable_password'] = kwargs.get('enable_password')
        if kwargs.get('nids_sid'):
            user['nids_sid'] = kwargs.get('nids_sid')
        if kwargs.get('server_id'):
            user['server_id'] = kwargs.get('server_id')
        if kwargs.get('gpgkey'):
            user['gpgkey'] = kwargs.get('gpgkey')
        if kwargs.get('certif_public'):
            user['certif_public'] = kwargs.get('certif_public')
        if kwargs.get('autoalert'):
            user['autoalert'] = kwargs.get('autoalert')
        if kwargs.get('contactalert'):
            user['contactalert'] = kwargs.get('contactalert')
        if kwargs.get('disabled'):
            user['disabled'] = kwargs.get('disabled')
        if kwargs.get('change_pw'):
            user['change_pw'] = kwargs.get('change_pw')
        if kwargs.get('termsaccepted'):
            user['termsaccepted'] = kwargs.get('termsaccepted')
        if kwargs.get('newsread'):
            user['newsread'] = kwargs.get('newsread')
        if kwargs.get('authkey'):
            user['authkey'] = kwargs.get('authkey')
        return user

    def get_users_list(self):
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'admin/users')
        response = session.get(url)
        return self._check_response(response)['response']

    def get_user(self, user_id):
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'admin/users/view/{}'.format(user_id))
        response = session.get(url)
        return self._check_response(response)

    def add_user(self, email, org_id, role_id, **kwargs):
        new_user = self._set_user_parameters(**dict(email=email, org_id=org_id, role_id=role_id, **kwargs))
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'admin/users/add/')
        response = session.post(url, data=json.dumps(new_user))
        return self._check_response(response)

    def add_user_json(self, json_file):
        session = self.__prepare_session()
        with open(json_file, 'r') as f:
            jdata = json.load(f)
        url = urljoin(self.root_url, 'admin/users/add/')
        response = session.post(url, data=json.dumps(jdata))
        return self._check_response(response)

    def get_user_fields_list(self):
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'admin/users/add/')
        response = session.get(url)
        return self._check_response(response)

    def edit_user(self, user_id, **kwargs):
        edit_user = self._set_user_parameters(**kwargs)
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'admin/users/edit/{}'.format(user_id))
        response = session.post(url, data=json.dumps(edit_user))
        return self._check_response(response)

    def edit_user_json(self, json_file, user_id):
        session = self.__prepare_session()
        with open(json_file, 'r') as f:
            jdata = json.load(f)
        url = urljoin(self.root_url, 'admin/users/edit/{}'.format(user_id))
        response = session.post(url, data=json.dumps(jdata))
        return self._check_response(response)

    def delete_user(self, user_id):
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'admin/users/delete/{}'.format(user_id))
        response = session.post(url)
        return self._check_response(response)

    # ############## Organisations ##################

    def _set_organisation_parameters(self, **kwargs):
        organisation = {}
        if kwargs.get('name'):
            organisation['name'] = kwargs.get('name')
        if kwargs.get('anonymise'):
            organisation['anonymise'] = kwargs.get('anonymise')
        if kwargs.get('description'):
            organisation['description'] = kwargs.get('description')
        if kwargs.get('type'):
            organisation['type'] = kwargs.get('type')
        if kwargs.get('nationality'):
            organisation['nationality'] = kwargs.get('nationality')
        if kwargs.get('sector'):
            organisation['sector'] = kwargs.get('sector')
        if kwargs.get('uuid'):
            organisation['uuid'] = kwargs.get('uuid')
        if kwargs.get('contacts'):
            organisation['contacts'] = kwargs.get('contacts')
        if kwargs.get('local'):
            organisation['local'] = kwargs.get('local')
        return organisation

    def get_organisations_list(self):
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'organisations')
        response = session.get(url)
        return self._check_response(response)['response']

    def get_organisation(self, organisation_id):
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'organisations/view/{}'.format(organisation_id))
        response = session.get(url)
        return self._check_response(response)

    def add_organisation(self, name, **kwargs):
        new_org = self._set_organisation_parameters(**dict(name=name, **kwargs))
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'admin/organisations/add/')
        response = session.post(url, data=json.dumps(new_org))
        return self._check_response(response)

    def add_organisation_json(self, json_file):
        session = self.__prepare_session()
        with open(json_file, 'r') as f:
            jdata = json.load(f)
        url = urljoin(self.root_url, 'admin/organisations/add/')
        response = session.post(url, data=json.dumps(jdata))
        return self._check_response(response)

    def get_organisation_fields_list(self):
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'admin/organisations/add/')
        response = session.get(url)
        return self._check_response(response)

    def edit_organisation(self, org_id, **kwargs):
        edit_org = self._set_organisation_parameters(**kwargs)
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'admin/organisations/edit/{}'.format(org_id))
        response = session.post(url, data=json.dumps(edit_org))
        return self._check_response(response)

    def edit_organisation_json(self, json_file, org_id):
        session = self.__prepare_session()
        with open(json_file, 'r') as f:
            jdata = json.load(f)
        url = urljoin(self.root_url, 'admin/organisations/edit/{}'.format(org_id))
        response = session.post(url, data=json.dumps(jdata))
        return self._check_response(response)

    def delete_organisation(self, org_id):
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'admin/organisations/delete/{}'.format(org_id))
        response = session.post(url)
        return self._check_response(response)

    # ############## Servers ##################

    def _set_server_organisation(self, server, organisation):
        if organisation is not None and 'type' in organisation:
            organisation_type = organisation['type']
            if organisation_type < 2:
                if 'id' in organisation:
                    server['organisation_type'] = organisation_type
                    server['json'] = json.dump({'id': organisation['id']})
            else:
                if 'name' in organisation and 'uuid' in organisation:
                    server['organisation_type'] = organisation_type
                    server['json'] = json.dumps({'name': organisation['name'], 'uuid': organisation['uuid']})
        return server

    def _set_server_parameters(self, url, name, authkey, organisation, internal,
                               push, pull, self_signed, push_rules, pull_rules,
                               submitted_cert, submitted_client_cert, delete_cert,
                               delete_client_cert):
        server = {}
        self._set_server_organisation(server, organisation)
        if url is not None:
            server['url'] = url
        if name is not None:
            server['name'] = name
        if authkey is not None:
            server['authkey'] = authkey
        if internal is not None:
            server['internal'] = internal
        if push is not None:
            server['push'] = push
        if pull is not None:
            server['pull'] = pull
        if self_signed is not None:
            server['self_signed'] = self_signed
        if push_rules is not None:
            server['push_rules'] = push_rules
        if pull_rules is not None:
            server['pull_rules'] = pull_rules
        if submitted_cert is not None:
            server['submitted_cert'] = submitted_cert
        if submitted_client_cert is not None:
            server['submitted_client_cert'] = submitted_client_cert
        if delete_cert is not None:
            server['delete_cert'] = delete_cert
        if delete_client_cert is not None:
            server['delete_client_cert'] = delete_client_cert
        return server

    def add_server(self, url, name, authkey, organisation, internal=None, push=None,
                   pull=None, self_signed=None, push_rules=None, pull_rules=None,
                   submitted_cert=None, submitted_client_cert=None):
        new_server = self._set_server_parameters(url, name, authkey, organisation, internal,
                                                 push, pull, self_signed, push_rules, pull_rules, submitted_cert,
                                                 submitted_client_cert, None, None)
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'servers/add')
        response = session.post(url, data=json.dumps(new_server))
        return self._check_response(response)

    def add_server_json(self, json_file):
        session = self.__prepare_session()
        with open(json_file, 'r') as f:
            jdata = json.load(f)
        url = urljoin(self.root_url, 'servers/add')
        response = session.post(url, data=json.dumps(jdata))
        return self._check_response(response)

    def edit_server(self, server_id, url=None, name=None, authkey=None, organisation=None, internal=None, push=None,
                    pull=None, self_signed=None, push_rules=None, pull_rules=None,
                    submitted_cert=None, submitted_client_cert=None, delete_cert=None, delete_client_cert=None):
        new_server = self._set_server_parameters(url, name, authkey, organisation, internal,
                                                 push, pull, self_signed, push_rules, pull_rules, submitted_cert,
                                                 submitted_client_cert, delete_cert, delete_client_cert)
        session = self.__prepare_session()
        url = urljoin(self.root_url, 'servers/edit/{}'.format(server_id))
        response = session.post(url, data=json.dumps(new_server))
        return self._check_response(response)

    def edit_server_json(self, json_file, server_id):
        session = self.__prepare_session()
        with open(json_file, 'r') as f:
            jdata = json.load(f)
        url = urljoin(self.root_url, 'servers/edit/{}'.format(server_id))
        response = session.post(url, data=json.dumps(jdata))
        return self._check_response(response)

    # ##############################################
    # ############### Non-JSON output ##############
    # ##############################################

    # ############## Suricata ##############

    def download_all_suricata(self):
        """Download all suricata rules events."""
        suricata_rules = urljoin(self.root_url, 'events/nids/suricata/download')
        session = self.__prepare_session('rules')
        response = session.get(suricata_rules)
        return response

    def download_suricata_rule_event(self, event_id):
        """Download one suricata rule event.

        :param event_id: ID of the event to download (same as get)
        """
        template = urljoin(self.root_url, 'events/nids/suricata/download/{}'.format(event_id))
        session = self.__prepare_session('rules')
        response = session.get(template)
        return response

    # ############## Text ###############

    def get_all_attributes_txt(self, type_attr, tags=False, eventId=False, allowNonIDS=False, date_from=False, date_to=False, last=False, enforceWarninglist=False, allowNotPublished=False):
        """Get all attributes from a specific type as plain text. Only published and IDS flagged attributes are exported, except if stated otherwise."""
        session = self.__prepare_session('txt')
        url = urljoin(self.root_url, 'attributes/text/download/%s/%s/%s/%s/%s/%s/%s/%s/%s' % (type_attr, tags, eventId, allowNonIDS, date_from, date_to, last, enforceWarninglist, allowNotPublished))
        response = session.get(url)
        return response

    # ############## STIX ##############

    def get_stix_event(self, event_id=None, with_attachments=False, from_date=False, to_date=False, tags=False):
        """Get an event/events in STIX format"""
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

    def get_stix(self, **kwargs):
        return self.get_stix_event(**kwargs)

    # ###########################
    # ####### Deprecated ########
    # ###########################

    @deprecated
    def add_tag(self, event, tag, attribute=False):
        # FIXME: this is dirty, this function needs to be deprecated with something tagging a UUID
        session = self.__prepare_session()
        if attribute:
            to_post = {'request': {'Attribute': {'id': event['id'], 'tag': tag}}}
            path = 'attributes/addTag'
        else:
            # Allow for backwards-compat with old style
            if "Event" in event:
                event = event["Event"]
            to_post = {'request': {'Event': {'id': event['id'], 'tag': tag}}}
            path = 'events/addTag'
        response = session.post(urljoin(self.root_url, path), data=json.dumps(to_post))
        return self._check_response(response)

    @deprecated
    def remove_tag(self, event, tag, attribute=False):
        # FIXME: this is dirty, this function needs to be deprecated with something removing the tag to a UUID
        session = self.__prepare_session()
        if attribute:
            to_post = {'request': {'Attribute': {'id': event['id'], 'tag': tag}}}
            path = 'attributes/addTag'
        else:
            to_post = {'request': {'Event': {'id': event['Event']['id'], 'tag': tag}}}
            path = 'events/addTag'
        response = session.post(urljoin(self.root_url, path), data=json.dumps(to_post))
        return self._check_response(response)
