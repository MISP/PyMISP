
# -*- coding: utf-8 -*-

"""Python API using the REST interface of MISP"""

import sys
import json
import datetime
from dateutil.parser import parse
import os
import base64
import re
import logging
from io import BytesIO, open
import zipfile

from . import __version__, deprecated
from .exceptions import PyMISPError, SearchError, NoURL, NoKey
from .mispevent import MISPEvent, MISPAttribute, MISPUser, MISPOrganisation, MISPSighting
from .abstract import MISPEncode

logger = logging.getLogger('pymisp')

try:
    from urllib.parse import urljoin
    # Least dirty way to support python 2 and 3
    basestring = str
    unicode = str
except ImportError:
    from urlparse import urljoin
    logger.warning("You're using python 2, it is strongly recommended to use python >=3.5")

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False


try:
    from requests_futures.sessions import FuturesSession
    ASYNC_OK = True
except ImportError:
    ASYNC_OK = False


class PyMISP(object):
    """Python API for MISP

    :param url: URL of the MISP instance you want to connect to
    :param key: API key of the user you want to use
    :param ssl: can be True or False (to check ot not the validity of the certificate. Or a CA_BUNDLE in case of self signed certiifcate (the concatenation of all the \*.crt of the chain)
    :param out_type: Type of object (json) NOTE: XML output isn't supported anymore, keeping the flag for compatibility reasons.
    :param debug: Write all the debug information to stderr
    :param proxies: Proxy dict as describes here: http://docs.python-requests.org/en/master/user/advanced/#proxies
    :param cert: Client certificate, as described there: http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification
    :param asynch: Use asynchronous processing where possible
    """

    def __init__(self, url, key, ssl=True, out_type='json', debug=None, proxies=None, cert=None, asynch=False):
        if not url:
            raise NoURL('Please provide the URL of your MISP instance.')
        if not key:
            raise NoKey('Please provide your authorization key.')

        self.root_url = url
        self.key = key
        self.ssl = ssl
        self.proxies = proxies
        self.cert = cert
        self.asynch = asynch
        if asynch and not ASYNC_OK:
            logger.critical("You turned on Async, but don't have requests_futures installed")
            self.asynch = False

        self.resources_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'data')
        if out_type != 'json':
            raise PyMISPError('The only output type supported by PyMISP is JSON. If you still rely on XML, use PyMISP v2.4.49')
        if debug:
            logger.setLevel(logging.DEBUG)
            logger.info('To configure logging in your script, leave it to None and use the following: import logging; logging.getLogger(\'pymisp\').setLevel(logging.DEBUG)')

        try:
            # Make sure the MISP instance is working and the URL is valid
            response = self.get_recommended_api_version()
            if response.get('errors'):
                logger.warning(response.get('errors')[0])
            elif not response.get('version'):
                logger.warning("Unable to check the recommended PyMISP version (MISP <2.4.60), please upgrade.")
            else:
                pymisp_version_tup = tuple(int(x) for x in __version__.split('.'))
                recommended_version_tup = tuple(int(x) for x in response['version'].split('.'))
                if recommended_version_tup < pymisp_version_tup[:3]:
                    logger.info("The version of PyMISP recommended by the MISP instance ({}) is older than the one you're using now ({}). If you have a problem, please upgrade the MISP instance or use an older PyMISP version.".format(response['version'], __version__))
                elif pymisp_version_tup[:3] < recommended_version_tup:
                    logger.warning("The version of PyMISP recommended by the MISP instance ({}) is newer than the one you're using now ({}). Please upgrade PyMISP.".format(response['version'], __version__))

        except Exception as e:
            raise PyMISPError('Unable to connect to MISP ({}). Please make sure the API key and the URL are correct (http/https is required): {}'.format(self.root_url, e))

        try:
            self.describe_types = self.get_live_describe_types()
        except Exception:
            self.describe_types = self.get_local_describe_types()

        self.categories = self.describe_types['categories']
        self.types = self.describe_types['types']
        self.category_type_mapping = self.describe_types['category_type_mappings']
        self.sane_default = self.describe_types['sane_defaults']

    def __repr__(self):
        return '<{self.__class__.__name__}(url={self.root_url})'.format(self=self)

    def get_live_query_acl(self):
        """This should return an empty list, unless the ACL is outdated."""
        response = self.__prepare_request('GET', urljoin(self.root_url, 'events/queryACL.json'))
        return self._check_response(response)

    def get_local_describe_types(self):
        with open(os.path.join(self.resources_path, 'describeTypes.json'), 'r') as f:
            describe_types = json.load(f)
        return describe_types['result']

    def get_live_describe_types(self):
        response = self.__prepare_request('GET', urljoin(self.root_url, 'attributes/describeTypes.json'))
        describe_types = self._check_response(response)
        if describe_types.get('error'):
            for e in describe_types.get('error'):
                raise PyMISPError('Failed: {}'.format(e))
        describe_types = describe_types['result']
        if not describe_types.get('sane_defaults'):
            raise PyMISPError('The MISP server your are trying to reach is outdated (<2.4.52). Please use PyMISP v2.4.51.1 (pip install -I PyMISP==v2.4.51.1) and/or contact your administrator.')
        return describe_types

    def __prepare_request(self, request_type, url, data=None,
                          background_callback=None, output_type='json'):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug('{} - {}'.format(request_type, url))
            if data is not None:
                logger.debug(data)
        if data is None:
            req = requests.Request(request_type, url)
        else:
            req = requests.Request(request_type, url, data=data)
        if self.asynch and background_callback is not None:
            s = FuturesSession()
        else:
            s = requests.Session()
        prepped = s.prepare_request(req)
        prepped.headers.update(
            {'Authorization': self.key,
             'Accept': 'application/{}'.format(output_type),
             'content-type': 'application/{}'.format(output_type),
             'User-Agent': 'PyMISP {} - Python {}.{}.{}'.format(__version__, *sys.version_info)})
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(prepped.headers)
        if self.asynch and background_callback is not None:
            return s.send(prepped, verify=self.ssl, proxies=self.proxies, cert=self.cert, background_callback=background_callback)
        else:
            return s.send(prepped, verify=self.ssl, proxies=self.proxies, cert=self.cert)

    # #####################
    # ### Core helpers ####
    # #####################

    def flatten_error_messages(self, response):
        """Dirty dirty method to normalize the error messages between the API calls.
        Any response containing the a key 'error' or 'errors' failed at some point,
        we make one single list out of it.
        """
        messages = []
        if response.get('error'):
            if isinstance(response['error'], list):
                for e in response['error']:
                    if isinstance(e, dict):
                        messages.append(e['error']['value'][0])
                    else:
                        messages.append(e)
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
                        if isinstance(errors, list):
                            for e in errors:
                                if not e:
                                    continue
                                if isinstance(e, basestring):
                                    messages.append(e)
                                    continue
                                for type_e, msgs in e.items():
                                    for m in msgs:
                                        messages.append('Error in {}: {}'.format(where, m))
                        else:
                            messages.append('{} ({})'.format(errors, where))

        return messages

    def _check_response(self, response):
        """Check if the response from the server is not an unexpected error"""
        errors = []
        if response.status_code >= 500:
            if len(response.content) == 0:
                raise PyMISPError('Something bad happened on the server-side, but there was no response content to be decoded')
            else:
                errors.append(response.json())
                logger.critical('Something bad happened on the server-side: {}'.format(response.json()))
        try:
            to_return = response.json()
        except ValueError:
            # It the server didn't return a JSON blob, we've a problem.
            raise PyMISPError('Unknown error (something is very broken server-side: {})'.format(response.text))

        if isinstance(to_return, (list, str)):
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
                errors.append(str(response.status_code))
        errors += self.flatten_error_messages(to_return)
        if errors:
            to_return['errors'] = errors
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(json.dumps(to_return, indent=4))
        return to_return

    def _one_or_more(self, value):
        """Returns a list/tuple of one or more items, regardless of input."""
        return value if isinstance(value, (tuple, list)) else (value,)

    def _make_mispevent(self, event):
        """Transform a Json MISP event into a MISPEvent"""
        if not isinstance(event, MISPEvent):
            e = MISPEvent(self.describe_types)
            e.load(event)
        else:
            e = event
        return e

    def _prepare_full_event(self, distribution, threat_level_id, analysis, info, date=None, published=False, orgc_id=None, org_id=None, sharing_group_id=None):
        """Initialize a new MISPEvent from scratch"""
        misp_event = MISPEvent(self.describe_types)
        misp_event.from_dict(info=info, distribution=distribution, threat_level_id=threat_level_id,
                             analysis=analysis, date=date, orgc_id=orgc_id, org_id=org_id, sharing_group_id=sharing_group_id)
        if published:
            misp_event.publish()
        return misp_event

    def _prepare_full_attribute(self, category, type_value, value, to_ids, comment=None, distribution=None, **kwargs):
        """Initialize a new MISPAttribute from scratch"""
        misp_attribute = MISPAttribute(self.describe_types)
        misp_attribute.from_dict(type=type_value, value=value, category=category,
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

    def test_connection(self):
        """Test the auth key"""
        response = self.get_version()
        if response.get('errors'):
            raise PyMISPError(response.get('errors')[0])
        return True

    def get_index(self, filters=None):
        """Return the index.

        Warning, there's a limit on the number of results
        """
        url = urljoin(self.root_url, 'events/index')
        if filters is None:
            response = self.__prepare_request('GET', url)
        else:
            response = self.__prepare_request('POST', url, json.dumps(filters))
        return self._check_response(response)

    def get_event(self, event_id):
        """Get an event

        :param event_id: Event id to get
        """
        url = urljoin(self.root_url, 'events/{}'.format(event_id))
        response = self.__prepare_request('GET', url)
        return self._check_response(response)

    def add_event(self, event):
        """Add a new event

        :param event: Event as JSON object / string to add
        """
        url = urljoin(self.root_url, 'events')
        if isinstance(event, MISPEvent):
            event = event.to_json()
        elif not isinstance(event, basestring):
            event = json.dumps(event)
        response = self.__prepare_request('POST', url, event)
        return self._check_response(response)

    def update_event(self, event_id, event):
        """Update an event

        :param event_id: Event id to update
        :param event: Event as JSON object / string to add
        """
        url = urljoin(self.root_url, 'events/{}'.format(event_id))
        if isinstance(event, MISPEvent):
            event = event.to_json()
        elif not isinstance(event, basestring):
            event = json.dumps(event)
        response = self.__prepare_request('POST', url, event)
        return self._check_response(response)

    def delete_event(self, event_id):
        """Delete an event

        :param event_id: Event id to delete
        """
        url = urljoin(self.root_url, 'events/{}'.format(event_id))
        response = self.__prepare_request('DELETE', url)
        return self._check_response(response)

    def delete_attribute(self, attribute_id, hard_delete=False):
        """Delete an attribute by ID"""
        if hard_delete:
            url = urljoin(self.root_url, 'attributes/delete/{}/1'.format(attribute_id))
        else:
            url = urljoin(self.root_url, 'attributes/delete/{}'.format(attribute_id))
        response = self.__prepare_request('GET', url)
        return self._check_response(response)

    def pushEventToZMQ(self, event_id):
        """Force push an event on ZMQ"""
        url = urljoin(self.root_url, 'events/pushEventToZMQ/{}.json'.format(event_id))
        response = self.__prepare_request('POST', url)
        return self._check_response(response)

    # ##############################################
    # ############### Event handling ###############
    # ##############################################

    def get(self, eid):
        """Get an event by event ID"""
        return self.get_event(eid)

    def update(self, event):
        """Update an event by ID"""
        e = self._make_mispevent(event)
        if e.uuid:
            eid = e.uuid
        else:
            eid = e.id
        return self.update_event(eid, e)

    def fast_publish(self, event_id, alert=False):
        """Does the same as the publish method, but just try to publish the event
        even with one single HTTP GET.
        The default is to not send a mail as it is assumed this method is called on update.
        """
        if not alert:
            url = urljoin(self.root_url, 'events/publish/{}'.format(event_id))
        else:
            url = urljoin(self.root_url, 'events/alert/{}'.format(event_id))
        response = self.__prepare_request('POST', url)
        return self._check_response(response)

    def publish(self, event, alert=True):
        """Publish event (with or without alert email)
        :param event: pass event or event id (as string or int) to publish
        :param alert: set to True by default (send alerting email) if False will not send alert
        :return publish status
        """
        if isinstance(event, int) or (isinstance(event, basestring) and event.isdigit()):
            event_id = event
        else:
            full_event = self._make_mispevent(event)
            if full_event.published:
                return {'error': 'Already published'}
            event_id = full_event.id
        return self.fast_publish(event_id, alert)

    def change_threat_level(self, event, threat_level_id):
        """Change the threat level of an event"""
        e = self._make_mispevent(event)
        e.threat_level_id = threat_level_id
        return self.update(e)

    def change_sharing_group(self, event, sharing_group_id):
        """Change the sharing group of an event"""
        e = self._make_mispevent(event)
        e.distribution = 4      # Needs to be 'Sharing group'
        e.sharing_group_id = sharing_group_id
        return self.update(e)

    def new_event(self, distribution=None, threat_level_id=None, analysis=None, info=None, date=None, published=False, orgc_id=None, org_id=None, sharing_group_id=None):
        """Create and add a new event"""
        misp_event = self._prepare_full_event(distribution, threat_level_id, analysis, info, date, published, orgc_id, org_id, sharing_group_id)
        return self.add_event(misp_event)

    def tag(self, uuid, tag):
        """Tag an event or an attribute"""
        if not self._valid_uuid(uuid):
            raise PyMISPError('Invalid UUID')
        url = urljoin(self.root_url, 'tags/attachTagToObject')
        to_post = {'uuid': uuid, 'tag': tag}
        response = self.__prepare_request('POST', url, json.dumps(to_post))
        return self._check_response(response)

    def untag(self, uuid, tag):
        """Untag an event or an attribute"""
        if not self._valid_uuid(uuid):
            raise PyMISPError('Invalid UUID')
        url = urljoin(self.root_url, 'tags/removeTagFromObject')
        to_post = {'uuid': uuid, 'tag': tag}
        response = self.__prepare_request('POST', url, json.dumps(to_post))
        return self._check_response(response)

    # ##### File attributes #####
    def _send_attributes(self, event, attributes, proposal=False):
        """
        Helper to add new attributes to an existing event, identified by an event object or an event id


        :param event: EventID (int) or Event to alter
        :param attributes: One or more attribute to add
        :param proposal: True or False based on whether the attributes should be proposed or directly save
        :type event: MISPEvent, int
        :type attributes: MISPAttribute, list
        :type proposal: bool
        :return: list of responses
        :rtype: list
        """
        event_id = self._extract_event_id(event)
        responses = []
        if not event_id:
            raise PyMISPError("Unable to find the ID of the event to update.")
        if not attributes:
            return {'error': 'No attributes.'}

        # Propals need to be posted in single requests
        if proposal:
            for a in attributes:
                # proposal_add(...) returns a dict
                responses.append(self.proposal_add(event_id, a))
        else:
            url = urljoin(self.root_url, 'attributes/add/{}'.format(event_id))
            if isinstance(attributes, list):
                values = []
                for a in attributes:
                    values.append(a['value'])
                attributes[0]['value'] = values
                data = attributes[0].to_json()
            else:
                data = attributes.to_json()
            # __prepare_request(...) returns a requests.Response Object
            responses.append(self.__prepare_request('POST', url, data).json())
        return responses

    def _extract_event_id(self, event):
        """
        Extracts the eventId from a given MISPEvent

        :param event: MISPEvent to extract the id from
        :type event: MISPEvent
        :return: EventId
        :rtype: int
        """
        event_id = None
        if isinstance(event, MISPEvent):
            if hasattr(event, 'id'):
                event_id = event.id
            elif hasattr(event, 'uuid'):
                event_id = event.uuid
        elif isinstance(event, int):
            event_id = event
        else:
            e = MISPEvent(describe_types=self.describe_types)
            e.load(event)
            if hasattr(e, 'id'):
                event_id = e.id
            elif hasattr(e, 'uuid'):
                event_id = e.uuid
        return event_id

    def add_named_attribute(self, event, type_value, value, category=None, to_ids=False, comment=None, distribution=None, proposal=False, **kwargs):
        """Add one or more attributes to an existing event"""
        attributes = []
        for value in self._one_or_more(value):
            attributes.append(self._prepare_full_attribute(category, type_value, value, to_ids, comment, distribution, **kwargs))
        return self._send_attributes(event, attributes, proposal)

    def add_hashes(self, event, category='Artifacts dropped', filename=None, md5=None, sha1=None, sha256=None, ssdeep=None, comment=None, to_ids=True, distribution=None, proposal=False, **kwargs):
        """Add hashe(s) to an existing event"""

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

    def av_detection_link(self, event, link, category='Antivirus detection', to_ids=False, comment=None, distribution=None, proposal=False, **kwargs):
        """Add AV detection link(s)"""
        return self.add_named_attribute(event, 'link', link, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_detection_name(self, event, name, category='Antivirus detection', to_ids=False, comment=None, distribution=None, proposal=False, **kwargs):
        """Add AV detection name(s)"""
        return self.add_named_attribute(event, 'text', name, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_filename(self, event, filename, category='Artifacts dropped', to_ids=False, comment=None, distribution=None, proposal=False, **kwargs):
        """Add filename(s)"""
        return self.add_named_attribute(event, 'filename', filename, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_attachment(self, event, attachment, category='Artifacts dropped', to_ids=False, comment=None, distribution=None, proposal=False, **kwargs):
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
        return self.add_named_attribute(event, 'attachment', filename, category, to_ids, comment, distribution, proposal, data=encodedData, **kwargs)

    def add_regkey(self, event, regkey, rvalue=None, category='Artifacts dropped', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add a registry key"""
        if rvalue:
            type_value = 'regkey|value'
            value = '{}|{}'.format(regkey, rvalue)
        else:
            type_value = 'regkey'
            value = regkey

        attributes = []
        attributes.append(self._prepare_full_attribute(category, type_value, value, to_ids, comment, distribution))
        return self._send_attributes(event, attributes, proposal)

    def add_regkeys(self, event, regkeys_values, category='Artifacts dropped', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add a registry keys"""
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

    def add_pattern(self, event, pattern, in_file=True, in_memory=False, category='Artifacts dropped', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add a pattern(s) in file or in memory"""
        if not (in_file or in_memory):
            raise PyMISPError('Invalid pattern type: please use in_memory=True or in_file=True')
        itemtype = 'pattern-in-file' if in_file else 'pattern-in-memory'
        return self.add_named_attribute(event, itemtype, pattern, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_pipe(self, event, named_pipe, category='Artifacts dropped', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add pipes(s)"""
        def scrub(s):
            if not s.startswith('\\.\\pipe\\'):
                s = '\\.\\pipe\\{}'.format(s)
            return s
        attributes = list(map(scrub, self._one_or_more(named_pipe)))
        return self.add_named_attribute(event, 'named pipe', attributes, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_mutex(self, event, mutex, category='Artifacts dropped', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add mutex(es)"""
        def scrub(s):
            if not s.startswith('\\BaseNamedObjects\\'):
                s = '\\BaseNamedObjects\\{}'.format(s)
            return s
        attributes = list(map(scrub, self._one_or_more(mutex)))
        return self.add_named_attribute(event, 'mutex', attributes, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_yara(self, event, yara, category='Payload delivery', to_ids=False, comment=None, distribution=None, proposal=False, **kwargs):
        """Add yara rule(es)"""
        return self.add_named_attribute(event, 'yara', yara, category, to_ids, comment, distribution, proposal, **kwargs)

    # ##### Network attributes #####

    def add_ipdst(self, event, ipdst, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add destination IP(s)"""
        return self.add_named_attribute(event, 'ip-dst', ipdst, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_ipsrc(self, event, ipsrc, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add source IP(s)"""
        return self.add_named_attribute(event, 'ip-src', ipsrc, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_hostname(self, event, hostname, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add hostname(s)"""
        return self.add_named_attribute(event, 'hostname', hostname, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_domain(self, event, domain, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add domain(s)"""
        return self.add_named_attribute(event, 'domain', domain, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_domain_ip(self, event, domain, ip, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add domain|ip"""
        if isinstance(ip, str):
            ip = [ip]
        composed = list(map(lambda x: '%s|%s' % (domain, x), ip))
        return self.add_named_attribute(event, 'domain|ip', composed, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_domains_ips(self, event, domain_ips, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add multiple domain|ip"""
        composed = list(map(lambda x: '%s|%s' % (x[0], x[1]), domain_ips.items()))
        return self.add_named_attribute(event, 'domain|ip', composed, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_url(self, event, url, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add url(s)"""
        return self.add_named_attribute(event, 'url', url, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_useragent(self, event, useragent, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add user agent(s)"""
        return self.add_named_attribute(event, 'user-agent', useragent, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_traffic_pattern(self, event, pattern, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add pattern(s) in traffic"""
        return self.add_named_attribute(event, 'pattern-in-traffic', pattern, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_snort(self, event, snort, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add SNORT rule(s)"""
        return self.add_named_attribute(event, 'snort', snort, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_net_other(self, event, netother, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add a free text entry"""
        return self.add_named_attribute(event, 'other', netother, category, to_ids, comment, distribution, proposal, **kwargs)

    # ##### Email attributes #####

    def add_email_src(self, event, email, category='Payload delivery', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add a source email"""
        return self.add_named_attribute(event, 'email-src', email, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_email_dst(self, event, email, category='Payload delivery', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add a destination email"""
        return self.add_named_attribute(event, 'email-dst', email, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_email_subject(self, event, email, category='Payload delivery', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an email subject"""
        return self.add_named_attribute(event, 'email-subject', email, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_email_attachment(self, event, email, category='Payload delivery', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an email atachment"""
        return self.add_named_attribute(event, 'email-attachment', email, category, to_ids, comment, distribution, proposal, **kwargs)

    # ##### Target attributes #####

    def add_target_email(self, event, target, category='Targeting data', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an target email"""
        return self.add_named_attribute(event, 'target-email', target, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_target_user(self, event, target, category='Targeting data', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an target user"""
        return self.add_named_attribute(event, 'target-user', target, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_target_machine(self, event, target, category='Targeting data', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an target machine"""
        return self.add_named_attribute(event, 'target-machine', target, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_target_org(self, event, target, category='Targeting data', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an target organisation"""
        return self.add_named_attribute(event, 'target-org', target, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_target_location(self, event, target, category='Targeting data', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an target location"""
        return self.add_named_attribute(event, 'target-location', target, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_target_external(self, event, target, category='Targeting data', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an target external"""
        return self.add_named_attribute(event, 'target-external', target, category, to_ids, comment, distribution, proposal, **kwargs)

    # ##### Attribution attributes #####

    def add_threat_actor(self, event, target, category='Attribution', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an threat actor"""
        return self.add_named_attribute(event, 'threat-actor', target, category, to_ids, comment, distribution, proposal, **kwargs)

    # ##### Internal reference attributes #####

    def add_internal_link(self, event, reference, category='Internal reference', to_ids=False, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an internal link"""
        return self.add_named_attribute(event, 'link', reference, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_internal_comment(self, event, reference, category='Internal reference', to_ids=False, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an internal comment"""
        return self.add_named_attribute(event, 'comment', reference, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_internal_text(self, event, reference, category='Internal reference', to_ids=False, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an internal text"""
        return self.add_named_attribute(event, 'text', reference, category, to_ids, comment, distribution, proposal, **kwargs)

    def add_internal_other(self, event, reference, category='Internal reference', to_ids=False, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an internal reference (type other)"""
        return self.add_named_attribute(event, 'other', reference, category, to_ids, comment, distribution, proposal, **kwargs)

    # ##################################################
    # ######### Upload samples through the API #########
    # ##################################################

    def _prepare_upload(self, event_id, distribution, to_ids, category, comment, info,
                        analysis, threat_level_id):
        """Helper to prepare a sample to upload"""
        to_post = {'request': {}}

        if event_id is not None:
            try:
                event_id = int(event_id)
            except ValueError:
                pass
        if not isinstance(event_id, int):
            # New event
            misp_event = self._prepare_full_event(distribution, threat_level_id, analysis, info)
            to_post['request']['distribution'] = misp_event.distribution
            to_post['request']['info'] = misp_event.info
            to_post['request']['analysis'] = misp_event.analysis
            to_post['request']['threat_level_id'] = misp_event.threat_level_id
        else:
            if distribution is not None:
                to_post['request']['distribution'] = distribution

        default_values = self.sane_default['malware-sample']
        if to_ids is None or not isinstance(to_ids, bool):
            to_ids = bool(int(default_values['to_ids']))
        to_post['request']['to_ids'] = to_ids

        if category is None or category not in self.categories:
            category = default_values['default_category']
        to_post['request']['category'] = category

        to_post['request']['comment'] = comment
        return to_post, event_id

    def _encode_file_to_upload(self, filepath_or_bytes):
        """Helper to encode a file to upload"""
        if isinstance(filepath_or_bytes, basestring) and os.path.isfile(filepath_or_bytes):
            with open(filepath_or_bytes, 'rb') as f:
                binblob = f.read()
        else:
            binblob = filepath_or_bytes
        return base64.b64encode(binblob).decode()

    def upload_sample(self, filename, filepath_or_bytes, event_id, distribution=None,
                      to_ids=True, category=None, comment=None, info=None,
                      analysis=None, threat_level_id=None):
        """Upload a sample"""
        to_post, event_id = self._prepare_upload(event_id, distribution, to_ids, category,
                                                 comment, info, analysis, threat_level_id)
        to_post['request']['files'] = [{'filename': filename, 'data': self._encode_file_to_upload(filepath_or_bytes)}]
        return self._upload_sample(to_post, event_id)

    def upload_samplelist(self, filepaths, event_id, distribution=None,
                          to_ids=True, category=None, comment=None, info=None,
                          analysis=None, threat_level_id=None):
        """Upload a list of samples"""
        to_post, event_id = self._prepare_upload(event_id, distribution, to_ids, category,
                                                 comment, info, analysis, threat_level_id)
        files = []
        for path in filepaths:
            if not os.path.isfile(path):
                continue
            files.append({'filename': os.path.basename(path), 'data': self._encode_file_to_upload(path)})
        to_post['request']['files'] = files
        return self._upload_sample(to_post, event_id)

    def _upload_sample(self, to_post, event_id=None):
        """Helper to upload a sample"""
        if event_id is None:
            url = urljoin(self.root_url, 'events/upload_sample')
        else:
            url = urljoin(self.root_url, 'events/upload_sample/{}'.format(event_id))
        response = self.__prepare_request('POST', url, json.dumps(to_post))
        return self._check_response(response)

    # ############################
    # ######## Proposals #########
    # ############################

    def __query_proposal(self, path, id, attribute=None):
        """Helper to prepare a query to handle proposals"""
        url = urljoin(self.root_url, 'shadow_attributes/{}/{}'.format(path, id))
        if path in ['add', 'edit']:
            query = {'request': {'ShadowAttribute': attribute}}
            response = self.__prepare_request('POST', url, json.dumps(query, cls=MISPEncode))
        elif path == 'view':
            response = self.__prepare_request('GET', url)
        else:  # accept or discard
            response = self.__prepare_request('POST', url)
        return self._check_response(response)

    def proposal_view(self, event_id=None, proposal_id=None):
        """View a proposal"""
        if proposal_id is not None and event_id is not None:
            return {'error': 'You can only view an event ID or a proposal ID'}
        if event_id is not None:
            id = event_id
        else:
            id = proposal_id
        return self.__query_proposal('view', id)

    def proposal_add(self, event_id, attribute):
        """Add a proposal"""
        return self.__query_proposal('add', event_id, attribute)

    def proposal_edit(self, attribute_id, attribute):
        """Edit a proposal"""
        return self.__query_proposal('edit', attribute_id, attribute)

    def proposal_accept(self, proposal_id):
        """Accept a proposal"""
        return self.__query_proposal('accept', proposal_id)

    def proposal_discard(self, proposal_id):
        """Discard a proposal"""
        return self.__query_proposal('discard', proposal_id)

    # ##############################
    # ###### Attribute update ######
    # ##############################

    def change_toids(self, attribute_uuid, to_ids):
        """Change the toids flag"""
        if to_ids not in [0, 1]:
            raise Exception('to_ids can only be 0 or 1')
        query = {"to_ids": to_ids}
        return self.__query('edit/{}'.format(attribute_uuid), query, controller='attributes')

    # ##############################
    # ###### Attribute update ######
    # ##############################

    def freetext(self, event_id, string, adhereToWarninglists=False, distribution=None):
        """Pass a text to the freetext importer"""
        query = {"value": string}
        wl_params = [False, True, 'soft']
        if adhereToWarninglists not in wl_params:
            raise Exception('Invalid parameter, adhereToWarninglists Can only be {}'.format(', '.join(wl_params)))
        if adhereToWarninglists:
            query['adhereToWarninglists'] = adhereToWarninglists
        if distribution is not None:
            query['distribution'] = distribution
        return self.__query('freeTextImport/{}'.format(event_id), query, controller='events')

    # ##############################
    # ######## REST Search #########
    # ##############################

    def __query(self, path, query, controller='events', async_callback=None):
        """Helper to prepare a search query"""
        if query.get('error') is not None:
            return query
        if controller not in ['events', 'attributes']:
            raise Exception('Invalid controller. Can only be {}'.format(', '.join(['events', 'attributes'])))
        url = urljoin(self.root_url, '{}/{}'.format(controller, path.lstrip('/')))

        if ASYNC_OK and async_callback:
            response = self.__prepare_request('POST', url, json.dumps(query), async_callback)
        else:
            response = self.__prepare_request('POST', url, json.dumps(query))
            return self._check_response(response)

    def search_index(self, published=None, eventid=None, tag=None, datefrom=None,
                     dateuntil=None, eventinfo=None, threatlevel=None, distribution=None,
                     analysis=None, attribute=None, org=None, async_callback=None, normalize=False):
        """Search only at the index level. Use ! infront of value as NOT, default OR
        If using async, give a callback that takes 2 args, session and response:
        basic usage is
        pymisp.search_index(..., async_callback=lambda ses,resp: print(resp.json()))

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
        :param async_callback: Function to call when the request returns (if running async)
        :param normalize: Normalize output | True or False
        """
        allowed = {'published': published, 'eventid': eventid, 'tag': tag, 'Dateuntil': dateuntil,
                   'Datefrom': datefrom, 'eventinfo': eventinfo, 'threatlevel': threatlevel,
                   'distribution': distribution, 'analysis': analysis, 'attribute': attribute,
                   'org': org}
        rule_levels = {'distribution': ["0", "1", "2", "3", "!0", "!1", "!2", "!3"],
                       'threatlevel': ["1", "2", "3", "4", "!1", "!2", "!3", "!4"],
                       'analysis': ["0", "1", "2", "!0", "!1", "!2"]}
        buildup_url = "events/index"

        to_post = {}
        for rule in allowed.keys():

            if allowed.get(rule) is None:
                continue
            param = allowed[rule]
            if not isinstance(param, list):
                param = [param]
            param = [x for x in map(str, param)]
            if rule in rule_levels:
                if not set(param).issubset(rule_levels[rule]):
                    raise SearchError('Values in your {} are invalid, has to be in {}'.format(rule, ', '.join(str(x) for x in rule_levels[rule])))
            to_post[rule] = '|'.join(str(x) for x in param)
        url = urljoin(self.root_url, buildup_url)

        if self.asynch and async_callback:
            response = self.__prepare_request('POST', url, json.dumps(to_post), async_callback)
        else:
            response = self.__prepare_request('POST', url, json.dumps(to_post))
            res = self._check_response(response)
            if normalize:
                to_return = {'response': []}
                for elem in res['response']:
                    tmp = {'Event': elem}
                    to_return['response'].append(tmp)
                res = to_return
            return res

    def search_all(self, value):
        """Search a value in the whole database"""
        query = {'value': value, 'searchall': 1}
        return self.__query('restSearch/download', query)

    def __prepare_rest_search(self, values, not_values):
        """Prepare a search, generate the chain processed by the server

        :param values: Values to search
        :param not_values: Values that should not be in the response
        """
        to_return = []
        if values is not None:
            if isinstance(values, list):
                to_return += values
            else:
                to_return.append(values)
        if not_values is not None:
            if isinstance(not_values, list):
                to_return += ['!{}'.format(v) for v in not_values]
            else:
                to_return.append('!{}'.format(not_values))
        return to_return

    def search(self, controller='events', async_callback=None, **kwargs):
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
        :param last: Last published events (for example 5d or 12h or 30m)
        :param eventid: Last date
        :param withAttachments: return events with or without the attachments
        :param uuid: search by uuid
        :param publish_timestamp: the publish timestamp
        :param timestamp: the timestamp of the last modification. Can be a list (from->to)
        :param enforceWarninglist: Enforce the warning lists
        :param searchall: full text search on the database
        :param metadata: return only metadata if True
        :param published: return only published events
        :param to_ids: return only the attributes with the to_ids flag set
        :param deleted: also return the deleted attributes
        :param async_callback: The function to run when results are returned
        """
        query = {}
        # Event:     array('value', 'type', 'category', 'org', 'tags', 'from', 'to', 'last', 'eventid', 'withAttachments', 'uuid', 'publish_timestamp', 'timestamp', 'enforceWarninglist', 'searchall', 'metadata', 'published');
        # Attribute: array('value', 'type', 'category', 'org', 'tags', 'from', 'to', 'last', 'eventid', 'withAttachments', 'uuid', 'publish_timestamp', 'timestamp', 'enforceWarninglist', 'to_ids', 'deleted');
        val = self.__prepare_rest_search(kwargs.pop('values', None), kwargs.pop('not_values', None))
        if val:
            query['value'] = val

        query['type'] = kwargs.pop('type_attribute', None)
        query['category'] = kwargs.pop('category', None)
        query['org'] = kwargs.pop('org', None)

        tag = self.__prepare_rest_search(kwargs.pop('tags', None), kwargs.pop('not_tags', None))
        if tag:
            query['tags'] = tag

        date_from = kwargs.pop('date_from', None)
        if date_from:
            if isinstance(date_from, datetime.date) or isinstance(date_from, datetime.datetime):
                query['from'] = date_from.strftime('%Y-%m-%d')
            else:
                query['from'] = date_from

        date_to = kwargs.pop('date_to', None)
        if date_to:
            if isinstance(date_to, datetime.date) or isinstance(date_to, datetime.datetime):
                query['to'] = date_to.strftime('%Y-%m-%d')
            else:
                query['to'] = date_to

        query['last'] = kwargs.pop('last', None)
        query['eventid'] = kwargs.pop('eventid', None)
        query['withAttachments'] = kwargs.pop('withAttachments', None)

        uuid = kwargs.pop('uuid', None)
        if uuid:
            if self._valid_uuid(uuid):
                query['uuid'] = uuid
            else:
                return {'error': 'You must enter a valid uuid.'}

        query['publish_timestamp'] = kwargs.pop('publish_timestamp', None)
        query['timestamp'] = kwargs.pop('timestamp', None)
        query['enforceWarninglist'] = kwargs.pop('enforceWarninglist', None)
        query['to_ids'] = kwargs.pop('to_ids', None)
        query['deleted'] = kwargs.pop('deleted', None)

        if controller == 'events':
            # Event search only:
            query['searchall'] = kwargs.pop('searchall', None)
            query['metadata'] = kwargs.pop('metadata', None)
            query['published'] = kwargs.pop('published', None)

        # Cleanup
        query = {k: v for k, v in query.items() if v is not None}

        if kwargs:
            raise SearchError('Unused parameter: {}'.format(', '.join(kwargs.keys())))

        # Create a session, make it async if and only if we have a callback
        return self.__query('restSearch/download', query, controller, async_callback)

    def get_attachment(self, attribute_id):
        """Get an attachement (not a malware sample) by attribute ID.
        Returns the attachment as a bytestream, or a dictionary containing the error message.

        :param attribute_id: Attribute ID to fetched
        """
        url = urljoin(self.root_url, 'attributes/downloadAttachment/download/{}'.format(attribute_id))
        response = self.__prepare_request('GET', url)
        try:
            response.json()
            # The query fails, response contains a json blob
            return self._check_response(response)
        except ValueError:
            # content contains the attachment in binary
            return response.content

    def get_yara(self, event_id):
        """Get the yara rules from an event"""
        url = urljoin(self.root_url, 'attributes/restSearch')
        to_post = {'request': {'eventid': event_id, 'type': 'yara'}}
        response = self.__prepare_request('POST', url, data=json.dumps(to_post))
        result = self._check_response(response)
        if result.get('error') is not None:
            return False, result.get('error')
        if not result.get('response'):
            return False, result.get('message')
        rules = '\n\n'.join([a['value'] for a in result['response']['Attribute']])
        return True, rules

    def download_samples(self, sample_hash=None, event_id=None, all_samples=False):
        """Download samples, by hash or event ID. If there are multiple samples in one event, use the all_samples switch"""
        url = urljoin(self.root_url, 'attributes/downloadSample')
        to_post = {'request': {'hash': sample_hash, 'eventID': event_id, 'allSamples': all_samples}}
        response = self.__prepare_request('POST', url, data=json.dumps(to_post))
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
        """Download the last published events.

        :param last: can be defined in days, hours, minutes (for example 5d or 12h or 30m)
        """
        return self.search(last=last)

    def _string_to_timestamp(self, date_string):
        pydate = parse(date_string)
        if sys.version_info >= (3, 3):
            # Sane python version
            timestamp = pydate.timestamp()
        else:
            # Whatever
            from datetime import timezone  # Only for Python < 3.3
            timestamp = (pydate - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds()
        return timestamp

    def get_events_last_modified(self, search_from, search_to=None):
        """Download the last modified events.

        :param search_from: Beginning of the interval. Can be either a timestamp, or a date (2000-12-21)
        :param search_to: End of the interval. Can be either a timestamp, or a date (2000-12-21)
        """

        search_from = self._string_to_timestamp(search_from)

        if search_to is not None:
            search_to = self._string_to_timestamp(search_to)
            to_search = [search_from, search_to]
        else:
            to_search = search_from

        return self.search(timestamp=to_search)

    # ########## Tags ##########

    def get_all_tags(self, quiet=False):
        """Get all the tags used on the instance"""
        url = urljoin(self.root_url, 'tags')
        response = self.__prepare_request('GET', url)
        r = self._check_response(response)
        if not quiet or r.get('errors'):
            return r
        else:
            to_return = []
            for tag in r['Tag']:
                to_return.append(tag['name'])
            return to_return

    def new_tag(self, name=None, colour="#00ace6", exportable=False):
        """Create a new tag"""
        to_post = {'Tag': {'name': name, 'colour': colour, 'exportable': exportable}}
        url = urljoin(self.root_url, 'tags/add')
        response = self.__prepare_request('POST', url, json.dumps(to_post))
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
        url = urljoin(self.root_url, 'servers/getPyMISPVersion.json')
        response = self.__prepare_request('GET', url)
        return self._check_response(response)

    def get_version(self):
        """Returns the version of the instance."""
        url = urljoin(self.root_url, 'servers/getVersion.json')
        response = self.__prepare_request('GET', url)
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
        if (context != 'category'):
            context = 'type'
        if percentage is not None:
            url = urljoin(self.root_url, 'attributes/attributeStatistics/{}/{}'.format(context, percentage))
        else:
            url = urljoin(self.root_url, 'attributes/attributeStatistics/{}'.format(context))
        response = self.__prepare_request('GET', url)
        return self._check_response(response)

    def get_tags_statistics(self, percentage=None, name_sort=None):
        """Get tags statistics from the MISP instance"""
        if percentage is not None:
            percentage = 'true'
        else:
            percentage = 'false'
        if name_sort is not None:
            name_sort = 'true'
        else:
            name_sort = 'false'
        url = urljoin(self.root_url, 'tags/tagStatistics/{}/{}'.format(percentage, name_sort))
        response = self.__prepare_request('GET', url)
        return self._check_response(response)

    # ############## Sightings ##################

    def sighting_per_id(self, attribute_id):
        """Add a sighting to an attribute (by attribute ID)"""
        url = urljoin(self.root_url, 'sightings/add/{}'.format(attribute_id))
        response = self.__prepare_request('POST', url)
        return self._check_response(response)

    def sighting_per_uuid(self, attribute_uuid):
        """Add a sighting to an attribute (by attribute UUID)"""
        url = urljoin(self.root_url, 'sightings/add/{}'.format(attribute_uuid))
        response = self.__prepare_request('POST', url)
        return self._check_response(response)

    def set_sightings(self, sightings):
        """Push a sighting (python dictionary)"""
        to_post = []
        if not isinstance(sightings, list):
            sightings = [sightings]
        for sighting in sightings:
            if isinstance(sighting, MISPSighting):
                to_post.append(sighting.to_json())
            elif isinstance(sighting, dict):
                to_post.append(json.dumps(sightings))
        url = urljoin(self.root_url, 'sightings/add/')
        response = self.__prepare_request('POST', url, json.dumps(to_post))
        return self._check_response(response)

    def sighting_per_json(self, json_file):
        """Push a sighting (JSON file)"""
        with open(json_file, 'r') as f:
            jdata = json.load(f)
            return self.set_sightings(jdata)

    def sighting(self, value, source=None, type=None, timestamp=None, **kwargs):
        """ Set a single sighting.
        :value: Value can either be the attribute's value (to update sighting on all the attributes with this value),
                or an UUID in order to update the sightings of one particular attribute.
        :source: Source of the sighting
        :type: Type of the sighting
        :timestamp: Timestamp associated to the sighting
        """
        s = MISPSighting()
        s.from_dict(value=value, source=source, type=type, timestamp=timestamp, **kwargs)
        return self.set_sightings(s)

    # ############## Sharing Groups ##################

    def get_sharing_groups(self):
        """Get the existing sharing groups"""
        url = urljoin(self.root_url, 'sharing_groups.json')
        response = self.__prepare_request('GET', url)
        return self._check_response(response)['response']

    # ############## Users ##################

    def get_users_list(self):
        url = urljoin(self.root_url, 'admin/users')
        response = self.__prepare_request('GET', url)
        return self._check_response(response)['response']

    def get_user(self, user_id):
        url = urljoin(self.root_url, 'admin/users/view/{}'.format(user_id))
        response = self.__prepare_request('GET', url)
        return self._check_response(response)

    def add_user(self, email, org_id, role_id, **kwargs):
        url = urljoin(self.root_url, 'admin/users/add/')
        new_user = MISPUser()
        new_user.from_dict(email=email, org_id=org_id, role_id=role_id, **kwargs)
        response = self.__prepare_request('POST', url, new_user.to_json())
        return self._check_response(response)

    def add_user_json(self, json_file):
        with open(json_file, 'r') as f:
            jdata = json.load(f)
        url = urljoin(self.root_url, 'admin/users/add/')
        response = self.__prepare_request('POST', url, json.dumps(jdata))
        return self._check_response(response)

    def get_user_fields_list(self):
        url = urljoin(self.root_url, 'admin/users/add/')
        response = self.__prepare_request('GET', url)
        return self._check_response(response)

    def edit_user(self, user_id, **kwargs):
        edit_user = MISPUser()
        edit_user.from_dict(**kwargs)
        url = urljoin(self.root_url, 'admin/users/edit/{}'.format(user_id))
        response = self.__prepare_request('POST', url, edit_user.to_json())
        return self._check_response(response)

    def edit_user_json(self, json_file, user_id):
        with open(json_file, 'r') as f:
            jdata = json.load(f)
        url = urljoin(self.root_url, 'admin/users/edit/{}'.format(user_id))
        response = self.__prepare_request('POST', url, json.dumps(jdata))
        return self._check_response(response)

    def delete_user(self, user_id):
        url = urljoin(self.root_url, 'admin/users/delete/{}'.format(user_id))
        response = self.__prepare_request('POST', url)
        return self._check_response(response)

    # ############## Organisations ##################

    def get_organisations_list(self, scope="local"):
        scope = scope.lower()
        if scope not in ["local", "external", "all"]:
            raise ValueError("Authorized fields are 'local','external' or 'all'")
        url = urljoin(self.root_url, 'organisations/index/scope:{}'.format(scope))
        response = self.__prepare_request('GET', url)
        return self._check_response(response)['response']

    def get_organisation(self, organisation_id):
        url = urljoin(self.root_url, 'organisations/view/{}'.format(organisation_id))
        response = self.__prepare_request('GET', url)
        return self._check_response(response)

    def add_organisation(self, name, **kwargs):
        new_org = MISPOrganisation()
        new_org.from_dict(name=name, **kwargs)
        if 'local' in new_org:
            if new_org.get('local') is False:
                if 'uuid' not in new_org:
                    raise PyMISPError('A remote org MUST have a valid uuid')
        url = urljoin(self.root_url, 'admin/organisations/add/')
        response = self.__prepare_request('POST', url, new_org.to_json())
        return self._check_response(response)

    def add_organisation_json(self, json_file):
        with open(json_file, 'r') as f:
            jdata = json.load(f)
        url = urljoin(self.root_url, 'admin/organisations/add/')
        response = self.__prepare_request('POST', url, json.dumps(jdata))
        return self._check_response(response)

    def get_organisation_fields_list(self):
        url = urljoin(self.root_url, 'admin/organisations/add/')
        response = self.__prepare_request('GET', url)
        return self._check_response(response)

    def edit_organisation(self, org_id, **kwargs):
        edit_org = MISPOrganisation()
        edit_org.from_dict(**kwargs)
        url = urljoin(self.root_url, 'admin/organisations/edit/{}'.format(org_id))
        response = self.__prepare_request('POST', url, edit_org.to_json())
        return self._check_response(response)

    def edit_organisation_json(self, json_file, org_id):
        with open(json_file, 'r') as f:
            jdata = json.load(f)
        url = urljoin(self.root_url, 'admin/organisations/edit/{}'.format(org_id))
        response = self.__prepare_request('POST', url, json.dumps(jdata))
        return self._check_response(response)

    def delete_organisation(self, org_id):
        url = urljoin(self.root_url, 'admin/organisations/delete/{}'.format(org_id))
        response = self.__prepare_request('POST', url)
        return self._check_response(response)

    # ############## Servers ##################

    def _set_server_organisation(self, server, organisation):
        if organisation is None:
            raise PyMISPError('Need a valid organisation as argument, create it before if needed')
        if 'Organisation' in organisation:
            organisation = organisation.get('Organisation')
        if 'local' not in organisation:
            raise PyMISPError('Need a valid organisation as argument. "local" value have not been set in this organisation')
        if 'id' not in organisation:
            raise PyMISPError('Need a valid organisation as argument. "id" value doesn\'t exist in provided organisation')

        if organisation.get('local'):  # Local organisation is '0' and remote organisation is '1'. These values are extracted from web interface of MISP
            organisation_type = 0
        else:
            organisation_type = 1
        server['organisation_type'] = organisation_type
        server['json'] = json.dumps({'id': organisation['id']})
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

    def add_server(self, url, name, authkey, organisation, internal=None, push=False,
                   pull=False, self_signed=False, push_rules="", pull_rules="",
                   submitted_cert=None, submitted_client_cert=None):
        new_server = self._set_server_parameters(url, name, authkey, organisation, internal,
                                                 push, pull, self_signed, push_rules, pull_rules, submitted_cert,
                                                 submitted_client_cert, None, None)
        url = urljoin(self.root_url, 'servers/add')
        response = self.__prepare_request('POST', url, json.dumps(new_server))
        return self._check_response(response)

    def add_server_json(self, json_file):
        with open(json_file, 'r') as f:
            jdata = json.load(f)
        url = urljoin(self.root_url, 'servers/add')
        response = self.__prepare_request('POST', url, json.dumps(jdata))
        return self._check_response(response)

    def edit_server(self, server_id, url=None, name=None, authkey=None, organisation=None, internal=None, push=False,
                    pull=False, self_signed=False, push_rules="", pull_rules="",
                    submitted_cert=None, submitted_client_cert=None, delete_cert=None, delete_client_cert=None):
        new_server = self._set_server_parameters(url, name, authkey, organisation, internal,
                                                 push, pull, self_signed, push_rules, pull_rules, submitted_cert,
                                                 submitted_client_cert, delete_cert, delete_client_cert)
        url = urljoin(self.root_url, 'servers/edit/{}'.format(server_id))
        response = self.__prepare_request('POST', url, json.dumps(new_server))
        return self._check_response(response)

    def edit_server_json(self, json_file, server_id):
        with open(json_file, 'r') as f:
            jdata = json.load(f)
        url = urljoin(self.root_url, 'servers/edit/{}'.format(server_id))
        response = self.__prepare_request('POST', url, json.dumps(jdata))
        return self._check_response(response)

    # ############## Roles ##################

    def get_roles_list(self):
        """Get the list of existing roles"""
        url = urljoin(self.root_url, '/roles')
        response = self.__prepare_request('GET', url)
        return self._check_response(response)['response']

    # ############## Tags ##################

    def get_tags_list(self):
        """Get the list of existing tags"""
        url = urljoin(self.root_url, '/tags')
        response = self.__prepare_request('GET', url)
        return self._check_response(response)['Tag']

    # ############## Taxonomies ##################

    def get_taxonomies_list(self):
        url = urljoin(self.root_url, '/taxonomies')
        response = self.__prepare_request('GET', url)
        return self._check_response(response)

    def get_taxonomy(self, taxonomy_id):
        url = urljoin(self.root_url, '/taxonomies/view/{}'.format(taxonomy_id))
        response = self.__prepare_request('GET', url)
        return self._check_response(response)

    # ##############################################
    # ############### Non-JSON output ##############
    # ##############################################

    # ############## Suricata ##############

    def download_all_suricata(self):
        """Download all suricata rules events."""
        url = urljoin(self.root_url, 'events/nids/suricata/download')
        response = self.__prepare_request('GET', url, output_type='rules')
        return response

    def download_suricata_rule_event(self, event_id):
        """Download one suricata rule event.

        :param event_id: ID of the event to download (same as get)
        """
        url = urljoin(self.root_url, 'events/nids/suricata/download/{}'.format(event_id))
        response = self.__prepare_request('GET', url, output_type='rules')
        return response

    # ############## Text ###############

    def get_all_attributes_txt(self, type_attr, tags=False, eventId=False, allowNonIDS=False, date_from=False, date_to=False, last=False, enforceWarninglist=False, allowNotPublished=False):
        """Get all attributes from a specific type as plain text. Only published and IDS flagged attributes are exported, except if stated otherwise."""
        url = urljoin(self.root_url, 'attributes/text/download/%s/%s/%s/%s/%s/%s/%s/%s/%s' % (type_attr, tags, eventId, allowNonIDS, date_from, date_to, last, enforceWarninglist, allowNotPublished))
        response = self.__prepare_request('GET', url, output_type='txt')
        return response

    # ############## STIX ##############

    def get_stix_event(self, event_id=None, with_attachments=False, from_date=False, to_date=False, tags=False):
        """Get an event/events in STIX format"""
        if tags:
            if isinstance(tags, list):
                tags = "&&".join(tags)
        url = urljoin(self.root_url, "/events/stix/download/{}/{}/{}/{}/{}".format(
            event_id, with_attachments, tags, from_date, to_date))
        logger.debug("Getting STIX event from %s", url)
        response = self.__prepare_request('GET', url)
        return self._check_response(response)

    def get_stix(self, **kwargs):
        return self.get_stix_event(**kwargs)

    def get_csv(self, eventid=None, attributes=[], object_attributes=[], misp_types=[], context=False, ignore=False, last=None):
        """Get MISP values in CSV format
        :param eventid: The event ID to query
        :param attributes: The column names to export from normal attributes (i.e. uuid, value, type, ...)
        :param object_attributes: The column names to export from attributes within objects (i.e. uuid, value, type, ...)
        :param misp_types: MISP types to get (i.e. ip-src, hostname, ...)
        :param context: Add event level context (event_info,event_member_org,event_source_org,event_distribution,event_threat_level_id,event_analysis,event_date,event_tag)
        :param ignore: Returns the attributes even if the event isn't published, or the attribute doesn't have the to_ids flag set
        """
        url = urljoin(self.root_url, '/events/csv/download')
        to_post = {}
        if eventid:
            to_post['eventid'] = eventid
        if attributes:
            to_post['attributes'] = attributes
        if object_attributes:
            to_post['object_attributes'] = object_attributes
        if misp_types:
            for t in misp_types:
                if t not in self.types:
                    logger.warning('{} is not a valid type'.format(t))
            to_post['type'] = misp_types
        if context:
            to_post['includeContext'] = True
        if ignore:
            to_post['ignore'] = True
        if last:
            to_post['last'] = last
        if to_post:
            response = self.__prepare_request('POST', url, json.dumps(to_post), output_type='json')
        else:
            response = self.__prepare_request('POST', url, output_type='json')
        return response.text

    # ###########################
    # ########   Feed   #########
    # ###########################

    def fetch_feed(self, feed_id):
        """Fetch one single feed"""
        url = urljoin(self.root_url, 'feeds/fetchFromFeed/{}'.format(feed_id))
        response = self.__prepare_request('GET', url)
        return self._check_response(response)

    def view_feeds(self):
        """Get the content of all the feeds"""
        url = urljoin(self.root_url, 'feeds')
        response = self.__prepare_request('GET', url)
        return self._check_response(response)

    def view_feed(self, feed_ids):
        """Get the content of a single feed"""
        url = urljoin(self.root_url, 'feeds/view/{}'.format(feed_ids))
        response = self.__prepare_request('GET', url)
        return self._check_response(response)

    def cache_feeds_all(self):
        """ Cache all the feeds"""
        url = urljoin(self.root_url, 'feeds/cacheFeeds/all')
        response = self.__prepare_request('GET', url)
        return self._check_response(response)

    def cache_feed(self, feed_id):
        """Cache a specific feed"""
        url = urljoin(self.root_url, 'feeds/cacheFeeds/{}'.format(feed_id))
        response = self.__prepare_request('GET', url)
        return self._check_response(response)

    def cache_feeds_freetext(self):
        """Cache all the freetext feeds"""
        url = urljoin(self.root_url, 'feeds/cacheFeeds/freetext')
        response = self.__prepare_request('GET', url)
        return self._check_response(response)

    def cache_feeds_misp(self):
        """Cache all the MISP feeds"""
        url = urljoin(self.root_url, 'feeds/cacheFeeds/misp')
        response = self.__prepare_request('GET', url)
        return self._check_response(response)

    def compare_feeds(self):
        """Generate the comparison matrix for all the MISP feeds"""
        url = urljoin(self.root_url, 'feeds/compareFeeds')
        response = self.__prepare_request('GET', url)
        return self._check_response(response)

    def cache_all_feeds(self):
        """Alias for cache_feeds_all"""
        # DEPRECATED
        return self.cache_feeds_all()

    # ###################
    # ###   Objects   ###
    # ###################

    def add_object(self, event_id, template_id, misp_object):
        """Add an object"""
        url = urljoin(self.root_url, 'objects/add/{}/{}'.format(event_id, template_id))
        response = self.__prepare_request('POST', url, misp_object.to_json())
        return self._check_response(response)

    def delete_object(self, id):
        """Deletes an object"""
        url = urljoin(self.root_url, 'objects/delete/{}'.format(id))
        response = self.__prepare_request('POST', url)
        return self._check_response(response)

    def add_object_reference(self, misp_object_reference):
        """Add a reference to an object"""
        url = urljoin(self.root_url, 'object_references/add')
        response = self.__prepare_request('POST', url, misp_object_reference.to_json())
        return self._check_response(response)

    def delete_object_reference(self, id):
        """Deletes a reference to an object"""
        url = urljoin(self.root_url, 'object_references/delete/{}'.format(id))
        response = self.__prepare_request('POST', url)
        return self._check_response(response)

    def get_object_templates_list(self):
        """Returns the list of Object templates available on the MISP instance"""
        url = urljoin(self.root_url, 'objectTemplates')
        response = self.__prepare_request('GET', url)
        return self._check_response(response)['response']

    def get_object_template_id(self, object_uuid):
        """Gets the template ID corresponting the UUID passed as parameter"""
        templates = self.get_object_templates_list()
        for t in templates:
            if t['ObjectTemplate']['uuid'] == object_uuid:
                return t['ObjectTemplate']['id']
        raise Exception('Unable to find template uuid {} on the MISP instance'.format(object_uuid))

    # ###########################
    # ####### Deprecated ########
    # ###########################

    @deprecated
    def add_tag(self, event, tag, attribute=False):
        if attribute:
            to_post = {'request': {'Attribute': {'id': event['id'], 'tag': tag}}}
            path = 'attributes/addTag'
        else:
            # Allow for backwards-compat with old style
            if "Event" in event:
                event = event["Event"]
            to_post = {'request': {'Event': {'id': event['id'], 'tag': tag}}}
            path = 'events/addTag'
        url = urljoin(self.root_url, path)
        response = self.__prepare_request('POST', url, json.dumps(to_post))
        return self._check_response(response)

    @deprecated
    def remove_tag(self, event, tag, attribute=False):
        if attribute:
            to_post = {'request': {'Attribute': {'id': event['id'], 'tag': tag}}}
            path = 'attributes/removeTag'
        else:
            to_post = {'request': {'Event': {'id': event['Event']['id'], 'tag': tag}}}
            path = 'events/removeTag'
        url = urljoin(self.root_url, path)
        response = self.__prepare_request('POST', url, json.dumps(to_post))
        return self._check_response(response)
