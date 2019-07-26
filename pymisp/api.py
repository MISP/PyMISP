
# -*- coding: utf-8 -*-

"""Python API using the REST interface of MISP"""

import copy
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
from deprecated import deprecated

from . import __version__, warning_2020
from .exceptions import PyMISPError, SearchError, NoURL, NoKey, PyMISPEmptyResponse
from .mispevent import MISPEvent, MISPAttribute, MISPUser, MISPOrganisation, MISPSighting, MISPFeed, MISPObject, MISPSharingGroup
from .abstract import AbstractMISP, MISPEncode

logger = logging.getLogger('pymisp')

try:
    from urllib.parse import urljoin
    # Least dirty way to support python 2 and 3
    basestring = str
    unicode = str
except ImportError:
    from urlparse import urljoin

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

if (3, 0) <= sys.version_info < (3, 6):
    OLD_PY3 = True
else:
    OLD_PY3 = False

try:
    from requests_futures.sessions import FuturesSession
    ASYNC_OK = True
except ImportError:
    ASYNC_OK = False

everything_broken = '''Unknown error: the response is not in JSON.
Something is broken server-side, please send us everything that follows (careful with the auth key):
Request headers:
{}
Request body:
{}
Response (if any):
{}'''


class PyMISP(object):  # pragma: no cover
    """Python API for MISP

    :param url: URL of the MISP instance you want to connect to
    :param key: API key of the user you want to use
    :param ssl: can be True or False (to check ot not the validity of the certificate. Or a CA_BUNDLE in case of self signed certificate (the concatenation of all the *.crt of the chain)
    :param out_type: Type of object (json) NOTE: XML output isn't supported anymore, keeping the flag for compatibility reasons.
    :param debug: Write all the debug information to stderr
    :param proxies: Proxy dict as describes here: http://docs.python-requests.org/en/master/user/advanced/#proxies
    :param cert: Client certificate, as described there: http://docs.python-requests.org/en/master/user/advanced/#client-side-certificates
    :param asynch: Use asynchronous processing where possible
    :param auth: The auth parameter is passed directly to requests, as described here: http://docs.python-requests.org/en/master/user/authentication/
    :param tool: The software using PyMISP (string), used to set a unique user-agent
    """

    warning_2020()

    @deprecated(reason="Please use ExpandedPyMISP instead (requires Python 3.6+). This class will be an alias of ExpandedPyMISP early 2020 and your code will most probably fail.")
    def __init__(self, url, key, ssl=True, out_type='json', debug=None, proxies=None, cert=None, asynch=False, auth=None, tool=None):
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
        self.auth = auth
        self.tool = tool
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

    @deprecated(reason="Use ExpandedPyMISP.remote_acl", version='2.4.111')
    def get_live_query_acl(self):
        """This should return an empty list, unless the ACL is outdated."""
        response = self._prepare_request('GET', urljoin(self.root_url, 'events/queryACL.json'))
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.describe_types_local", version='2.4.110')
    def get_local_describe_types(self):
        with open(os.path.join(self.resources_path, 'describeTypes.json'), 'rb') as f:
            if OLD_PY3:
                describe_types = json.loads(f.read().decode())
            else:
                describe_types = json.load(f)
        return describe_types['result']

    @deprecated(reason="Use ExpandedPyMISP.describe_types_remote", version='2.4.110')
    def get_live_describe_types(self):
        response = self._prepare_request('GET', urljoin(self.root_url, 'attributes/describeTypes.json'))
        describe_types = self._check_response(response)
        if describe_types.get('error'):
            for e in describe_types.get('error'):
                raise PyMISPError('Failed: {}'.format(e))
        describe_types = describe_types['result']
        if not describe_types.get('sane_defaults'):
            raise PyMISPError('The MISP server your are trying to reach is outdated (<2.4.52). Please use PyMISP v2.4.51.1 (pip install -I PyMISP==v2.4.51.1) and/or contact your administrator.')
        return describe_types

    def _prepare_request(self, request_type, url, data=None,
                         background_callback=None, output_type='json'):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug('{} - {}'.format(request_type, url))
            if data is not None:
                logger.debug(data)
        if data is None:
            req = requests.Request(request_type, url)
        else:
            if not isinstance(data, str):
                if isinstance(data, dict):
                    # Remove None values.
                    data = {k: v for k, v in data.items() if v is not None}
                data = json.dumps(data, cls=MISPEncode)
            req = requests.Request(request_type, url, data=data)
        if self.asynch and background_callback is not None:
            local_session = FuturesSession
        else:
            local_session = requests.Session
        with local_session() as s:
            ua_suffix = ''
            if self.tool:
                ua_suffix = ' - {}'.format(self.tool)
            req.auth = self.auth
            prepped = s.prepare_request(req)
            prepped.headers.update(
                {'Authorization': self.key,
                 'Accept': 'application/{}'.format(output_type),
                 'content-type': 'application/{}'.format(output_type),
                 'User-Agent': 'PyMISP {} - Python {}.{}.{}{}'.format(__version__, sys.version_info[0], sys.version_info[1], sys.version_info[2], ua_suffix)})
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(prepped.headers)
            settings = s.merge_environment_settings(req.url, proxies=self.proxies or {}, stream=None, verify=self.ssl, cert=self.cert)
            if self.asynch and background_callback is not None:
                return s.send(prepped, background_callback=background_callback, **settings)
            else:
                return s.send(prepped, **settings)

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

    def _check_response(self, response, lenient_response_type=False):
        """Check if the response from the server is not an unexpected error"""
        try:
            json_response = response.json()
        except ValueError:
            # If the server didn't return a JSON blob, we've a problem.
            if not len(response.text):
                raise PyMISPEmptyResponse('The server returned an empty response. \n{}\n{}\n'.format(response.request.headers, response.request.body))
            if lenient_response_type and not response.headers.get('content-type').startswith('application/json;'):
                return response.text
            else:
                raise PyMISPError(everything_broken.format(response.request.headers, response.request.body, response.text))

        errors = []

        if response.status_code >= 500:
            errors.append('500 exception: {}'.format(json_response))
            logger.critical(everything_broken.format(response.request.headers, response.request.body, json_response))

        to_return = json_response
        if isinstance(to_return, (list, str)):
            # FIXME: This case look like a bug.
            to_return = {'response': to_return}
        else:
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
            e.load(copy.copy(event))
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
        regex = re.compile(r'^[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z', re.I)
        match = regex.match(uuid)
        return bool(match)

    # ################################################
    # ############### Simple REST API ################
    # ################################################

    @deprecated(reason="Not used, open an issue if required.", version='2.4.110')
    def test_connection(self):
        """Test the auth key"""
        response = self.get_version()
        if response.get('errors'):
            raise PyMISPError(response.get('errors')[0])
        return True

    @deprecated(reason="Use ExpandedPyMISP.search_index")
    def get_index(self, filters=None):
        """Return the index.

        Warning, there's a limit on the number of results
        """
        url = urljoin(self.root_url, 'events/index')
        if filters is None:
            response = self._prepare_request('GET', url)
        else:
            response = self._prepare_request('POST', url, json.dumps(filters))
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.get_event")
    def get_event(self, event_id):
        """Get an event

        :param event_id: Event id to get
        """
        url = urljoin(self.root_url, 'events/{}'.format(event_id))
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.get_object")
    def get_object(self, obj_id):
        """Get an object

        :param obj_id: Object id to get
        """
        url = urljoin(self.root_url, 'objects/view/{}'.format(obj_id))
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.get_attribute")
    def get_attribute(self, att_id):
        """Get an attribute

        :param att_id: Attribute id to get
        """
        url = urljoin(self.root_url, 'attributes/view/{}'.format(att_id))
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.add_event")
    def add_event(self, event):
        """Add a new event

        :param event: Event as JSON object / string to add
        """
        url = urljoin(self.root_url, 'events')
        if isinstance(event, MISPEvent):
            event = event.to_json()
        elif not isinstance(event, basestring):
            event = json.dumps(event)
        response = self._prepare_request('POST', url, event)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.update_attribute")
    def update_attribute(self, attribute_id, attribute):
        """Update an attribute

        :param attribute_id: Attribute id/uuid to update
        :param attribute: Attribute as JSON object / string to add
        """
        url = urljoin(self.root_url, 'attributes/{}'.format(attribute_id))
        if isinstance(attribute, MISPAttribute):
            attribute = attribute.to_json()
        elif not isinstance(attribute, basestring):
            attribute = json.dumps(attribute)
        response = self._prepare_request('POST', url, attribute)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.update_event")
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
        response = self._prepare_request('POST', url, event)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.delete_event")
    def delete_event(self, event_id):
        """Delete an event

        :param event_id: Event id to delete
        """
        url = urljoin(self.root_url, 'events/{}'.format(event_id))
        response = self._prepare_request('DELETE', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.delete_attribute")
    def delete_attribute(self, attribute_id, hard_delete=False):
        """Delete an attribute by ID"""
        if hard_delete:
            url = urljoin(self.root_url, 'attributes/delete/{}/1'.format(attribute_id))
        else:
            url = urljoin(self.root_url, 'attributes/delete/{}'.format(attribute_id))
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.push_event_to_ZMQ")
    def pushEventToZMQ(self, event_id):
        """Force push an event on ZMQ"""
        url = urljoin(self.root_url, 'events/pushEventToZMQ/{}.json'.format(event_id))
        response = self._prepare_request('POST', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.direct_call")
    def direct_call(self, url, data=None):
        '''Very lightweight call that posts a data blob (python dictionary or json string) on the URL'''
        url = urljoin(self.root_url, url)
        if not data:
            response = self._prepare_request('GET', url)
        else:
            if isinstance(data, dict):
                data = json.dumps(data)
            response = self._prepare_request('POST', url, data)
        return self._check_response(response, lenient_response_type=True)

    # ##############################################
    # ############### Event handling ###############
    # ##############################################

    @deprecated(reason="Use ExpandedPyMISP.get_event")
    def get(self, eid):
        """Get an event by event ID"""
        return self.get_event(eid)

    @deprecated(reason="Use ExpandedPyMISP.update_event")
    def update(self, event):
        """Update an event by ID"""
        e = self._make_mispevent(event)
        if e.uuid:
            eid = e.uuid
        else:
            eid = e.id
        return self.update_event(eid, e)

    @deprecated(reason="Use ExpandedPyMISP.publish")
    def fast_publish(self, event_id, alert=False):
        """Does the same as the publish method, but just try to publish the event
        even with one single HTTP GET.
        The default is to not send a mail as it is assumed this method is called on update.
        """
        if not alert:
            url = urljoin(self.root_url, 'events/publish/{}'.format(event_id))
        else:
            url = urljoin(self.root_url, 'events/alert/{}'.format(event_id))
        response = self._prepare_request('POST', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.publish")
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

    @deprecated(reason="Use ExpandedPyMISP.update_event")
    def change_threat_level(self, event, threat_level_id):
        """Change the threat level of an event"""
        e = self._make_mispevent(event)
        e.threat_level_id = threat_level_id
        return self.update(e)

    @deprecated(reason="Use ExpandedPyMISP.update_event")
    def change_analysis_status(self, event, analysis_status):
        """Change the analysis status of an event"""
        e = self._make_mispevent(event)
        e.analysis = analysis_status
        return self.update(e)

    @deprecated(reason="Use ExpandedPyMISP.update_event")
    def change_distribution(self, event, distribution):
        """Change the distribution of an event"""
        e = self._make_mispevent(event)
        e.distribution = distribution
        return self.update(e)

    @deprecated(reason="Use ExpandedPyMISP.change_sharing_group_on_entity")
    def change_sharing_group(self, event, sharing_group_id):
        """Change the sharing group of an event"""
        e = self._make_mispevent(event)
        e.distribution = 4       # Needs to be 'Sharing group'
        if 'SharingGroup' in e:  # Delete former SharingGroup information
            del e.SharingGroup
        e.sharing_group_id = sharing_group_id  # Set new sharing group id
        return self.update(e)

    @deprecated(reason="Use ExpandedPyMISP.add_event")
    def new_event(self, distribution=None, threat_level_id=None, analysis=None, info=None, date=None, published=False, orgc_id=None, org_id=None, sharing_group_id=None):
        """Create and add a new event"""
        misp_event = self._prepare_full_event(distribution, threat_level_id, analysis, info, date, published, orgc_id, org_id, sharing_group_id)
        return self.add_event(misp_event)

    @deprecated(reason="Use ExpandedPyMISP.tag", version='2.4.111')
    def tag(self, uuid, tag):
        """Tag an event or an attribute"""
        if not self._valid_uuid(uuid):
            raise PyMISPError('Invalid UUID')
        url = urljoin(self.root_url, 'tags/attachTagToObject')
        to_post = {'uuid': uuid, 'tag': tag}
        response = self._prepare_request('POST', url, json.dumps(to_post))
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.untag", version='2.4.111')
    def untag(self, uuid, tag):
        """Untag an event or an attribute"""
        if not self._valid_uuid(uuid):
            raise PyMISPError('Invalid UUID')
        url = urljoin(self.root_url, 'tags/removeTagFromObject')
        to_post = {'uuid': uuid, 'tag': tag}
        response = self._prepare_request('POST', url, json.dumps(to_post))
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
            return [{'error': 'No attributes.'}]

        # Propals need to be posted in single requests
        if proposal:
            for a in attributes:
                # proposal_add(...) returns a dict
                responses.append(self.proposal_add(event_id, a))
        else:
            url = urljoin(self.root_url, 'attributes/add/{}'.format(event_id))
            if isinstance(attributes, list):
                if all(isinstance(a, AbstractMISP) for a in attributes):
                    data = attributes
                else:
                    values = []
                    for a in attributes:
                        values.append(a['value'])
                    attributes[0]['value'] = values
                    data = attributes[0].to_json()
            else:
                data = attributes.to_json()
            # _prepare_request(...) returns a requests.Response Object
            resp = self._prepare_request('POST', url, json.dumps(data, cls=MISPEncode))
            try:
                responses.append(resp.json())
            except Exception:
                # The response isn't a json object, appending the text.
                responses.append(resp.text)
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
        elif isinstance(event, int) or (isinstance(event, str) and (event.isdigit() or self._valid_uuid(event))):
            event_id = event
        else:
            if 'Event' in event:
                e = event['Event']
            else:
                e = event
            if 'id' in e:
                event_id = e['id']
            elif 'uuid' in e:
                event_id = e['uuid']
        return event_id

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_named_attribute(self, event, type_value, value, category=None, to_ids=False, comment=None, distribution=None, proposal=False, **kwargs):
        """Add one or more attributes to an existing event"""
        attributes = []
        for value in self._one_or_more(value):
            attributes.append(self._prepare_full_attribute(category, type_value, value, to_ids, comment, distribution, **kwargs))
        return self._send_attributes(event, attributes, proposal)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
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

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def av_detection_link(self, event, link, category='Antivirus detection', to_ids=False, comment=None, distribution=None, proposal=False, **kwargs):
        """Add AV detection link(s)"""
        return self.add_named_attribute(event, 'link', link, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_detection_name(self, event, name, category='Antivirus detection', to_ids=False, comment=None, distribution=None, proposal=False, **kwargs):
        """Add AV detection name(s)"""
        return self.add_named_attribute(event, 'text', name, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_filename(self, event, filename, category='Artifacts dropped', to_ids=False, comment=None, distribution=None, proposal=False, **kwargs):
        """Add filename(s)"""
        return self.add_named_attribute(event, 'filename', filename, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_attachment(self, event, attachment, category='Artifacts dropped', to_ids=False, comment=None, distribution=None, proposal=False, filename=None, **kwargs):
        """Add an attachment to the MISP event

        :param event: The event to add an attachment to
        :param attachment: Either a file handle or a path to a file - will be uploaded
        :param filename: Explicitly defined attachment filename
        """
        if isinstance(attachment, basestring) and os.path.isfile(attachment):
            # We have a file to open
            if filename is None:
                filename = os.path.basename(attachment)
            with open(attachment, "rb") as f:
                fileData = f.read()
        elif hasattr(attachment, "read"):
            # It's a file handle - we can read it but it has no filename
            fileData = attachment.read()
            if filename is None:
                filename = 'attachment'
        elif isinstance(attachment, (tuple, list)):
            # tuple/list (filename, pseudofile)
            if filename is None:
                filename = attachment[0]
            if hasattr(attachment[1], "read"):
                # Pseudo file
                fileData = attachment[1].read()
            else:
                fileData = attachment[1]
        else:
            # Plain file content, no filename
            if filename is None:
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

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
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

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
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

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_pattern(self, event, pattern, in_file=True, in_memory=False, category='Artifacts dropped', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add a pattern(s) in file or in memory"""
        if not (in_file or in_memory):
            raise PyMISPError('Invalid pattern type: please use in_memory=True or in_file=True')
        itemtype = 'pattern-in-file' if in_file else 'pattern-in-memory'
        return self.add_named_attribute(event, itemtype, pattern, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_pipe(self, event, named_pipe, category='Artifacts dropped', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add pipes(s)"""
        def scrub(s):
            if not s.startswith('\\.\\pipe\\'):
                s = '\\.\\pipe\\{}'.format(s)
            return s
        attributes = list(map(scrub, self._one_or_more(named_pipe)))
        return self.add_named_attribute(event, 'named pipe', attributes, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_mutex(self, event, mutex, category='Artifacts dropped', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add mutex(es)"""
        def scrub(s):
            if not s.startswith('\\BaseNamedObjects\\'):
                s = '\\BaseNamedObjects\\{}'.format(s)
            return s
        attributes = list(map(scrub, self._one_or_more(mutex)))
        return self.add_named_attribute(event, 'mutex', attributes, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_yara(self, event, yara, category='Payload delivery', to_ids=False, comment=None, distribution=None, proposal=False, **kwargs):
        """Add yara rule(es)"""
        return self.add_named_attribute(event, 'yara', yara, category, to_ids, comment, distribution, proposal, **kwargs)

    # ##### Network attributes #####

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_ipdst(self, event, ipdst, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add destination IP(s)"""
        return self.add_named_attribute(event, 'ip-dst', ipdst, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_ipsrc(self, event, ipsrc, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add source IP(s)"""
        return self.add_named_attribute(event, 'ip-src', ipsrc, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_hostname(self, event, hostname, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add hostname(s)"""
        return self.add_named_attribute(event, 'hostname', hostname, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_domain(self, event, domain, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add domain(s)"""
        return self.add_named_attribute(event, 'domain', domain, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_domain_ip(self, event, domain, ip, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add domain|ip"""
        if isinstance(ip, str):
            ip = [ip]
        composed = list(map(lambda x: '%s|%s' % (domain, x), ip))
        return self.add_named_attribute(event, 'domain|ip', composed, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_domains_ips(self, event, domain_ips, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add multiple domain|ip"""
        composed = list(map(lambda x: '%s|%s' % (x[0], x[1]), domain_ips.items()))
        return self.add_named_attribute(event, 'domain|ip', composed, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_url(self, event, url, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add url(s)"""
        return self.add_named_attribute(event, 'url', url, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_useragent(self, event, useragent, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add user agent(s)"""
        return self.add_named_attribute(event, 'user-agent', useragent, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_traffic_pattern(self, event, pattern, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add pattern(s) in traffic"""
        return self.add_named_attribute(event, 'pattern-in-traffic', pattern, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_snort(self, event, snort, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add SNORT rule(s)"""
        return self.add_named_attribute(event, 'snort', snort, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_asn(self, event, asn, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add network ASN"""
        return self.add_named_attribute(event, 'AS', asn, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_net_other(self, event, netother, category='Network activity', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add a free text entry"""
        return self.add_named_attribute(event, 'other', netother, category, to_ids, comment, distribution, proposal, **kwargs)

    # ##### Email attributes #####

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_email_src(self, event, email, category='Payload delivery', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add a source email"""
        return self.add_named_attribute(event, 'email-src', email, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_email_dst(self, event, email, category='Payload delivery', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add a destination email"""
        return self.add_named_attribute(event, 'email-dst', email, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_email_subject(self, event, email, category='Payload delivery', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an email subject"""
        return self.add_named_attribute(event, 'email-subject', email, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_email_attachment(self, event, email, category='Payload delivery', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an email atachment"""
        return self.add_named_attribute(event, 'email-attachment', email, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_email_header(self, event, email, category='Payload delivery', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an email header"""
        return self.add_named_attribute(event, 'email-header', email, category, to_ids, comment, distribution, proposal, **kwargs)

    # ##### Target attributes #####

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_target_email(self, event, target, category='Targeting data', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an target email"""
        return self.add_named_attribute(event, 'target-email', target, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_target_user(self, event, target, category='Targeting data', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an target user"""
        return self.add_named_attribute(event, 'target-user', target, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_target_machine(self, event, target, category='Targeting data', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an target machine"""
        return self.add_named_attribute(event, 'target-machine', target, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_target_org(self, event, target, category='Targeting data', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an target organisation"""
        return self.add_named_attribute(event, 'target-org', target, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_target_location(self, event, target, category='Targeting data', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an target location"""
        return self.add_named_attribute(event, 'target-location', target, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_target_external(self, event, target, category='Targeting data', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an target external"""
        return self.add_named_attribute(event, 'target-external', target, category, to_ids, comment, distribution, proposal, **kwargs)

    # ##### Attribution attributes #####

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_threat_actor(self, event, target, category='Attribution', to_ids=True, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an threat actor"""
        return self.add_named_attribute(event, 'threat-actor', target, category, to_ids, comment, distribution, proposal, **kwargs)

    # ##### Internal reference attributes #####

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_internal_link(self, event, reference, category='Internal reference', to_ids=False, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an internal link"""
        return self.add_named_attribute(event, 'link', reference, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_internal_comment(self, event, reference, category='Internal reference', to_ids=False, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an internal comment"""
        return self.add_named_attribute(event, 'comment', reference, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_internal_text(self, event, reference, category='Internal reference', to_ids=False, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an internal text"""
        return self.add_named_attribute(event, 'text', reference, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_internal_other(self, event, reference, category='Internal reference', to_ids=False, comment=None, distribution=None, proposal=False, **kwargs):
        """Add an internal reference (type other)"""
        return self.add_named_attribute(event, 'other', reference, category, to_ids, comment, distribution, proposal, **kwargs)

    # ##### Other attributes #####

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_other_comment(self, event, reference, category='Other', to_ids=False, comment=None, distribution=None, proposal=False, **kwargs):
        """Add other comment"""
        return self.add_named_attribute(event, 'comment', reference, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_other_counter(self, event, reference, category='Other', to_ids=False, comment=None, distribution=None, proposal=False, **kwargs):
        """Add other counter"""
        return self.add_named_attribute(event, 'counter', reference, category, to_ids, comment, distribution, proposal, **kwargs)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute and MISPAttribute")
    def add_other_text(self, event, reference, category='Other', to_ids=False, comment=None, distribution=None, proposal=False, **kwargs):
        """Add other text"""
        return self.add_named_attribute(event, 'text', reference, category, to_ids, comment, distribution, proposal, **kwargs)

    # ##################################################
    # ######### Upload samples through the API #########
    # ##################################################

    def _prepare_upload(self, event_id, distribution, to_ids, category, comment, info,
                        analysis, threat_level_id, advanced_extraction):
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
        to_post['request']['advanced'] = 1 if advanced_extraction else 0
        return to_post, event_id

    def _encode_file_to_upload(self, filepath_or_bytes):
        """Helper to encode a file to upload"""
        if isinstance(filepath_or_bytes, basestring):
            if os.path.isfile(filepath_or_bytes):
                with open(filepath_or_bytes, 'rb') as f:
                    binblob = f.read()
            else:
                binblob = filepath_or_bytes.encode()
        else:
            binblob = filepath_or_bytes
        return base64.b64encode(binblob).decode()

    @deprecated(reason="Use MISPEvent.add_attribute with the expand='binary' key")
    def upload_sample(self, filename, filepath_or_bytes, event_id, distribution=None,
                      to_ids=True, category=None, comment=None, info=None,
                      analysis=None, threat_level_id=None, advanced_extraction=False):
        """Upload a sample"""
        to_post, event_id = self._prepare_upload(event_id, distribution, to_ids, category,
                                                 comment, info, analysis, threat_level_id,
                                                 advanced_extraction)
        to_post['request']['files'] = [{'filename': filename, 'data': self._encode_file_to_upload(filepath_or_bytes)}]
        return self._upload_sample(to_post, event_id)

    @deprecated(reason="Use MISPEvent.add_attribute with the expand='binary' key")
    def upload_samplelist(self, filepaths, event_id, distribution=None,
                          to_ids=True, category=None, comment=None, info=None,
                          analysis=None, threat_level_id=None, advanced_extraction=False):
        """Upload a list of samples"""
        to_post, event_id = self._prepare_upload(event_id, distribution, to_ids, category,
                                                 comment, info, analysis, threat_level_id,
                                                 advanced_extraction)
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
        response = self._prepare_request('POST', url, json.dumps(to_post))
        return self._check_response(response)

    # ############################
    # ######## Proposals #########
    # ############################

    def __query_proposal(self, path, id, attribute=None):
        """Helper to prepare a query to handle proposals"""
        url = urljoin(self.root_url, 'shadow_attributes/{}/{}'.format(path, id))
        if path in ['add', 'edit']:
            query = {'request': {'ShadowAttribute': attribute}}
            response = self._prepare_request('POST', url, json.dumps(query, cls=MISPEncode))
        elif path == 'view':
            response = self._prepare_request('GET', url)
        else:  # accept or discard
            response = self._prepare_request('POST', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.attribute_proposals", version='2.4.111')
    def proposal_index(self, timestamp=0):
        return self.__query_proposal('index', 'all:1/timestamp:{}'.format(timestamp))

    @deprecated(reason="Use ExpandedPyMISP.get_attribute_proposal", version='2.4.111')
    def proposal_view(self, event_id=None, proposal_id=None):
        """View a proposal"""
        if proposal_id is not None and event_id is not None:
            return {'error': 'You can only view an event ID or a proposal ID'}
        if event_id is not None:
            id = event_id
        else:
            id = proposal_id
        return self.__query_proposal('view', id)

    @deprecated(reason="Use ExpandedPyMISP.add_attribute_proposal", version='2.4.111')
    def proposal_add(self, event_id, attribute):
        """Add a proposal"""
        return self.__query_proposal('add', event_id, attribute)

    @deprecated(reason="Use ExpandedPyMISP.update_attribute_proposal", version='2.4.111')
    def proposal_edit(self, attribute_id, attribute):
        """Edit a proposal"""
        return self.__query_proposal('edit', attribute_id, attribute)

    @deprecated(reason="Use ExpandedPyMISP.accept_attribute_proposal", version='2.4.111')
    def proposal_accept(self, proposal_id):
        """Accept a proposal"""
        return self.__query_proposal('accept', proposal_id)

    @deprecated(reason="Use ExpandedPyMISP.discard_attribute_proposal", version='2.4.111')
    def proposal_discard(self, proposal_id):
        """Discard a proposal"""
        return self.__query_proposal('discard', proposal_id)

    # ##############################
    # ###### Attribute update ######
    # ##############################

    @deprecated(reason="Use ExpandedPyMISP.update_attribute and MISPAttribute")
    def change_toids(self, attribute_uuid, to_ids):
        """Change the toids flag"""
        if to_ids not in [0, 1]:
            raise Exception('to_ids can only be 0 or 1')
        query = {"to_ids": to_ids}
        return self.__query('edit/{}'.format(attribute_uuid), query, controller='attributes')

    @deprecated(reason="Use ExpandedPyMISP.update_attribute and MISPAttribute")
    def change_comment(self, attribute_uuid, comment):
        """Change the comment of attribute"""
        query = {"comment": comment}
        return self.__query('edit/{}'.format(attribute_uuid), query, controller='attributes')

    @deprecated(reason="Use ExpandedPyMISP.update_attribute and MISPAttribute")
    def change_disable_correlation(self, attribute_uuid, disable_correlation):
        """Change the disable_correlation flag"""
        possible_values = [0, 1, False, True]
        if disable_correlation not in possible_values:
            raise Exception('disable_correlation can only be in {}'.format(', '.join(possible_values)))
        query = {"disable_correlation": disable_correlation}
        return self.__query('edit/{}'.format(attribute_uuid), query, controller='attributes')

    # ##############################
    # ###### Attribute update ######
    # ##############################

    @deprecated(reason="Use ExpandedPyMISP.freetext", version='2.4.111')
    def freetext(self, event_id, string, adhereToWarninglists=False, distribution=None, returnMetaAttributes=False):
        """Pass a text to the freetext importer"""
        query = {"value": string}
        wl_params = [False, True, 'soft']
        if adhereToWarninglists not in wl_params:
            raise Exception('Invalid parameter, adhereToWarninglists Can only be {}'.format(', '.join(wl_params)))
        if adhereToWarninglists:
            query['adhereToWarninglists'] = adhereToWarninglists
        if distribution is not None:
            query['distribution'] = distribution
        if returnMetaAttributes:
            query['returnMetaAttributes'] = returnMetaAttributes
        return self.__query('freeTextImport/{}'.format(event_id), query, controller='events')

    # ##############################
    # ######## REST Search #########
    # ##############################

    def __query(self, path, query, controller='events', async_callback=None):
        """Helper to prepare a search query"""
        if query.get('error') is not None:
            return query
        if controller not in ['events', 'attributes', 'objects', 'sightings']:
            raise ValueError('Invalid controller. Can only be {}'.format(', '.join(['events', 'attributes', 'objects', 'sightings'])))
        url = urljoin(self.root_url, '{}/{}'.format(controller, path.lstrip('/')))

        if ASYNC_OK and async_callback:
            response = self._prepare_request('POST', url, json.dumps(query), async_callback)
        else:
            response = self._prepare_request('POST', url, json.dumps(query))
            return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.search_index", version='2.4.111')
    def search_index(self, published=None, eventid=None, tag=None, datefrom=None,
                     dateuntil=None, eventinfo=None, threatlevel=None, distribution=None,
                     analysis=None, attribute=None, org=None, async_callback=None, normalize=False,
                     timestamp=None, sharinggroup=None):
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
        :param timestamp: Interval since last update (in second, or 1d, 1h, ...)
        :param sharinggroup: The sharing group value
        """
        allowed = {'published': published, 'eventid': eventid, 'tag': tag, 'dateuntil': dateuntil,
                   'datefrom': datefrom, 'eventinfo': eventinfo, 'threatlevel': threatlevel,
                   'distribution': distribution, 'analysis': analysis, 'attribute': attribute,
                   'org': org, 'timestamp': timestamp, 'sharinggroup': sharinggroup}
        rule_levels = {'distribution': ["0", "1", "2", "3", "!0", "!1", "!2", "!3"],
                       'threatlevel': ["1", "2", "3", "4", "!1", "!2", "!3", "!4"],
                       'analysis': ["0", "1", "2", "!0", "!1", "!2"]}
        buildup_url = "events/index"

        to_post = {}
        for rule in allowed.keys():

            if allowed.get(rule) is None:
                continue
            param = allowed[rule]
            if isinstance(param, bool):
                param = int(param)
            if not isinstance(param, list):
                param = [param]
            # param = [x for x in map(str, param)]
            if rule in rule_levels:
                if not set(param).issubset(rule_levels[rule]):
                    raise SearchError('Values in your {} are invalid, has to be in {}'.format(rule, ', '.join(str(x) for x in rule_levels[rule])))
            to_post[rule] = '|'.join(str(x) for x in param)
        url = urljoin(self.root_url, buildup_url)

        if self.asynch and async_callback:
            response = self._prepare_request('POST', url, json.dumps(to_post), async_callback)
        else:
            response = self._prepare_request('POST', url, json.dumps(to_post))
            res = self._check_response(response)
            if normalize:
                to_return = {'response': []}
                for elem in res['response']:
                    tmp = {'Event': elem}
                    to_return['response'].append(tmp)
                res = to_return
            return res

    @deprecated(reason="Use ExpandedPyMISP.search", version='2.4.111')
    def search_all(self, value):
        """Search a value in the whole database"""
        query = {'value': value, 'searchall': 1}
        return self.__query('restSearch', query)

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

    @deprecated(reason="Use ExpandedPyMISP.search", version='2.4.111')
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
        :param eventid: Evend ID(s) | str or list
        :param withAttachments: return events with or without the attachments
        :param uuid: search by uuid
        :param publish_timestamp: the publish timestamp
        :param timestamp: the timestamp of the last modification. Can be a list (from->to)
        :param enforceWarninglist: Enforce the warning lists
        :param includeWarninglistHits: Include the warning list hits
        :param searchall: full text search on the database
        :param metadata: return only metadata if True
        :param published: return only published events
        :param to_ids: return only the attributes with the to_ids flag set
        :param deleted: also return the deleted attributes
        :param event_timestamp: the timestamp of the last modification of the event (attributes controller only)). Can be a list (from->to)
        :param includeProposals: return shadow attributes if True
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

        returnFormat = kwargs.pop('returnFormat', None)
        if returnFormat:
            if returnFormat in ['json', 'openioc', 'xml', 'suricata', 'snort', 'text', 'rpz', 'csv', 'cache', 'stix', 'stix2']:
                query['returnFormat'] = returnFormat
            else:
                return {'error': 'You must enter a valid returnFormat - json, openioc, xml, suricata, snort, text, rpz, csv, stix, stix2 or cache'}
        else:
            query['returnFormat'] = 'json'

        query['publish_timestamp'] = kwargs.pop('publish_timestamp', None)
        query['timestamp'] = kwargs.pop('timestamp', None)
        query['enforceWarninglist'] = kwargs.pop('enforceWarninglist', None)
        query['includeWarninglistHits'] = kwargs.pop('includeWarninglistHits', None)
        query['to_ids'] = kwargs.pop('to_ids', None)
        query['deleted'] = kwargs.pop('deleted', None)
        query['published'] = kwargs.pop('published', None)

        if controller == 'events':
            # Event search only:
            query['searchall'] = kwargs.pop('searchall', None)
            query['metadata'] = kwargs.pop('metadata', None)
        if controller == 'attributes':
            query['event_timestamp'] = kwargs.pop('event_timestamp', None)
            query['includeProposals'] = kwargs.pop('includeProposals', None)

        if kwargs:
            logger.info('Some unknown parameters are in kwargs. appending as-is: {}'.format(', '.join(kwargs.keys())))
            # Add all other keys as-is.
            query.update({k: v for k, v in kwargs.items()})

        # Cleanup
        query = {k: v for k, v in query.items() if v is not None}

        # Create a session, make it async if and only if we have a callback
        return self.__query('restSearch', query, controller, async_callback)

    @deprecated(reason="Use ExpandedPyMISP.get_attribute", version='2.4.111')
    def get_attachment(self, attribute_id):
        """Get an attachement (not a malware sample) by attribute ID.
        Returns the attachment as a bytestream, or a dictionary containing the error message.

        :param attribute_id: Attribute ID to fetched
        """
        url = urljoin(self.root_url, 'attributes/download/{}'.format(attribute_id))
        response = self._prepare_request('GET', url)
        try:
            response.json()
            # The query fails, response contains a json blob
            return self._check_response(response)
        except ValueError:
            # content contains the attachment in binary
            return response.content

    @deprecated(reason="Use ExpandedPyMISP.search", version='2.4.111')
    def get_yara(self, event_id):
        """Get the yara rules from an event"""
        url = urljoin(self.root_url, 'attributes/restSearch')
        to_post = {'request': {'eventid': event_id, 'type': 'yara'}}
        response = self._prepare_request('POST', url, data=json.dumps(to_post))
        result = self._check_response(response)
        if result.get('error') is not None:
            return False, result.get('error')
        if not result.get('response'):
            return False, result.get('message')
        rules = '\n\n'.join([a['value'] for a in result['response']['Attribute']])
        return True, rules

    @deprecated(reason="Use ExpandedPyMISP.search. Open an issue if needed.", version='2.4.111')
    def download_samples(self, sample_hash=None, event_id=None, all_samples=False, unzip=True):
        """Download samples, by hash or event ID. If there are multiple samples in one event, use the all_samples switch

        :param sample_hash: hash of sample
        :param event_id: ID of event
        :param all_samples: download all samples
        :param unzip: whether to unzip or keep zipped
        :return: A tuple with (success, [[event_id, sample_hash, sample_as_bytesio], [event_id,...]])
                 In case of legacy sample, the sample_hash will be replaced by the zip's filename
        """
        url = urljoin(self.root_url, 'attributes/downloadSample')
        to_post = {'request': {'hash': sample_hash, 'eventID': event_id, 'allSamples': all_samples}}
        response = self._prepare_request('POST', url, data=json.dumps(to_post))
        result = self._check_response(response)
        if result.get('error') is not None:
            return False, result.get('error')
        if not result.get('result'):
            return False, result.get('message')
        details = []
        for f in result['result']:
            decoded = base64.b64decode(f['base64'])
            zipped = BytesIO(decoded)
            if unzip:
                try:
                    archive = zipfile.ZipFile(zipped)
                    if f.get('md5') and f['md5'] in archive.namelist():
                        # New format
                        unzipped = BytesIO(archive.open(f['md5'], pwd=b'infected').read())
                        details.append([f['event_id'], f['md5'], unzipped])
                    else:
                        # Old format
                        unzipped = BytesIO(archive.open(f['filename'], pwd=b'infected').read())
                        details.append([f['event_id'], f['filename'], unzipped])
                except zipfile.BadZipfile:
                    # In case the sample isn't zipped
                    details.append([f['event_id'], f['filename'], zipped])
            else:
                details.append([f['event_id'], "{0}.zip".format(f['filename']), zipped])
        return True, details

    @deprecated(reason="Use ExpandedPyMISP.search", version='2.4.111')
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

    @deprecated(reason="Use ExpandedPyMISP.search", version='2.4.111')
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

    @deprecated(reason="Use ExpandedPyMISP.tags", version='2.4.111')
    def get_all_tags(self, quiet=False):
        """Get all the tags used on the instance"""
        url = urljoin(self.root_url, 'tags')
        response = self._prepare_request('GET', url)
        r = self._check_response(response)
        if not quiet or r.get('errors'):
            return r
        else:
            to_return = []
            for tag in r['Tag']:
                to_return.append(tag['name'])
            return to_return

    @deprecated(reason="Use ExpandedPyMISP.add_tag", version='2.4.111')
    def new_tag(self, name=None, colour="#00ace6", exportable=False, hide_tag=False):
        """Create a new tag"""
        to_post = {'Tag': {'name': name, 'colour': colour, 'exportable': exportable, 'hide_tag': hide_tag}}
        url = urljoin(self.root_url, 'tags/add')
        response = self._prepare_request('POST', url, json.dumps(to_post))
        return self._check_response(response)

    # ########## Version ##########

    @deprecated(reason="Use ExpandedPyMISP.version", version='2.4.110')
    def get_api_version(self):
        """Returns the current version of PyMISP installed on the system"""
        return {'version': __version__}

    @deprecated(reason="Use ExpandedPyMISP.pymisp_version_master", version='2.4.110')
    def get_api_version_master(self):
        """Get the most recent version of PyMISP from github"""
        r = requests.get('https://raw.githubusercontent.com/MISP/PyMISP/master/pymisp/__init__.py')
        if r.status_code == 200:
            version = re.findall("__version__ = '(.*)'", r.text)
            return {'version': version[0]}
        else:
            return {'error': 'Impossible to retrieve the version of the master branch.'}

    @deprecated(reason="Use ExpandedPyMISP.recommended_pymisp_version", version='2.4.110')
    def get_recommended_api_version(self):
        """Returns the recommended API version from the server"""
        url = urljoin(self.root_url, 'servers/getPyMISPVersion.json')
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.misp_instance_version", version='2.4.110')
    def get_version(self):
        """Returns the version of the instance."""
        url = urljoin(self.root_url, 'servers/getVersion.json')
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.misp_instance_version_master", version='2.4.110')
    def get_version_master(self):
        """Get the most recent version from github"""
        r = requests.get('https://raw.githubusercontent.com/MISP/MISP/2.4/VERSION.json')
        if r.status_code == 200:
            master_version = json.loads(r.text)
            return {'version': '{}.{}.{}'.format(master_version['major'], master_version['minor'], master_version['hotfix'])}
        else:
            return {'error': 'Impossible to retrieve the version of the master branch.'}

    # ############## Statistics ##################

    @deprecated(reason="Use ExpandedPyMISP.attributes_statistics", version='2.4.110')
    def get_attributes_statistics(self, context='type', percentage=None):
        """Get attributes statistics from the MISP instance"""
        if (context != 'category'):
            context = 'type'
        if percentage is not None:
            url = urljoin(self.root_url, 'attributes/attributeStatistics/{}/{}'.format(context, percentage))
        else:
            url = urljoin(self.root_url, 'attributes/attributeStatistics/{}'.format(context))
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.tags_statistics", version='2.4.110')
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
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.users_statistics", version='2.4.110')
    def get_users_statistics(self, context='data'):
        """Get users statistics from the MISP instance"""
        availables_contexts = ['data', 'orgs', 'users', 'tags', 'attributehistogram', 'sightings', 'attackMatrix']
        if context not in availables_contexts:
            context = 'data'
        url = urljoin(self.root_url, 'users/statistics/{}.json'.format(context))
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    # ############## Sightings ##################

    @deprecated(reason="Use ExpandedPyMISP.add_sighting", version='2.4.110')
    def sighting_per_id(self, attribute_id):
        """Add a sighting to an attribute (by attribute ID)"""
        url = urljoin(self.root_url, 'sightings/add/{}'.format(attribute_id))
        response = self._prepare_request('POST', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.add_sighting", version='2.4.110')
    def sighting_per_uuid(self, attribute_uuid):
        """Add a sighting to an attribute (by attribute UUID)"""
        url = urljoin(self.root_url, 'sightings/add/{}'.format(attribute_uuid))
        response = self._prepare_request('POST', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.add_sighting", version='2.4.110')
    def set_sightings(self, sightings):
        """Push a sighting (python dictionary or MISPSighting) or a list of sightings"""
        if not isinstance(sightings, list):
            sightings = [sightings]
        for sighting in sightings:
            if isinstance(sighting, MISPSighting):
                to_post = sighting.to_json()
            elif isinstance(sighting, dict):
                to_post = json.dumps(sighting)
            url = urljoin(self.root_url, 'sightings/add/')
            response = self._prepare_request('POST', url, to_post)
        return self._check_response(response)

    @deprecated(reason="Not used, open an issue if required.", version='2.4.110')
    def sighting_per_json(self, json_file):
        """Push a sighting (JSON file)"""
        with open(json_file, 'rb') as f:
            jdata = json.load(f)
            return self.set_sightings(jdata)

    @deprecated(reason="Use ExpandedPyMISP.add_sighting", version='2.4.110')
    def sighting(self, value=None, uuid=None, id=None, source=None, type=None, timestamp=None, **kwargs):
        """ Set a single sighting.
        :value: Value of the attribute the sighting is related too. Pushing this object
                will update the sighting count of each attriutes with thifs value on the instance
        :uuid: UUID of the attribute to update
        :id: ID of the attribute to update
        :source: Source of the sighting
        :type: Type of the sighting
        :timestamp: Timestamp associated to the sighting
        """
        s = MISPSighting()
        s.from_dict(value=value, uuid=uuid, id=id, source=source, type=type, timestamp=timestamp, **kwargs)
        return self.set_sightings(s)

    @deprecated(reason="Use ExpandedPyMISP.sightings", version='2.4.110')
    def sighting_list(self, element_id, scope="attribute", org_id=False):
        """Get the list of sighting.
        :param element_id: could be an event id or attribute id
        :type element_id: int
        :param scope: could be attribute or event
        :return: A json list of sighting corresponding to the search
        :rtype: dict

        :Example:

        >>> misp.sighting_list(4731) # default search on attribute
        [ ... ]
        >>> misp.sighting_list(42, event) # return list of sighting for event 42
        [ ... ]
        >>> misp.sighting_list(element_id=42, org_id=2, scope=event) # return list of sighting for event 42 filtered with org id 2
        """
        if isinstance(element_id, int) is False:
            raise Exception('Invalid parameter, element_id must be a number')
        if scope not in ["attribute", "event"]:
            raise Exception('scope parameter must be "attribute" or "event"')
        if org_id is not False:
            if isinstance(org_id, int) is False:
                raise Exception('Invalid parameter, org_id must be a number')
        else:
            org_id = ""
        uri = 'sightings/listSightings/{}/{}/{}'.format(element_id, scope, org_id)
        url = urljoin(self.root_url, uri)
        response = self._prepare_request('POST', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.search_sightings", version='2.4.110')
    def search_sightings(self, context='', async_callback=None, **kwargs):
        """Search sightings via the REST API
        :context: The context of the search, could be attribute, event or False
        :param context_id: ID of the attribute or event if context is specified
        :param type_sighting: Type of the sighting
        :param date_from: From date
        :param date_to: To date
        :param publish_timestamp: Last published sighting (e.g. 5m, 3h, 7d)
        :param org_id: The org_id
        :param source: The source of the sighting
        :param include_attribute: Should the result include attribute data
        :param include_event: Should the result include event data
        :param async_callback: The function to run when results are returned

        :Example:

        >>> misp.search_sightings(**{'publish_timestamp': '30d'}) # search sightings for the last 30 days on the instance
        [ ... ]
        >>> misp.search_sightings('attribute', context_id=6, include_attribute=1) # return list of sighting for attribute 6 along with the attribute itself
        [ ... ]
        >>> misp.search_sightings('event', **{'context_id': 17, 'include_event': 1, 'org_id': 2}) # return list of sighting for event 17 filtered with org id 2
        """
        if context not in ['', 'attribute', 'event']:
            raise Exception('Context parameter must be empty, "attribute" or "event"')
        query = {}
        # Sighting: array('id', 'type', 'from', 'to', 'last', 'org_id', 'includeAttribute', 'includeEvent');
        query['returnFormat'] = kwargs.pop('returnFormat', 'json')
        query['id'] = kwargs.pop('context_id', None)
        query['type'] = kwargs.pop('type_sighting', None)
        query['from'] = kwargs.pop('date_from', None)
        query['to'] = kwargs.pop('date_to', None)
        query['last'] = kwargs.pop('publish_timestamp', None)
        query['org_id'] = kwargs.pop('org_id', None)
        query['source'] = kwargs.pop('source', None)
        query['includeAttribute'] = kwargs.pop('include_attribute', None)
        query['includeEvent'] = kwargs.pop('include_event', None)

        # Cleanup
        query = {k: v for k, v in query.items() if v is not None}

        if kwargs:
            raise SearchError('Unused parameter: {}'.format(', '.join(kwargs.keys())))

        # Create a session, make it async if and only if we have a callback
        controller = 'sightings'
        return self.__query('restSearch/' + context, query, controller, async_callback)

    # ############## Sharing Groups ##################

    @deprecated(reason="Use ExpandedPyMISP.sharing_groups", version='2.4.110')
    def get_sharing_groups(self):
        """Get the existing sharing groups"""
        url = urljoin(self.root_url, 'sharing_groups.json')
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    # ############## Users ##################

    @deprecated(reason="Use ExpandedPyMISP.users", version='2.4.110')
    def get_users_list(self):
        return self._rest_list('admin/users')

    @deprecated(reason="Use ExpandedPyMISP.get_user", version='2.4.110')
    def get_user(self, user_id='me'):
        return self._rest_view('users', user_id)

    @deprecated(reason="Use ExpandedPyMISP.add_user", version='2.4.110')
    def add_user(self, email, org_id=None, role_id=None, **kwargs):
        if isinstance(email, MISPUser):
            # Very dirty, allow to call that from ExpandedPyMISP
            new_user = email
        else:
            new_user = MISPUser()
            new_user.from_dict(email=email, org_id=org_id, role_id=role_id, **kwargs)
        return self._rest_add('admin/users', new_user)

    @deprecated(reason="Not used, open an issue if required.", version='2.4.110')
    def add_user_json(self, json_file):
        with open(json_file, 'rb') as f:
            jdata = json.load(f)
        new_user = MISPUser()
        new_user.from_dict(**jdata)
        return self._rest_add('admin/users', new_user)

    @deprecated(reason="Not used, open an issue if required.", version='2.4.110')
    def get_user_fields_list(self):
        return self._rest_get_parameters('admin/users')

    @deprecated(reason="Use ExpandedPyMISP.update_user", version='2.4.110')
    def edit_user(self, user_id, **kwargs):
        edit_user = MISPUser()
        edit_user.from_dict(**kwargs)
        return self._rest_edit('admin/users', edit_user, user_id)

    @deprecated(reason="Not used, open an issue if required.", version='2.4.110')
    def edit_user_json(self, json_file, user_id):
        with open(json_file, 'rb') as f:
            jdata = json.load(f)
        new_user = MISPUser()
        new_user.from_dict(**jdata)
        return self._rest_edit('admin/users', new_user, user_id)

    @deprecated(reason="Use ExpandedPyMISP.delete_user", version='2.4.110')
    def delete_user(self, user_id):
        return self._rest_delete('admin/users', user_id)

    # ############## Organisations ##################

    @deprecated(reason="Use ExpandedPyMISP.organisations", version='2.4.110')
    def get_organisations_list(self, scope="local"):
        scope = scope.lower()
        if scope not in ["local", "external", "all"]:
            raise ValueError("Authorized fields are 'local','external' or 'all'")
        return self._rest_list('organisations/index/scope:{}'.format(scope))

    @deprecated(reason="Use ExpandedPyMISP.get_organisation", version='2.4.110')
    def get_organisation(self, organisation_id):
        return self._rest_view('organisations', organisation_id)

    @deprecated(reason="Use ExpandedPyMISP.add_organisation", version='2.4.110')
    def add_organisation(self, name, **kwargs):
        if isinstance(name, MISPOrganisation):
            # Very dirty, allow to call that from ExpandedPyMISP
            new_org = name
        else:
            new_org = MISPOrganisation()
            new_org.from_dict(name=name, **kwargs)
            if 'local' in new_org:
                if new_org.get('local') is False:
                    if 'uuid' not in new_org:
                        raise PyMISPError('A remote org MUST have a valid uuid')
        return self._rest_add('admin/organisations', new_org)

    @deprecated(reason="Not used, open an issue if required.", version='2.4.110')
    def add_organisation_json(self, json_file):
        with open(json_file, 'rb') as f:
            jdata = json.load(f)
        new_org = MISPOrganisation()
        new_org.from_dict(**jdata)
        return self._rest_add('admin/organisations', new_org)

    @deprecated(reason="Not used, open an issue if required.", version='2.4.110')
    def get_organisation_fields_list(self):
        return self._rest_get_parameters('admin/organisations')

    @deprecated(reason="Use ExpandedPyMISP.update_organisation", version='2.4.110')
    def edit_organisation(self, org_id, **kwargs):
        edit_org = MISPOrganisation()
        edit_org.from_dict(**kwargs)
        return self._rest_edit('admin/organisations', edit_org, org_id)

    @deprecated(reason="Not used, open an issue if required.", version='2.4.110')
    def edit_organisation_json(self, json_file, org_id):
        with open(json_file, 'rb') as f:
            jdata = json.load(f)
        edit_org = MISPOrganisation()
        edit_org.from_dict(**jdata)
        return self._rest_edit('admin/organisations', edit_org, org_id)

    @deprecated(reason="Use ExpandedPyMISP.delete_organisation", version='2.4.110')
    def delete_organisation(self, org_id):
        return self._rest_delete('admin/organisations', org_id)

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

    @deprecated(reason="Use ExpandedPyMISP.add_server", version='2.4.110')
    def add_server(self, url, name, authkey, organisation, internal=None, push=False,
                   pull=False, self_signed=False, push_rules="", pull_rules="",
                   submitted_cert=None, submitted_client_cert=None):
        new_server = self._set_server_parameters(url, name, authkey, organisation, internal,
                                                 push, pull, self_signed, push_rules, pull_rules, submitted_cert,
                                                 submitted_client_cert, None, None)
        url = urljoin(self.root_url, 'servers/add')
        response = self._prepare_request('POST', url, json.dumps(new_server))
        return self._check_response(response)

    @deprecated(reason="Not used, open an issue if required.", version='2.4.110')
    def add_server_json(self, json_file):
        with open(json_file, 'rb') as f:
            jdata = json.load(f)
        url = urljoin(self.root_url, 'servers/add')
        response = self._prepare_request('POST', url, json.dumps(jdata))
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.update_server", version='2.4.110')
    def edit_server(self, server_id, url=None, name=None, authkey=None, organisation=None, internal=None, push=False,
                    pull=False, self_signed=False, push_rules="", pull_rules="",
                    submitted_cert=None, submitted_client_cert=None, delete_cert=None, delete_client_cert=None):
        new_server = self._set_server_parameters(url, name, authkey, organisation, internal,
                                                 push, pull, self_signed, push_rules, pull_rules, submitted_cert,
                                                 submitted_client_cert, delete_cert, delete_client_cert)
        url = urljoin(self.root_url, 'servers/edit/{}'.format(server_id))
        response = self._prepare_request('POST', url, json.dumps(new_server))
        return self._check_response(response)

    @deprecated(reason="Not used, open an issue if required.", version='2.4.110')
    def edit_server_json(self, json_file, server_id):
        with open(json_file, 'rb') as f:
            jdata = json.load(f)
        url = urljoin(self.root_url, 'servers/edit/{}'.format(server_id))
        response = self._prepare_request('POST', url, json.dumps(jdata))
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.server_pull", version='2.4.110')
    def server_pull(self, server_id, event_id=None):
        url = urljoin(self.root_url, 'servers/pull/{}'.format(server_id))
        if event_id is not None:
            url += '/{}'.format(event_id)
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.server_push", version='2.4.110')
    def server_push(self, server_id, event_id=None):
        url = urljoin(self.root_url, 'servers/push/{}'.format(server_id))
        if event_id is not None:
            url += '/{}'.format(event_id)
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.servers", version='2.4.110')
    def servers_index(self):
        url = urljoin(self.root_url, 'servers/index')
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    # ############## Roles ##################

    @deprecated(reason="Use ExpandedPyMISP.roles", version='2.4.110')
    def get_roles_list(self):
        """Get the list of existing roles"""
        url = urljoin(self.root_url, 'roles')
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    # ############## Tags ##################

    @deprecated(reason="Use ExpandedPyMISP.tags", version='2.4.110')
    def get_tags_list(self):
        """Get the list of existing tags."""
        url = urljoin(self.root_url, 'tags')
        response = self._prepare_request('GET', url)
        return self._check_response(response)['Tag']

    @deprecated(reason="Use ExpandedPyMISP.get_tag", version='2.4.110')
    def get_tag(self, tag_id):
        """Get a tag by id."""
        url = urljoin(self.root_url, 'tags/view/{}'.format(tag_id))
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    def _set_tag_parameters(self, name, colour, exportable, hide_tag, org_id, count, user_id, numerical_value,
                            attribute_count, old_tag):
        tag = old_tag
        if name is not None:
            tag['name'] = name
        if colour is not None:
            tag['colour'] = colour
        if exportable is not None:
            tag['exportable'] = exportable
        if hide_tag is not None:
            tag['hide_tag'] = hide_tag
        if org_id is not None:
            tag['org_id'] = org_id
        if count is not None:
            tag['count'] = count
        if user_id is not None:
            tag['user_id'] = user_id
        if numerical_value is not None:
            tag['numerical_value'] = numerical_value
        if attribute_count is not None:
            tag['attribute_count'] = attribute_count

        return {'Tag': tag}

    @deprecated(reason="Use ExpandedPyMISP.update_tag", version='2.4.110')
    def edit_tag(self, tag_id, name=None, colour=None, exportable=None, hide_tag=None, org_id=None, count=None,
                 user_id=None, numerical_value=None, attribute_count=None):
        """Edit only the provided parameters of a tag."""
        old_tag = self.get_tag(tag_id)
        new_tag = self._set_tag_parameters(name, colour, exportable, hide_tag, org_id, count, user_id,
                                           numerical_value, attribute_count, old_tag)
        url = urljoin(self.root_url, 'tags/edit/{}'.format(tag_id))
        response = self._prepare_request('POST', url, json.dumps(new_tag))
        return self._check_response(response)

    @deprecated(reason="Not used, open an issue if required.", version='2.4.110')
    def edit_tag_json(self, json_file, tag_id):
        """Edit the tag using a json file."""
        with open(json_file, 'rb') as f:
            jdata = json.load(f)
        url = urljoin(self.root_url, 'tags/edit/{}'.format(tag_id))
        response = self._prepare_request('POST', url, json.dumps(jdata))
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.enable_tag", version='2.4.110')
    def enable_tag(self, tag_id):
        """Enable a tag by id."""
        response = self.edit_tag(tag_id, hide_tag=False)
        return response

    @deprecated(reason="Use ExpandedPyMISP.disable_tag", version='2.4.110')
    def disable_tag(self, tag_id):
        """Disable a tag by id."""
        response = self.edit_tag(tag_id, hide_tag=True)
        return response

    # ############## Taxonomies ##################

    @deprecated(reason="Use ExpandedPyMISP.taxonomies", version='2.4.110')
    def get_taxonomies_list(self):
        """Get all the taxonomies."""
        url = urljoin(self.root_url, 'taxonomies')
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.get_taxonomy", version='2.4.110')
    def get_taxonomy(self, taxonomy_id):
        """Get a taxonomy by id."""
        url = urljoin(self.root_url, 'taxonomies/view/{}'.format(taxonomy_id))
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.update_taxonomies", version='2.4.110')
    def update_taxonomies(self):
        """Update all the taxonomies."""
        url = urljoin(self.root_url, 'taxonomies/update')
        response = self._prepare_request('POST', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.enable_taxonomy", version='2.4.110')
    def enable_taxonomy(self, taxonomy_id):
        """Enable a taxonomy by id."""
        url = urljoin(self.root_url, 'taxonomies/enable/{}'.format(taxonomy_id))
        response = self._prepare_request('POST', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.disable_taxonomy", version='2.4.110')
    def disable_taxonomy(self, taxonomy_id):
        """Disable a taxonomy by id."""
        self.disable_taxonomy_tags(taxonomy_id)
        url = urljoin(self.root_url, 'taxonomies/disable/{}'.format(taxonomy_id))
        response = self._prepare_request('POST', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.get_taxonomy", version='2.4.110')
    def get_taxonomy_tags_list(self, taxonomy_id):
        """Get all the tags of a taxonomy by id."""
        url = urljoin(self.root_url, 'taxonomies/view/{}'.format(taxonomy_id))
        response = self._prepare_request('GET', url)
        return self._check_response(response)["entries"]

    @deprecated(reason="Use ExpandedPyMISP.enable_taxonomy_tags", version='2.4.110')
    def enable_taxonomy_tags(self, taxonomy_id):
        """Enable all the tags of a taxonomy by id."""
        enabled = self.get_taxonomy(taxonomy_id)['Taxonomy']['enabled']
        if enabled:
            url = urljoin(self.root_url, 'taxonomies/addTag/{}'.format(taxonomy_id))
            response = self._prepare_request('POST', url)
            return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.disable_taxonomy_tags", version='2.4.110')
    def disable_taxonomy_tags(self, taxonomy_id):
        """Disable all the tags of a taxonomy by id."""
        url = urljoin(self.root_url, 'taxonomies/disableTag/{}'.format(taxonomy_id))
        response = self._prepare_request('POST', url)
        return self._check_response(response)

    # ############## WarningLists ##################

    @deprecated(reason="Use ExpandedPyMISP.warninglists", version='2.4.110')
    def get_warninglists(self):
        """Get all the warninglists."""
        url = urljoin(self.root_url, 'warninglists')
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.get_warninglist", version='2.4.110')
    def get_warninglist(self, warninglist_id):
        """Get a warninglist by id."""
        url = urljoin(self.root_url, 'warninglists/view/{}'.format(warninglist_id))
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.update_warninglists", version='2.4.110')
    def update_warninglists(self):
        """Update all the warninglists."""
        url = urljoin(self.root_url, 'warninglists/update')
        response = self._prepare_request('POST', url)
        return self._check_response(response)

    @deprecated(reason="Please ExpandedPyMISP.toggle_warninglist instead.")
    def toggle_warninglist(self, warninglist_id=None, warninglist_name=None, force_enable=None):
        '''Toggle (enable/disable) the status of a warninglist by ID.
        :param warninglist_id: ID of the WarningList
        :param force_enable: Force the warning list in the enabled state (does nothing if already enabled)
        '''
        if warninglist_id is None and warninglist_name is None:
            raise Exception('Either warninglist_id or warninglist_name is required.')
        query = {}
        if warninglist_id is not None:
            if not isinstance(warninglist_id, list):
                warninglist_id = [warninglist_id]
            query['id'] = warninglist_id
        if warninglist_name is not None:
            if not isinstance(warninglist_name, list):
                warninglist_name = [warninglist_name]
            query['name'] = warninglist_name
        if force_enable is not None:
            query['enabled'] = force_enable
        url = urljoin(self.root_url, 'warninglists/toggleEnable')
        response = self._prepare_request('POST', url, json.dumps(query))
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.enable_warninglist", version='2.4.110')
    def enable_warninglist(self, warninglist_id):
        """Enable a warninglist by id."""
        return self.toggle_warninglist(warninglist_id=warninglist_id, force_enable=True)

    @deprecated(reason="Use ExpandedPyMISP.disable_warninglist", version='2.4.110')
    def disable_warninglist(self, warninglist_id):
        """Disable a warninglist by id."""
        return self.toggle_warninglist(warninglist_id=warninglist_id, force_enable=False)

    @deprecated(reason='Use ExpandedPyMISP.values_in_warninglist', version='2.4.110')
    def check_warninglist(self, value):
        """Check if IOC values are in warninglist"""
        url = urljoin(self.root_url, 'warninglists/checkValue')
        response = self._prepare_request('POST', url, json.dumps(value))
        return self._check_response(response)

    # ############## NoticeLists ##################

    @deprecated(reason="Use ExpandedPyMISP.noticelists", version='2.4.110')
    def get_noticelists(self):
        """Get all the noticelists."""
        url = urljoin(self.root_url, 'noticelists')
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.get_noticelist", version='2.4.110')
    def get_noticelist(self, noticelist_id):
        """Get a noticelist by id."""
        url = urljoin(self.root_url, 'noticelists/view/{}'.format(noticelist_id))
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.update_noticelists", version='2.4.110')
    def update_noticelists(self):
        """Update all the noticelists."""
        url = urljoin(self.root_url, 'noticelists/update')
        response = self._prepare_request('POST', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.enable_noticelist", version='2.4.110')
    def enable_noticelist(self, noticelist_id):
        """Enable a noticelist by id."""
        url = urljoin(self.root_url, 'noticelists/enableNoticelist/{}/true'.format(noticelist_id))
        response = self._prepare_request('POST', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.disable_noticelist", version='2.4.110')
    def disable_noticelist(self, noticelist_id):
        """Disable a noticelist by id."""
        url = urljoin(self.root_url, 'noticelists/enableNoticelist/{}'.format(noticelist_id))
        response = self._prepare_request('POST', url)
        return self._check_response(response)

    # ############## Galaxies/Clusters ##################

    @deprecated(reason="Use ExpandedPyMISP.galaxies", version='2.4.110')
    def get_galaxies(self):
        """Get all the galaxies."""
        url = urljoin(self.root_url, 'galaxies')
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.get_galaxy", version='2.4.110')
    def get_galaxy(self, galaxy_id):
        """Get a galaxy by id."""
        url = urljoin(self.root_url, 'galaxies/view/{}'.format(galaxy_id))
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.update_galaxies", version='2.4.110')
    def update_galaxies(self):
        """Update all the galaxies."""
        url = urljoin(self.root_url, 'galaxies/update')
        response = self._prepare_request('POST', url)
        return self._check_response(response)

    # ##############################################
    # ############### Non-JSON output ##############
    # ##############################################

    # ############## Suricata ##############

    @deprecated(reason="Use ExpandedPyMISP.search", version='2.4.111')
    def download_all_suricata(self):
        """Download all suricata rules events."""
        url = urljoin(self.root_url, 'events/nids/suricata/download')
        response = self._prepare_request('GET', url, output_type='rules')
        return response

    @deprecated(reason="Use ExpandedPyMISP.search", version='2.4.111')
    def download_suricata_rule_event(self, event_id):
        """Download one suricata rule event.

        :param event_id: ID of the event to download (same as get)
        """
        url = urljoin(self.root_url, 'events/nids/suricata/download/{}'.format(event_id))
        response = self._prepare_request('GET', url, output_type='rules')
        return response

    # ############## Text ###############

    @deprecated(reason="Use ExpandedPyMISP.search", version='2.4.111')
    def get_all_attributes_txt(self, type_attr, tags=False, eventId=False, allowNonIDS=False, date_from=False, date_to=False, last=False, enforceWarninglist=False, allowNotPublished=False):
        """Get all attributes from a specific type as plain text. Only published and IDS flagged attributes are exported, except if stated otherwise."""
        url = urljoin(self.root_url, 'attributes/text/download/%s/%s/%s/%s/%s/%s/%s/%s/%s' % (type_attr, tags, eventId, allowNonIDS, date_from, date_to, last, enforceWarninglist, allowNotPublished))
        response = self._prepare_request('GET', url, output_type='txt')
        return response

    # ############## STIX ##############

    @deprecated(reason="Use ExpandedPyMISP.search", version='2.4.111')
    def get_stix_event(self, event_id=None, with_attachments=False, from_date=False, to_date=False, tags=False):
        """Get an event/events in STIX format"""
        if tags:
            if isinstance(tags, list):
                tags = "&&".join(tags)
        url = urljoin(self.root_url, "events/stix/download/{}/{}/{}/{}/{}".format(
            event_id, with_attachments, tags, from_date, to_date))
        logger.debug("Getting STIX event from %s", url)
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.search", version='2.4.111')
    def get_stix(self, **kwargs):
        return self.get_stix_event(**kwargs)

    @deprecated(reason="Use ExpandedPyMISP.search", version='2.4.111')
    def get_csv(self, eventid=None, attributes=[], object_attributes=[], misp_types=[], context=False, ignore=False, last=None):
        """Get MISP values in CSV format
        :param eventid: The event ID to query
        :param attributes: The column names to export from normal attributes (i.e. uuid, value, type, ...)
        :param object_attributes: The column names to export from attributes within objects (i.e. uuid, value, type, ...)
        :param misp_types: MISP types to get (i.e. ip-src, hostname, ...)
        :param context: Add event level context (event_info,event_member_org,event_source_org,event_distribution,event_threat_level_id,event_analysis,event_date,event_tag)
        :param ignore: Returns the attributes even if the event isn't published, or the attribute doesn't have the to_ids flag set
        """
        url = urljoin(self.root_url, 'events/csv/download')
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
            response = self._prepare_request('POST', url, json.dumps(to_post), output_type='json')
        else:
            response = self._prepare_request('POST', url, output_type='json')
        return response.text

    # #######################################
    # ######## RestResponse generic #########
    # #######################################

    def _rest_list(self, urlpath):
        url = urljoin(self.root_url, urlpath)
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    def _rest_get_parameters(self, urlpath):
        url = urljoin(self.root_url, '{}/add'.format(urlpath))
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    def _rest_view(self, urlpath, rest_id):
        url = urljoin(self.root_url, '{}/view/{}'.format(urlpath, rest_id))
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    def _rest_add(self, urlpath, obj):
        url = urljoin(self.root_url, '{}/add'.format(urlpath))
        response = self._prepare_request('POST', url, obj.to_json())
        return self._check_response(response)

    def _rest_edit(self, urlpath, obj, rest_id):
        url = urljoin(self.root_url, '{}/edit/{}'.format(urlpath, rest_id))
        response = self._prepare_request('POST', url, obj.to_json())
        return self._check_response(response)

    def _rest_delete(self, urlpath, rest_id):
        url = urljoin(self.root_url, '{}/delete/{}'.format(urlpath, rest_id))
        response = self._prepare_request('POST', url)
        return self._check_response(response)

    # ###########################
    # ########   Feed   #########
    # ###########################

    @deprecated(reason="Use ExpandedPyMISP.feeds instead")
    def get_feeds_list(self):
        """Get the content of all the feeds"""
        return self._rest_list('feeds')

    @deprecated(reason="Use ExpandedPyMISP.get_feed instead")
    def get_feed(self, feed_id):
        """Get the content of a single feed"""
        return self._rest_view('feeds', feed_id)

    @deprecated(reason="Use ExpandedPyMISP.add_feed instead")
    def add_feed(self, source_format, url, name, input_source, provider, **kwargs):
        """Delete a feed"""
        new_feed = MISPFeed()
        new_feed.from_dict(source_format=source_format, url=url, name=name,
                           input_source=input_source, provider=provider)
        return self._rest_add('feeds', new_feed)

    @deprecated(reason="Not used, open an issue if required.", version='2.4.110')
    def get_feed_fields_list(self):
        return self._rest_get_parameters('feeds')

    @deprecated(reason="Use ExpandedPyMISP.update_feed instead")
    def edit_feed(self, feed_id, **kwargs):
        """Delete a feed"""
        edit_feed = MISPFeed()
        edit_feed.from_dict(**kwargs)
        return self._rest_edit('feeds', edit_feed)

    @deprecated(reason="Use ExpandedPyMISP.delete_feed instead")
    def delete_feed(self, feed_id):
        """Delete a feed"""
        return self._rest_delete('feeds', feed_id)

    @deprecated(reason="Use ExpandedPyMISP.fetch_feed instead")
    def fetch_feed(self, feed_id):
        """Fetch one single feed"""
        url = urljoin(self.root_url, 'feeds/fetchFromFeed/{}'.format(feed_id))
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.cache_all_feeds instead")
    def cache_feeds_all(self):
        """ Cache all the feeds"""
        url = urljoin(self.root_url, 'feeds/cacheFeeds/all')
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.cache_feeds instead")
    def cache_feed(self, feed_id):
        """Cache a specific feed"""
        url = urljoin(self.root_url, 'feeds/cacheFeeds/{}'.format(feed_id))
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.cache_freetext_feeds instead")
    def cache_feeds_freetext(self):
        """Cache all the freetext feeds"""
        url = urljoin(self.root_url, 'feeds/cacheFeeds/freetext')
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.cache_misp_feeds instead")
    def cache_feeds_misp(self):
        """Cache all the MISP feeds"""
        url = urljoin(self.root_url, 'feeds/cacheFeeds/misp')
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.compare_feeds instead")
    def compare_feeds(self):
        """Generate the comparison matrix for all the MISP feeds"""
        url = urljoin(self.root_url, 'feeds/compareFeeds')
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.get_feed instead")
    def view_feed(self, feed_ids):
        """Alias for get_feed"""
        return self.get_feed(feed_ids)

    @deprecated(reason="Use ExpandedPyMISP.feeds instead")
    def view_feeds(self):
        """Alias for get_feeds_list"""
        return self.get_feeds_list()

    # ######################
    # ### Sharing Groups ###
    # ######################

    @deprecated(reason="Use ExpandedPyMISP.add_sharing_group", version='2.4.111')
    def add_sharing_group(self, name, releasability, description, active=True):
        """Add a new sharing group, which includes the organisation associated
        with the API key and the local server

        :name: The name of the sharing group to create
        :releasability: The releasibility information
        :description: The description of the sharing group
        :active: Should the sharing group be set to be active?
        """

        new_sg = MISPSharingGroup()
        new_sg.from_dict(name=name, releasability=releasability,
                         description=description, active=active)
        return self._rest_add('sharing_groups', new_sg)

    @deprecated(reason="Use ExpandedPyMISP.add_org_to_sharing_group", version='2.4.111')
    def sharing_group_org_add(self, sharing_group, organisation, extend=False):
        '''Add an organisation to a sharing group.
        :sharing_group: Sharing group's local instance ID, or Sharing group's global UUID
        :organisation: Organisation's local instance ID, or Organisation's global UUID, or Organisation's name as known to the curent instance
        :extend: Allow the organisation to extend the group
        '''
        to_jsonify = {'sg_id': sharing_group, 'org_id': organisation, 'extend': extend}
        url = urljoin(self.root_url, 'sharingGroups/addOrg')
        response = self._prepare_request('POST', url, json.dumps(to_jsonify))
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.remove_org_from_sharing_group", version='2.4.111')
    def sharing_group_org_remove(self, sharing_group, organisation):
        '''Remove an organisation from a sharing group.
        :sharing_group: Sharing group's local instance ID, or Sharing group's global UUID
        :organisation: Organisation's local instance ID, or Organisation's global UUID, or Organisation's name as known to the curent instance
        '''
        to_jsonify = {'sg_id': sharing_group, 'org_id': organisation}
        url = urljoin(self.root_url, 'sharingGroups/removeOrg')
        response = self._prepare_request('POST', url, json.dumps(to_jsonify))
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.add_server_to_sharing_group", version='2.4.111')
    def sharing_group_server_add(self, sharing_group, server, all_orgs=False):
        '''Add a server to a sharing group.
        :sharing_group: Sharing group's local instance ID, or Sharing group's global UUID
        :server: Server's local instance ID, or URL of the Server, or Server's name as known to the curent instance
        :all_orgs: Add all the organisations of the server to the group
        '''
        to_jsonify = {'sg_id': sharing_group, 'server_id': server, 'all_orgs': all_orgs}
        url = urljoin(self.root_url, 'sharingGroups/addServer')
        response = self._prepare_request('POST', url, json.dumps(to_jsonify))
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.remove_server_from_sharing_group", version='2.4.111')
    def sharing_group_server_remove(self, sharing_group, server):
        '''Remove a server from a sharing group.
        :sharing_group: Sharing group's local instance ID, or Sharing group's global UUID
        :server: Server's local instance ID, or URL of the Server, or Server's name as known to the curent instance
        '''
        to_jsonify = {'sg_id': sharing_group, 'server_id': server}
        url = urljoin(self.root_url, 'sharingGroups/removeServer')
        response = self._prepare_request('POST', url, json.dumps(to_jsonify))
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.delete_sharing_group", version='2.4.111')
    def delete_sharing_group(self, sharing_group):
        """Delete a sharing group
        :sharing_group: Sharing group's local instance ID, or Sharing group's global uuid
        """
        return self._rest_delete("sharing_groups", sharing_group)

    # ###################
    # ###   Objects   ###
    # ###################

    @deprecated(reason="Use ExpandedPyMISP.add_object", version='2.4.111')
    def add_object(self, event_id, *args, **kwargs):
        """Add an object
        :param event_id: Event ID of the event to attach the object to
        :param template_id: Template ID of the template related to that event (not required)
        :param misp_object: MISPObject to attach
        """
        # NOTE: this slightly fucked up thing is due to the fact template_id was required, and was the 2nd parameter.
        template_id = kwargs.get('template_id')
        misp_object = kwargs.get('misp_object')
        if args:
            if isinstance(args[0], MISPObject):
                misp_object = args[0]
            else:
                template_id = args[0]
                misp_object = args[1]

        if template_id is not None:
            url = urljoin(self.root_url, 'objects/add/{}/{}'.format(event_id, template_id))
        else:
            url = urljoin(self.root_url, 'objects/add/{}'.format(event_id))
        response = self._prepare_request('POST', url, misp_object.to_json())
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.update_object", version='2.4.111')
    def edit_object(self, misp_object, object_id=None):
        """Edit an existing object"""
        if object_id:
            param = object_id
        elif hasattr(misp_object, 'uuid'):
            param = misp_object.uuid
        elif hasattr(misp_object, 'id'):
            param = misp_object.id
        else:
            raise PyMISPError('In order to update an object, you have to provide an object ID (either in the misp_object, or as a parameter)')
        url = urljoin(self.root_url, 'objects/edit/{}'.format(param))
        response = self._prepare_request('POST', url, misp_object.to_json())
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.delete_object", version='2.4.111')
    def delete_object(self, id):
        """Deletes an object"""
        url = urljoin(self.root_url, 'objects/delete/{}'.format(id))
        response = self._prepare_request('POST', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.add_object_reference", version='2.4.111')
    def add_object_reference(self, misp_object_reference):
        """Add a reference to an object"""
        url = urljoin(self.root_url, 'object_references/add')
        response = self._prepare_request('POST', url, misp_object_reference.to_json())
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.delete_object_reference", version='2.4.111')
    def delete_object_reference(self, id):
        """Deletes a reference to an object"""
        url = urljoin(self.root_url, 'object_references/delete/{}'.format(id))
        response = self._prepare_request('POST', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.object_templates", version='2.4.111')
    def get_object_templates_list(self):
        """Returns the list of Object templates available on the MISP instance"""
        url = urljoin(self.root_url, 'objectTemplates')
        response = self._prepare_request('GET', url)
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.get_object_template", version='2.4.111')
    def get_object_template(self, object_uuid):
        """Gets the full object template corresponting the UUID passed as parameter"""
        url = urljoin(self.root_url, 'objectTemplates/view/{}'.format(object_uuid))
        response = self._prepare_request('GET', url)
        return self._check_response(response)
        if 'ObjectTemplate' in response:
            return response['ObjectTemplate']['id']
        return response

    @deprecated(reason="Use ExpandedPyMISP.get_object_template - open an issue if you really need this method.", version='2.4.111')
    def get_object_template_id(self, object_uuid):
        """Gets the template ID corresponting the UUID passed as parameter"""
        template = self.get_object_template(object_uuid)
        if 'ObjectTemplate' in template:
            return template['ObjectTemplate']['id']
        # Contains the error message.
        return template

    @deprecated(reason="Use ExpandedPyMISP.update_object_templates", version='2.4.111')
    def update_object_templates(self):
        url = urljoin(self.root_url, 'objectTemplates/update')
        response = self._prepare_request('POST', url)
        return self._check_response(response)

    # ###########################
    # ####### Deprecated ########
    # ###########################

    @deprecated(reason="Use ExpandedPyMISP.tag", version='2.4.111')
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
        response = self._prepare_request('POST', url, json.dumps(to_post))
        return self._check_response(response)

    @deprecated(reason="Use ExpandedPyMISP.untag", version='2.4.111')
    def remove_tag(self, event, tag, attribute=False):
        if attribute:
            to_post = {'request': {'Attribute': {'id': event['id'], 'tag': tag}}}
            path = 'attributes/removeTag'
        else:
            to_post = {'request': {'Event': {'id': event['Event']['id'], 'tag': tag}}}
            path = 'events/removeTag'
        url = urljoin(self.root_url, path)
        response = self._prepare_request('POST', url, json.dumps(to_post))
        return self._check_response(response)
