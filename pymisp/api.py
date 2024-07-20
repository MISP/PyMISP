from __future__ import annotations

from typing import TypeVar, Any, Mapping, Iterable, MutableMapping, Union, List, Dict
from datetime import date, datetime
import csv
from pathlib import Path
import logging
from urllib.parse import urljoin
import requests
from requests.auth import AuthBase
import re
from uuid import UUID
import warnings
import sys
import copy
from io import BytesIO, StringIO
from importlib.metadata import version

try:
    # orjson is optional dependency that speedups parsing and encoding JSON
    from orjson import loads, dumps  # type: ignore
    HAS_ORJSON = True
except ImportError:
    from json import loads, dumps
    HAS_ORJSON = False

from . import __version__, everything_broken
from .exceptions import MISPServerError, PyMISPUnexpectedResponse, PyMISPError, NoURL, NoKey
from .mispevent import MISPEvent, MISPAttribute, MISPSighting, MISPLog, MISPObject, \
    MISPUser, MISPOrganisation, MISPShadowAttribute, MISPWarninglist, MISPTaxonomy, \
    MISPGalaxy, MISPNoticelist, MISPObjectReference, MISPObjectTemplate, MISPSharingGroup, \
    MISPRole, MISPServer, MISPFeed, MISPEventDelegation, MISPCommunity, MISPUserSetting, \
    MISPInbox, MISPEventBlocklist, MISPOrganisationBlocklist, MISPEventReport, \
    MISPGalaxyCluster, MISPGalaxyClusterRelation, MISPCorrelationExclusion, MISPDecayingModel, \
    MISPNote, MISPOpinion, MISPRelationship, AnalystDataBehaviorMixin
from .abstract import pymisp_json_default, MISPTag, AbstractMISP, describe_types


if sys.platform == 'linux':
    # Enable TCP keepalive by default on every requests
    import socket
    from urllib3.connection import HTTPConnection
    HTTPConnection.default_socket_options = HTTPConnection.default_socket_options + [  # type: ignore
        (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),  # enable keepalive
        (socket.SOL_TCP, socket.TCP_KEEPIDLE, 30),  # Start pinging after 30s of idle time
        (socket.SOL_TCP, socket.TCP_KEEPINTVL, 10),  # ping every 10s
        (socket.SOL_TCP, socket.TCP_KEEPCNT, 6)  # kill the connection if 6 ping fail  (60s total)
    ]

try:
    # cached_property exists since Python 3.8
    from functools import cached_property
except ImportError:
    from functools import lru_cache

    def cached_property(func):  # type: ignore
        return property(lru_cache(func))

SearchType = TypeVar('SearchType', str, int)
# str: string to search / list: values to search (OR) / dict: {'OR': [list], 'NOT': [list], 'AND': [list]}
# NOTE: we cannot use new typing here until we drop Python 3.8 and 3.9 support
SearchParameterTypes = TypeVar('SearchParameterTypes', str, List[Union[str, int]], Dict[str, Union[str, int]])

ToIDSType = TypeVar('ToIDSType', str, int, bool)

logger = logging.getLogger('pymisp')


def get_uuid_or_id_from_abstract_misp(obj: AbstractMISP | int | str | UUID | dict[str, Any]) -> str | int:
    """Extract the relevant ID accordingly to the given type passed as parameter"""
    if isinstance(obj, UUID):
        return str(obj)
    if isinstance(obj, (int, str)):
        return obj

    if isinstance(obj, dict) and len(obj) == 1:
        # We have an object in that format: {'Event': {'id': 2, ...}}
        # We need to get the content of that dictionary
        obj = obj[list(obj.keys())[0]]

    if isinstance(obj, MISPShadowAttribute):
        # A ShadowAttribute has the same UUID as the related Attribute, we *need* to use the ID
        return obj['id']
    if isinstance(obj, MISPEventDelegation):
        # An EventDelegation doesn't have a uuid, we *need* to use the ID
        return obj['id']

    # For the blocklists, we want to return a specific key.
    if isinstance(obj, MISPEventBlocklist):
        return obj.event_uuid
    if isinstance(obj, MISPOrganisationBlocklist):
        return obj.org_uuid

    # at this point, we must have an AbstractMISP
    if 'uuid' in obj:  # type: ignore
        return obj['uuid']  # type: ignore
    return obj['id']  # type: ignore


def register_user(misp_url: str, email: str,
                  organisation: MISPOrganisation | int | str | UUID | None = None,
                  org_id: str | None = None, org_name: str | None = None,
                  message: str | None = None, custom_perms: str | None = None,
                  perm_sync: bool = False, perm_publish: bool = False, perm_admin: bool = False,
                  verify: bool = True) -> dict[str, Any] | list[dict[str, Any]]:
    """Ask for the creation of an account for the user with the given email address"""
    data = copy.deepcopy(locals())
    if organisation:
        data['org_uuid'] = get_uuid_or_id_from_abstract_misp(data.pop('organisation'))

    url = urljoin(data.pop('misp_url'), 'users/register')
    user_agent = f'PyMISP {__version__} - no login -  Python {".".join(str(x) for x in sys.version_info[:2])}'
    headers = {
        'Accept': 'application/json',
        'content-type': 'application/json',
        'User-Agent': user_agent}
    r = requests.post(url, json=data, verify=data.pop('verify'), headers=headers)
    return r.json()


def brotli_supported() -> bool:
    """
    Returns whether Brotli compression is supported
    """
    major: int
    minor: int
    patch: int

    # urllib >= 1.25.1 includes brotli support
    version_splitted = version('urllib3').split('.')  # noqa: F811
    if len(version_splitted) == 2:
        major, minor = version_splitted  # type: ignore
        patch = 0
    else:
        major, minor, patch = version_splitted  # type: ignore
    major, minor, patch = int(major), int(minor), int(patch)
    urllib3_with_brotli = (major == 1 and ((minor == 25 and patch >= 1) or (minor >= 26))) or major >= 2

    if not urllib3_with_brotli:
        return False

    # pybrotli is an extra package required by urllib3 for brotli support
    try:
        import brotli  # type: ignore # noqa
        return True
    except ImportError:
        return False


class PyMISP:
    """Python API for MISP

    :param url: URL of the MISP instance you want to connect to
    :param key: API key of the user you want to use
    :param ssl: can be True or False (to check or to not check the validity of the certificate. Or a CA_BUNDLE in case of self signed or other certificate (the concatenation of all the crt of the chain)
    :param debug: Write all the debug information to stderr
    :param proxies: Proxy dict, as described here: http://docs.python-requests.org/en/master/user/advanced/#proxies
    :param cert: Client certificate, as described here: http://docs.python-requests.org/en/master/user/advanced/#client-side-certificates
    :param auth: The auth parameter is passed directly to requests, as described here: http://docs.python-requests.org/en/master/user/authentication/
    :param tool: The software using PyMISP (string), used to set a unique user-agent
    :param http_headers: Arbitrary headers to pass to all the requests.
    :param https_adapter: Arbitrary HTTPS adapter for the requests session.
    :param http_auth_header_name: The name of the HTTP header to use for the API key. Can be either "Authorization" or "X-MISP-AUTH".
    :param timeout: Timeout, as described here: https://requests.readthedocs.io/en/master/user/advanced/#timeouts
    """

    def __init__(self, url: str, key: str, ssl: bool | str = True, debug: bool = False, proxies: MutableMapping[str, str] | None = None,
                 cert: str | tuple[str, str] | None = None, auth: AuthBase | None = None, tool: str = '',
                 timeout: float | tuple[float, float] | None = None,
                 http_headers: dict[str, str] | None = None,
                 https_adapter: requests.adapters.BaseAdapter | None = None,
                 http_auth_header_name: str = 'Authorization'
                 ):

        if not url:
            raise NoURL('Please provide the URL of your MISP instance.')
        if not key:
            raise NoKey('Please provide your authorization key.')

        self.root_url: str = url
        self.key: str = key.strip()
        self.ssl: bool | str = ssl
        self.proxies: MutableMapping[str, str] | None = proxies
        self.cert: str | tuple[str, str] | None = cert
        self.auth: AuthBase | None = auth
        self.timeout: float | tuple[float, float] | None = timeout
        self.__session = requests.Session()  # use one session to keep connection between requests
        if https_adapter is not None:
            self.__session.mount('https://', https_adapter)
        if brotli_supported():
            self.__session.headers['Accept-Encoding'] = ', '.join(('br', 'gzip', 'deflate'))

        if http_auth_header_name in ['Authorization', 'X-MISP-AUTH']:
            self.__session.headers[http_auth_header_name] = self.key
        else:
            raise PyMISPError('http_auth_header_name should be either "Authorization" or "X-MISP-AUTH"')

        user_agent = f'PyMISP {__version__} - Python {".".join(str(x) for x in sys.version_info[:2])}'
        if tool:
            user_agent = f'{user_agent} - {tool}'
        self.__session.headers['User-Agent'] = user_agent

        if http_headers:
            self.__session.headers.update(http_headers)

        self.global_pythonify = False

        self.resources_path = Path(__file__).parent / 'data'
        if debug:
            logger.setLevel(logging.DEBUG)
            logger.info('To configure logging in your script, leave it to None and use the following: import logging; logging.getLogger(\'pymisp\').setLevel(logging.DEBUG)')

        try:
            # Make sure the MISP instance is working and the URL is valid
            response = self.recommended_pymisp_version
            if 'errors' in response:
                logger.warning(response['errors'][0])
            else:
                pymisp_version_tup = tuple(int(x) for x in __version__.split('.'))
                recommended_version_tup = tuple(int(x) for x in response['version'].split('.'))
                if recommended_version_tup < pymisp_version_tup[:3]:
                    logger.info(f"The version of PyMISP recommended by the MISP instance ({response['version']}) is older than the one you're using now ({__version__}). If you have a problem, please upgrade the MISP instance or use an older PyMISP version.")
                elif pymisp_version_tup[:3] < recommended_version_tup:
                    logger.warning(f"The version of PyMISP recommended by the MISP instance ({response['version']}) is newer than the one you're using now ({__version__}). Please upgrade PyMISP.")

            misp_version = self.misp_instance_version
            if 'version' in misp_version:
                self._misp_version = tuple(int(v) for v in misp_version['version'].split('.'))

            # Get the user information
            self._current_user: MISPUser
            self._current_role: MISPRole
            self._current_user_settings: list[MISPUserSetting]
            user_infos = self.get_user(pythonify=True, expanded=True)
            if isinstance(user_infos, dict):
                # There was an error during the get_user call
                if e := user_infos.get('errors'):
                    raise PyMISPError(f'Unable to get the user settings: {e}')
                raise PyMISPError(f'Unexpected error when initializing the connection: {user_infos}')
            elif isinstance(user_infos, tuple) and len(user_infos) == 3:
                self._current_user, self._current_role, self._current_user_settings = user_infos
            else:
                raise PyMISPError(f'Unexpected error when initializing the connection: {user_infos}')
        except PyMISPError as e:
            raise e
        except Exception as e:
            raise PyMISPError(f'Unable to connect to MISP ({self.root_url}). Please make sure the API key and the URL are correct (http/https is required): {e}')

        try:
            self.describe_types = self.describe_types_remote
        except Exception:
            self.describe_types = self.describe_types_local

        self.categories = self.describe_types['categories']
        self.types = self.describe_types['types']
        self.category_type_mapping = self.describe_types['category_type_mappings']
        self.sane_default = self.describe_types['sane_defaults']

    def remote_acl(self, debug_type: str = 'findMissingFunctionNames') -> dict[str, Any] | list[dict[str, Any]]:
        """This should return an empty list, unless the ACL is outdated.

        :param debug_type: printAllFunctionNames, findMissingFunctionNames, or printRoleAccess
        """
        response = self._prepare_request('GET', f'events/queryACL/{debug_type}')
        return self._check_json_response(response)

    @property
    def describe_types_local(self) -> dict[str, Any] | list[dict[str, Any]]:
        '''Returns the content of describe types from the package'''
        return describe_types

    @property
    def describe_types_remote(self) -> dict[str, Any] | list[dict[str, Any]]:
        '''Returns the content of describe types from the remote instance'''
        response = self._prepare_request('GET', 'attributes/describeTypes.json')
        remote_describe_types = self._check_json_response(response)
        return remote_describe_types['result']

    @property
    def recommended_pymisp_version(self) -> dict[str, Any] | list[dict[str, Any]]:
        """Returns the recommended API version from the server"""
        # Sine MISP 2.4.146 is recommended PyMISP version included in getVersion call
        misp_version = self.misp_instance_version
        if "pymisp_recommended_version" in misp_version:
            return {"version": misp_version["pymisp_recommended_version"]}  # Returns dict to keep BC

        response = self._prepare_request('GET', 'servers/getPyMISPVersion.json')
        return self._check_json_response(response)

    @property
    def version(self) -> dict[str, Any] | list[dict[str, Any]]:
        """Returns the version of PyMISP you're currently using"""
        return {'version': __version__}

    @property
    def pymisp_version_master(self) -> dict[str, Any] | list[dict[str, Any]]:
        """PyMISP version as defined in the main repository"""
        return self.pymisp_version_main

    @property
    def pymisp_version_main(self) -> dict[str, Any] | list[dict[str, Any]]:
        """Get the most recent version of PyMISP from github"""
        r = requests.get('https://raw.githubusercontent.com/MISP/PyMISP/main/pyproject.toml')
        if r.status_code == 200:
            version = re.findall('version = "(.*)"', r.text)
            return {'version': version[0]}
        return {'error': 'Impossible to retrieve the version of the main branch.'}

    @cached_property
    def misp_instance_version(self) -> dict[str, Any] | list[dict[str, Any]]:
        """Returns the version of the instance."""
        response = self._prepare_request('GET', 'servers/getVersion')
        return self._check_json_response(response)

    @property
    def misp_instance_version_master(self) -> dict[str, Any] | list[dict[str, Any]]:
        """Get the most recent version from github"""
        r = requests.get('https://raw.githubusercontent.com/MISP/MISP/2.4/VERSION.json')
        if r.status_code == 200:
            master_version = loads(r.content)
            return {'version': '{}.{}.{}'.format(master_version['major'], master_version['minor'], master_version['hotfix'])}
        return {'error': 'Impossible to retrieve the version of the master branch.'}

    def update_misp(self) -> dict[str, Any] | list[dict[str, Any]]:
        """Trigger a server update"""
        response = self._prepare_request('POST', 'servers/update')
        return self._check_json_response(response)

    def set_server_setting(self, setting: str, value: str | int | bool, force: bool = False) -> dict[str, Any] | list[dict[str, Any]]:
        """Set a setting on the MISP instance

        :param setting: server setting name
        :param value: value to set
        :param force: override value test
        """
        data = {'value': value, 'force': force}
        response = self._prepare_request('POST', f'servers/serverSettingsEdit/{setting}', data=data)
        return self._check_json_response(response)

    def get_server_setting(self, setting: str) -> dict[str, Any] | list[dict[str, Any]]:
        """Get a setting from the MISP instance

        :param setting: server setting name
        """
        response = self._prepare_request('GET', f'servers/getSetting/{setting}')
        return self._check_json_response(response)

    def server_settings(self) -> dict[str, Any] | list[dict[str, Any]]:
        """Get all the settings from the server"""
        response = self._prepare_request('GET', 'servers/serverSettings')
        return self._check_json_response(response)

    def restart_workers(self) -> dict[str, Any] | list[dict[str, Any]]:
        """Restart all the workers"""
        response = self._prepare_request('POST', 'servers/restartWorkers')
        return self._check_json_response(response)

    def db_schema_diagnostic(self) -> dict[str, Any] | list[dict[str, Any]]:
        """Get the schema diagnostic"""
        response = self._prepare_request('GET', 'servers/dbSchemaDiagnostic')
        return self._check_json_response(response)

    def toggle_global_pythonify(self) -> None:
        """Toggle the pythonify variable for the class"""
        self.global_pythonify = not self.global_pythonify

    # ## BEGIN Event ##

    def events(self, pythonify: bool = False) -> dict[str, Any] | list[MISPEvent] | list[dict[str, Any]]:
        """Get all the events from the MISP instance: https://www.misp-project.org/openapi/#tag/Events/operation/getEvents

        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        r = self._prepare_request('GET', 'events/index')
        events_r = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or isinstance(events_r, dict):
            return events_r
        to_return = []
        for event in events_r:
            e = MISPEvent()
            e.from_dict(**event)
            to_return.append(e)
        return to_return

    def get_event(self, event: MISPEvent | int | str | UUID,
                  deleted: bool | int | list[int] = False,
                  extended: bool | int = False,
                  pythonify: bool = False) -> dict[str, Any] | MISPEvent:
        """Get an event from a MISP instance. Includes collections like
        Attribute, EventReport, Feed, Galaxy, Object, Tag, etc. so the
        response size may be large : https://www.misp-project.org/openapi/#tag/Events/operation/getEventById

        :param event: event to get
        :param deleted: whether to include soft-deleted attributes
        :param extended: whether to get extended events
        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        event_id = get_uuid_or_id_from_abstract_misp(event)
        data = {}
        if deleted:
            data['deleted'] = deleted
        if extended:
            data['extended'] = extended
        if data:
            r = self._prepare_request('POST', f'events/view/{event_id}', data=data)
        else:
            r = self._prepare_request('GET', f'events/view/{event_id}')
        event_r = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in event_r:
            return event_r
        e = MISPEvent()
        e.load(event_r)
        return e

    def event_exists(self, event: MISPEvent | int | str | UUID) -> bool:
        """Fast check if event exists.

        :param event: Event to check
        """
        event_id = get_uuid_or_id_from_abstract_misp(event)
        r = self._prepare_request('HEAD', f'events/view/{event_id}')
        return self._check_head_response(r)

    def add_event(self, event: MISPEvent, pythonify: bool = False, metadata: bool = False) -> dict[str, Any] | MISPEvent:
        """Add a new event on a MISP instance: https://www.misp-project.org/openapi/#tag/Events/operation/addEvent

        :param event: event to add
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        :param metadata: Return just event metadata after successful creating
        """
        r = self._prepare_request('POST', 'events/add' + ('/metadata:1' if metadata else ''), data=event)
        new_event = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in new_event:
            return new_event
        e = MISPEvent()
        e.load(new_event)
        return e

    def update_event(self, event: MISPEvent, event_id: int | None = None, pythonify: bool = False,
                     metadata: bool = False) -> dict[str, Any] | MISPEvent:
        """Update an event on a MISP instance: https://www.misp-project.org/openapi/#tag/Events/operation/editEvent

        :param event: event to update
        :param event_id: ID of event to update
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        :param metadata: Return just event metadata after successful update
        """
        if event_id is None:
            eid = get_uuid_or_id_from_abstract_misp(event)
        else:
            eid = get_uuid_or_id_from_abstract_misp(event_id)
        r = self._prepare_request('POST', f'events/edit/{eid}' + ('/metadata:1' if metadata else ''), data=event)
        updated_event = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in updated_event:
            return updated_event
        e = MISPEvent()
        e.load(updated_event)
        return e

    def delete_event(self, event: MISPEvent | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Delete an event from a MISP instance: https://www.misp-project.org/openapi/#tag/Events/operation/deleteEvent

        :param event: event to delete
        """
        event_id = get_uuid_or_id_from_abstract_misp(event)
        response = self._prepare_request('POST', f'events/delete/{event_id}')
        return self._check_json_response(response)

    def publish(self, event: MISPEvent | int | str | UUID, alert: bool = False) -> dict[str, Any] | list[dict[str, Any]]:
        """Publish the event with one single HTTP POST: https://www.misp-project.org/openapi/#tag/Events/operation/publishEvent

        :param event: event to publish
        :param alert: whether to send an email.  The default is to not send a mail as it is assumed this method is called on update.
        """
        event_id = get_uuid_or_id_from_abstract_misp(event)
        if alert:
            response = self._prepare_request('POST', f'events/alert/{event_id}')
        else:
            response = self._prepare_request('POST', f'events/publish/{event_id}')
        return self._check_json_response(response)

    def unpublish(self, event: MISPEvent | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Unpublish the event with one single HTTP POST: https://www.misp-project.org/openapi/#tag/Events/operation/unpublishEvent

        :param event: event to unpublish
        """
        event_id = get_uuid_or_id_from_abstract_misp(event)
        response = self._prepare_request('POST', f'events/unpublish/{event_id}')
        return self._check_json_response(response)

    def contact_event_reporter(self, event: MISPEvent | int | str | UUID, message: str) -> dict[str, Any] | list[dict[str, Any]]:
        """Send a message to the reporter of an event

        :param event: event with reporter to contact
        :param message: message to send
        """
        event_id = get_uuid_or_id_from_abstract_misp(event)
        to_post = {'message': message}
        response = self._prepare_request('POST', f'events/contact/{event_id}', data=to_post)
        return self._check_json_response(response)

    # ## END Event ###

    # ## BEGIN Event Report ###

    def get_event_report(self, event_report: MISPEventReport | int | str | UUID,
                         pythonify: bool = False) -> dict[str, Any] | MISPEventReport:
        """Get an event report from a MISP instance

        :param event_report: event report to get
        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        event_report_id = get_uuid_or_id_from_abstract_misp(event_report)
        r = self._prepare_request('GET', f'eventReports/view/{event_report_id}')
        event_report_r = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in event_report_r:
            return event_report_r
        er = MISPEventReport()
        er.from_dict(**event_report_r)
        return er

    def get_event_reports(self, event_id: int | str,
                          pythonify: bool = False) -> dict[str, Any] | list[MISPEventReport] | list[dict[str, Any]]:
        """Get event report from a MISP instance that are attached to an event ID

        :param event_id: event id to get the event reports for
        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output.
        """
        r = self._prepare_request('GET', f'eventReports/index/event_id:{event_id}')
        event_reports = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or isinstance(event_reports, dict):
            return event_reports
        to_return = []
        for event_report in event_reports:
            er = MISPEventReport()
            er.from_dict(**event_report)
            to_return.append(er)
        return to_return

    def add_event_report(self, event: MISPEvent | int | str | UUID, event_report: MISPEventReport, pythonify: bool = False) -> dict[str, Any] | MISPEventReport:
        """Add an event report to an existing MISP event

        :param event: event to extend
        :param event_report: event report to add.
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        event_id = get_uuid_or_id_from_abstract_misp(event)
        r = self._prepare_request('POST', f'eventReports/add/{event_id}', data=event_report)
        new_event_report = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in new_event_report:
            return new_event_report
        er = MISPEventReport()
        er.from_dict(**new_event_report)
        return er

    def update_event_report(self, event_report: MISPEventReport, event_report_id: int | None = None, pythonify: bool = False) -> dict[str, Any] | MISPEventReport:
        """Update an event report on a MISP instance

        :param event_report: event report to update
        :param event_report_id: event report ID to update
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        if event_report_id is None:
            erid = get_uuid_or_id_from_abstract_misp(event_report)
        else:
            erid = get_uuid_or_id_from_abstract_misp(event_report_id)
        r = self._prepare_request('POST', f'eventReports/edit/{erid}', data=event_report)
        updated_event_report = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in updated_event_report:
            return updated_event_report
        er = MISPEventReport()
        er.from_dict(**updated_event_report)
        return er

    def delete_event_report(self, event_report: MISPEventReport | int | str | UUID, hard: bool = False) -> dict[str, Any] | list[dict[str, Any]]:
        """Delete an event report from a MISP instance

        :param event_report: event report to delete
        :param hard: flag for hard delete
        """
        event_report_id = get_uuid_or_id_from_abstract_misp(event_report)
        request_url = f'eventReports/delete/{event_report_id}'
        data = {}
        if hard:
            data['hard'] = 1
        r = self._prepare_request('POST', request_url, data=data)
        return self._check_json_response(r)
    # ## END Event Report ###

    # ## BEGIN Galaxy Cluster ###
    def attach_galaxy_cluster(self, misp_entity: MISPEvent | MISPAttribute, galaxy_cluster: MISPGalaxyCluster | int | str, local: bool = False, pythonify: bool = False) -> dict[str, Any] | list[dict[str, Any]]:
        """Attach a galaxy cluster to an event or an attribute

        :param misp_entity: a MISP Event or a MISP Attribute
        :param galaxy_cluster: Galaxy cluster to attach
        :param local: whether the object should be attached locally or not to the target
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        if isinstance(misp_entity, MISPEvent):
            attach_target_type = 'event'
        elif isinstance(misp_entity, MISPAttribute):
            attach_target_type = 'attribute'
        else:
            raise PyMISPError('The misp_entity must be MISPEvent or MISPAttribute')

        attach_target_id = misp_entity.id
        local = 1 if local else 0

        if isinstance(galaxy_cluster, MISPGalaxyCluster):
            cluster_id = galaxy_cluster.id
        elif isinstance(galaxy_cluster, (int, str)):
            cluster_id = galaxy_cluster
        else:
            raise PyMISPError('The galaxy_cluster must be MISPGalaxyCluster or the id associated with the cluster (int or str)')

        to_post = {'Galaxy': {'target_id': cluster_id}}
        url = f'galaxies/attachCluster/{attach_target_id}/{attach_target_type}/local:{local}'

        r = self._prepare_request('POST', url, data=to_post)
        return self._check_json_response(r)
    # ## END Galaxy Cluster ###

    # ## BEGIN Analyst Data ###a
    def get_analyst_data(self, analyst_data: AnalystDataBehaviorMixin | int | str | UUID,
                         pythonify: bool = False) -> dict[str, Any] | MISPNote | MISPOpinion | MISPRelationship:
        """Get an analyst data from a MISP instance

        :param analyst_data: analyst data to get
        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        if isinstance(analyst_data, AnalystDataBehaviorMixin):
            analyst_data_type = analyst_data.analyst_data_object_type
        else:
            analyst_data_type = 'all'
        analyst_data_id = get_uuid_or_id_from_abstract_misp(analyst_data)
        r = self._prepare_request('GET', f'analyst_data/view/{analyst_data_type}/{analyst_data_id}')
        analyst_data_r = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in analyst_data_r or analyst_data_type == 'all':
            return analyst_data_r
        er = type(analyst_data)()
        er.from_dict(**analyst_data_r)
        return er

    def add_analyst_data(self, analyst_data: MISPNote | MISPOpinion | MISPRelationship,
                         pythonify: bool = False) -> dict[str, Any] | MISPNote | MISPOpinion | MISPRelationship:
        """Add an analyst data to an existing MISP element

        :param analyst_data: analyst_data to add
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        object_uuid = analyst_data.object_uuid
        object_type = analyst_data.object_type
        r = self._prepare_request('POST', f'analyst_data/add/{analyst_data.analyst_data_object_type}/{object_uuid}/{object_type}', data=analyst_data)
        new_analyst_data = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in new_analyst_data:
            return new_analyst_data
        er = type(analyst_data)()
        er.from_dict(**new_analyst_data)
        return er

    def update_analyst_data(self, analyst_data: MISPNote | MISPOpinion | MISPRelationship, analyst_data_id: int | None = None,
                            pythonify: bool = False) -> dict[str, Any] | MISPNote | MISPOpinion | MISPRelationship:
        """Update an analyst data on a MISP instance

        :param analyst_data: analyst data to update
        :param analyst_data_id: analyst data ID to update
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        if isinstance(analyst_data, AnalystDataBehaviorMixin):
            analyst_data_type = analyst_data.analyst_data_object_type
        else:
            analyst_data_type = 'all'
        if analyst_data_id is None:
            analyst_data_id = get_uuid_or_id_from_abstract_misp(analyst_data)
        r = self._prepare_request('POST', f'analyst_data/edit/{analyst_data_type}/{analyst_data_id}', data=analyst_data)
        updated_analyst_data = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in updated_analyst_data or analyst_data_type == 'all':
            return updated_analyst_data
        er = type(analyst_data)()
        er.from_dict(**updated_analyst_data)
        return er

    def delete_analyst_data(self, analyst_data: MISPNote | MISPOpinion | MISPRelationship | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Delete an analyst data from a MISP instance

        :param analyst_data: analyst data to delete
        """
        if isinstance(analyst_data, AnalystDataBehaviorMixin):
            analyst_data_type = analyst_data.analyst_data_object_type
        else:
            analyst_data_type = 'all'
        analyst_data_id = get_uuid_or_id_from_abstract_misp(analyst_data)
        request_url = f'analyst_data/delete/{analyst_data_type}/{analyst_data_id}'
        r = self._prepare_request('POST', request_url)
        return self._check_json_response(r)

    # ## END Analyst Data ###

    # ## BEGIN Analyst Note ###

    def get_note(self, note: MISPNote, pythonify: bool = False) -> dict[str, Any] | MISPNote:
        """Get a note from a MISP instance

        :param note: note to get
        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        return self.get_analyst_data(note, pythonify)

    def add_note(self, note: MISPNote, pythonify: bool = False) -> dict[str, Any] | MISPNote:
        """Add a note to an existing MISP element

        :param note: note to add
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        return self.add_analyst_data(note, pythonify)

    def update_note(self, note: MISPNote, note_id: int | None = None, pythonify: bool = False) -> dict[str, Any] | MISPNote:
        """Update a note on a MISP instance

        :param note: note to update
        :param note_id: note ID to update
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        return self.update_analyst_data(note, note_id, pythonify)

    def delete_note(self, note: MISPNote | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Delete a note from a MISP instance

        :param note: note delete
        """
        return self.delete_analyst_data(note)

    # ## END Analyst Note ###

    # ## BEGIN Analyst Opinion ###

    def get_opinion(self, opinion: MISPOpinion, pythonify: bool = False) -> dict[str, Any] | MISPOpinion:
        """Get an opinion from a MISP instance

        :param opinion: opinion to get
        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        return self.get_analyst_data(opinion, pythonify)

    def add_opinion(self, opinion: MISPOpinion, pythonify: bool = False) -> dict[str, Any] | MISPOpinion:
        """Add an opinion to an existing MISP element

        :param opinion: opinion to add
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        return self.add_analyst_data(opinion, pythonify)

    def update_opinion(self, opinion: MISPOpinion, opinion_id: int | None = None, pythonify: bool = False) -> dict[str, Any] | MISPOpinion:
        """Update an opinion on a MISP instance

        :param opinion: opinion to update
        :param opinion_id: opinion ID to update
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        return self.update_analyst_data(opinion, opinion_id, pythonify)

    def delete_opinion(self, opinion: MISPOpinion | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Delete an opinion from a MISP instance

        :param opinion: opinion to delete
        """
        return self.delete_analyst_data(opinion)

    # ## END Analyst Opinion ###

    # ## BEGIN Analyst Relationship ###

    def get_relationship(self, relationship: MISPRelationship, pythonify: bool = False) -> dict[str, Any] | MISPRelationship:
        """Get a relationship from a MISP instance

        :param relationship: relationship to get
        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        return self.get_analyst_data(relationship, pythonify)

    def add_relationship(self, relationship: MISPRelationship, pythonify: bool = False) -> dict[str, Any] | MISPRelationship:
        """Add a relationship to an existing MISP element

        :param relationship: relationship to add
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        return self.add_analyst_data(relationship, pythonify)

    def update_relationship(self, relationship: MISPRelationship, relationship_id: int | None = None, pythonify: bool = False) -> dict[str, Any] | MISPRelationship:
        """Update a relationship on a MISP instance

        :param relationship: relationship to update
        :param relationship_id: relationship ID to update
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        return self.update_analyst_data(relationship, relationship_id, pythonify)

    def delete_relationship(self, relationship: MISPRelationship | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Delete a relationship from a MISP instance

        :param relationship: relationship to delete
        """
        return self.delete_analyst_data(relationship)

    # ## END Analyst Relationship ###

    # ## BEGIN Object ###

    def get_object(self, misp_object: MISPObject | int | str | UUID, pythonify: bool = False) -> dict[str, Any] | MISPObject:
        """Get an object from the remote MISP instance: https://www.misp-project.org/openapi/#tag/Objects/operation/getObjectById

        :param misp_object: object to get
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        object_id = get_uuid_or_id_from_abstract_misp(misp_object)
        r = self._prepare_request('GET', f'objects/view/{object_id}')
        misp_object_r = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in misp_object_r:
            return misp_object_r
        o = MISPObject(misp_object_r['Object']['name'], standalone=False)
        o.from_dict(**misp_object_r)
        return o

    def object_exists(self, misp_object: MISPObject | int | str | UUID) -> bool:
        """Fast check if object exists.

        :param misp_object: Attribute to check
        """
        object_id = get_uuid_or_id_from_abstract_misp(misp_object)
        r = self._prepare_request('HEAD', f'objects/view/{object_id}')
        return self._check_head_response(r)

    def add_object(self, event: MISPEvent | int | str | UUID, misp_object: MISPObject, pythonify: bool = False, break_on_duplicate: bool = False) -> dict[str, Any] | MISPObject:
        """Add a MISP Object to an existing MISP event: https://www.misp-project.org/openapi/#tag/Objects/operation/addObject

        :param event: event to extend
        :param misp_object: object to add
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        :param break_on_duplicate: if True, check and reject if this object's attributes match an existing object's attributes; may require much time
        """
        event_id = get_uuid_or_id_from_abstract_misp(event)
        params = {'breakOnDuplicate': 1} if break_on_duplicate else {}
        r = self._prepare_request('POST', f'objects/add/{event_id}', data=misp_object, kw_params=params)
        new_object = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in new_object:
            return new_object
        o = MISPObject(new_object['Object']['name'], standalone=False)
        o.from_dict(**new_object)
        return o

    def update_object(self, misp_object: MISPObject, object_id: int | None = None, pythonify: bool = False) -> dict[str, Any] | MISPObject:
        """Update an object on a MISP instance

        :param misp_object: object to update
        :param object_id: ID of object to update
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        if object_id is None:
            oid = get_uuid_or_id_from_abstract_misp(misp_object)
        else:
            oid = get_uuid_or_id_from_abstract_misp(object_id)
        r = self._prepare_request('POST', f'objects/edit/{oid}', data=misp_object)
        updated_object = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in updated_object:
            return updated_object
        o = MISPObject(updated_object['Object']['name'], standalone=False)
        o.from_dict(**updated_object)
        return o

    def delete_object(self, misp_object: MISPObject | int | str | UUID, hard: bool = False) -> dict[str, Any] | list[dict[str, Any]]:
        """Delete an object from a MISP instance: https://www.misp-project.org/openapi/#tag/Objects/operation/deleteObject

        :param misp_object: object to delete
        :param hard: flag for hard delete
        """
        object_id = get_uuid_or_id_from_abstract_misp(misp_object)
        data = {}
        if hard:
            data['hard'] = 1
        r = self._prepare_request('POST', f'objects/delete/{object_id}', data=data)
        return self._check_json_response(r)

    def add_object_reference(self, misp_object_reference: MISPObjectReference, pythonify: bool = False) -> dict[str, Any] | MISPObjectReference:
        """Add a reference to an object

        :param misp_object_reference: object reference
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        r = self._prepare_request('POST', 'objectReferences/add', misp_object_reference)
        object_reference = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in object_reference:
            return object_reference
        ref = MISPObjectReference()
        ref.from_dict(**object_reference)
        return ref

    def delete_object_reference(
        self,
        object_reference: MISPObjectReference | int | str | UUID,
        hard: bool = False,
    ) -> dict[str, Any] | list[dict[str, Any]]:
        """Delete a reference to an object."""
        object_reference_id = get_uuid_or_id_from_abstract_misp(object_reference)
        query_url = f"objectReferences/delete/{object_reference_id}"
        if hard:
            query_url += "/true"
        response = self._prepare_request("POST", query_url)
        return self._check_json_response(response)

    # Object templates

    def object_templates(self, pythonify: bool = False) -> dict[str, Any] | list[MISPObjectTemplate] | list[dict[str, Any]]:
        """Get all the object templates

        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        r = self._prepare_request('GET', 'objectTemplates/index')
        templates = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or isinstance(templates, dict):
            return templates
        to_return = []
        for object_template in templates:
            o = MISPObjectTemplate()
            o.from_dict(**object_template)
            to_return.append(o)
        return to_return

    def get_object_template(self, object_template: MISPObjectTemplate | int | str | UUID, pythonify: bool = False) -> dict[str, Any] | MISPObjectTemplate:
        """Gets the full object template

        :param object_template: template or ID to get
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        object_template_id = get_uuid_or_id_from_abstract_misp(object_template)
        r = self._prepare_request('GET', f'objectTemplates/view/{object_template_id}')
        object_template_r = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in object_template_r:
            return object_template_r
        t = MISPObjectTemplate()
        t.from_dict(**object_template_r)
        return t

    def get_raw_object_template(self, uuid_or_name: str) -> dict[str, Any] | list[dict[str, Any]]:
        """Get a row template. It needs to be present on disk on the MISP instance you're connected to.
        The response of this method can be passed to MISPObject(<name>, misp_objects_template_custom=<response>)
        """
        r = self._prepare_request('GET', f'objectTemplates/getRaw/{uuid_or_name}')
        return self._check_json_response(r)

    def update_object_templates(self) -> dict[str, Any] | list[dict[str, Any]]:
        """Trigger an update of the object templates"""
        response = self._prepare_request('POST', 'objectTemplates/update')
        return self._check_json_response(response)

    # ## END Object ###

    # ## BEGIN Attribute ###

    def attributes(self, pythonify: bool = False) -> dict[str, Any] | list[MISPAttribute] | list[dict[str, Any]]:
        """Get all the attributes from the MISP instance: https://www.misp-project.org/openapi/#tag/Attributes/operation/getAttributes

        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        r = self._prepare_request('GET', 'attributes/index')
        attributes_r = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or isinstance(attributes_r, dict):
            return attributes_r
        to_return = []
        for attribute in attributes_r:
            a = MISPAttribute()
            a.from_dict(**attribute)
            to_return.append(a)
        return to_return

    def get_attribute(self, attribute: MISPAttribute | int | str | UUID, pythonify: bool = False) -> dict[str, Any] | MISPAttribute:
        """Get an attribute from a MISP instance: https://www.misp-project.org/openapi/#tag/Attributes/operation/getAttributeById

        :param attribute: attribute to get
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        attribute_id = get_uuid_or_id_from_abstract_misp(attribute)
        r = self._prepare_request('GET', f'attributes/view/{attribute_id}')
        attribute_r = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in attribute_r:
            return attribute_r
        a = MISPAttribute()
        a.from_dict(**attribute_r)
        return a

    def attribute_exists(self, attribute: MISPAttribute | int | str | UUID) -> bool:
        """Fast check if attribute exists.

        :param attribute: Attribute to check
        """
        attribute_id = get_uuid_or_id_from_abstract_misp(attribute)
        r = self._prepare_request('HEAD', f'attributes/view/{attribute_id}')
        return self._check_head_response(r)

    def add_attribute(self, event: MISPEvent | int | str | UUID, attribute: MISPAttribute | Iterable[str], pythonify: bool = False, break_on_duplicate: bool = True) -> dict[str, Any] | MISPAttribute | MISPShadowAttribute:
        """Add an attribute to an existing MISP event: https://www.misp-project.org/openapi/#tag/Attributes/operation/addAttribute

        :param event: event to extend
        :param attribute: attribute or (MISP version 2.4.113+) list of attributes to add.
            If a list is passed, the pythonified response is a dict with the following structure:
            {'attributes': [MISPAttribute], 'errors': {errors by attributes}}
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        :param break_on_duplicate: if False, do not fail if the attribute already exists, updates existing attribute instead (timestamp will be always updated)
        """
        params = {'breakOnDuplicate': 0} if break_on_duplicate is not True else {}
        event_id = get_uuid_or_id_from_abstract_misp(event)
        r = self._prepare_request('POST', f'attributes/add/{event_id}', data=attribute, kw_params=params)
        new_attribute = self._check_json_response(r)
        if isinstance(attribute, list):
            # Multiple attributes were passed at once, the handling is totally different
            if not (self.global_pythonify or pythonify):
                return new_attribute
            to_return: dict[str, list[MISPAttribute]] = {'attributes': []}
            if 'errors' in new_attribute:
                to_return['errors'] = new_attribute['errors']

            if len(attribute) == 1:
                # input list size 1 yields dict, not list of size 1
                if 'Attribute' in new_attribute:
                    a = MISPAttribute()
                    a.from_dict(**new_attribute['Attribute'])
                    to_return['attributes'].append(a)
            else:
                for new_attr in new_attribute['Attribute']:
                    a = MISPAttribute()
                    a.from_dict(**new_attr)
                    to_return['attributes'].append(a)
            return to_return

        if ('errors' in new_attribute and new_attribute['errors'][0] == 403
                and new_attribute['errors'][1]['message'] == 'You do not have permission to do that.'):
            # At this point, we assume the user tried to add an attribute on an event they don't own
            # Re-try with a proposal
            if isinstance(attribute, (MISPAttribute, dict)):
                return self.add_attribute_proposal(event_id, attribute, pythonify)  # type: ignore
        if not (self.global_pythonify or pythonify) or 'errors' in new_attribute:
            return new_attribute
        a = MISPAttribute()
        a.from_dict(**new_attribute)
        return a

    def update_attribute(self, attribute: MISPAttribute, attribute_id: int | None = None, pythonify: bool = False) -> dict[str, Any] | MISPAttribute | MISPShadowAttribute:
        """Update an attribute on a MISP instance: https://www.misp-project.org/openapi/#tag/Attributes/operation/editAttribute

        :param attribute: attribute to update
        :param attribute_id: attribute ID to update
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        if attribute_id is None:
            aid = get_uuid_or_id_from_abstract_misp(attribute)
        else:
            aid = get_uuid_or_id_from_abstract_misp(attribute_id)
        r = self._prepare_request('POST', f'attributes/edit/{aid}', data=attribute)
        updated_attribute = self._check_json_response(r)
        if 'errors' in updated_attribute:
            if (updated_attribute['errors'][0] == 403
                    and updated_attribute['errors'][1]['message'] == 'You do not have permission to do that.'):
                # At this point, we assume the user tried to update an attribute on an event they don't own
                # Re-try with a proposal
                return self.update_attribute_proposal(aid, attribute, pythonify)
        if not (self.global_pythonify or pythonify) or 'errors' in updated_attribute:
            return updated_attribute
        a = MISPAttribute()
        a.from_dict(**updated_attribute)
        return a

    def delete_attribute(self, attribute: MISPAttribute | int | str | UUID, hard: bool = False) -> dict[str, Any] | list[dict[str, Any]]:
        """Delete an attribute from a MISP instance: https://www.misp-project.org/openapi/#tag/Attributes/operation/deleteAttribute

        :param attribute: attribute to delete
        :param hard: flag for hard delete
        """
        attribute_id = get_uuid_or_id_from_abstract_misp(attribute)
        data = {}
        if hard:
            data['hard'] = 1
        r = self._prepare_request('POST', f'attributes/delete/{attribute_id}', data=data)
        response = self._check_json_response(r)
        if ('errors' in response and response['errors'][0] == 403
                and response['errors'][1]['message'] == 'You do not have permission to do that.'):
            # FIXME: https://github.com/MISP/MISP/issues/4913
            # At this point, we assume the user tried to delete an attribute on an event they don't own
            # Re-try with a proposal
            return self.delete_attribute_proposal(attribute_id)
        return response

    def restore_attribute(self, attribute: MISPAttribute | int | str | UUID, pythonify: bool = False) -> dict[str, Any] | MISPAttribute:
        """Restore a soft deleted attribute from a MISP instance: https://www.misp-project.org/openapi/#tag/Attributes/operation/restoreAttribute

        :param attribute: attribute to restore
        """
        attribute_id = get_uuid_or_id_from_abstract_misp(attribute)
        r = self._prepare_request('POST', f'attributes/restore/{attribute_id}')
        response = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in response:
            return response
        a = MISPAttribute()
        a.from_dict(**response)
        return a

    # ## END Attribute ###

    # ## BEGIN Attribute Proposal ###

    def attribute_proposals(self, event: MISPEvent | int | str | UUID | None = None, pythonify: bool = False) -> dict[str, Any] | list[MISPShadowAttribute] | list[dict[str, Any]]:
        """Get all the attribute proposals

        :param event: event
        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        if event:
            event_id = get_uuid_or_id_from_abstract_misp(event)
            r = self._prepare_request('GET', f'shadowAttributes/index/{event_id}')
        else:
            r = self._prepare_request('GET', 'shadowAttributes/index')
        attribute_proposals = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or isinstance(attribute_proposals, dict):
            return attribute_proposals
        to_return = []
        for attribute_proposal in attribute_proposals:
            a = MISPShadowAttribute()
            a.from_dict(**attribute_proposal)
            to_return.append(a)
        return to_return

    def get_attribute_proposal(self, proposal: MISPShadowAttribute | int | str | UUID, pythonify: bool = False) -> dict[str, Any] | MISPShadowAttribute:
        """Get an attribute proposal

        :param proposal: proposal to get
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        proposal_id = get_uuid_or_id_from_abstract_misp(proposal)
        r = self._prepare_request('GET', f'shadowAttributes/view/{proposal_id}')
        attribute_proposal = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in attribute_proposal:
            return attribute_proposal
        a = MISPShadowAttribute()
        a.from_dict(**attribute_proposal)
        return a

    # NOTE: the tree following method have a very specific meaning, look at the comments

    def add_attribute_proposal(self, event: MISPEvent | int | str | UUID, attribute: MISPAttribute, pythonify: bool = False) -> dict[str, Any] | MISPShadowAttribute:
        """Propose a new attribute in an event

        :param event: event to receive new attribute
        :param attribute: attribute to propose
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        event_id = get_uuid_or_id_from_abstract_misp(event)
        r = self._prepare_request('POST', f'shadowAttributes/add/{event_id}', data=attribute)
        new_attribute_proposal = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in new_attribute_proposal:
            return new_attribute_proposal
        a = MISPShadowAttribute()
        a.from_dict(**new_attribute_proposal)
        return a

    def update_attribute_proposal(self, initial_attribute: MISPAttribute | int | str | UUID, attribute: MISPAttribute, pythonify: bool = False) -> dict[str, Any] | MISPShadowAttribute:
        """Propose a change for an attribute

        :param initial_attribute: attribute to change
        :param attribute: attribute to propose
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        initial_attribute_id = get_uuid_or_id_from_abstract_misp(initial_attribute)
        r = self._prepare_request('POST', f'shadowAttributes/edit/{initial_attribute_id}', data=attribute)
        update_attribute_proposal = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in update_attribute_proposal:
            return update_attribute_proposal
        a = MISPShadowAttribute()
        a.from_dict(**update_attribute_proposal)
        return a

    def delete_attribute_proposal(self, attribute: MISPAttribute | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Propose the deletion of an attribute

        :param attribute: attribute to delete
        """
        attribute_id = get_uuid_or_id_from_abstract_misp(attribute)
        response = self._prepare_request('POST', f'shadowAttributes/delete/{attribute_id}')
        return self._check_json_response(response)

    def accept_attribute_proposal(self, proposal: MISPShadowAttribute | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Accept a proposal. You cannot modify an existing proposal, only accept/discard

        :param proposal: attribute proposal to accept
        """
        proposal_id = get_uuid_or_id_from_abstract_misp(proposal)
        response = self._prepare_request('POST', f'shadowAttributes/accept/{proposal_id}')
        return self._check_json_response(response)

    def discard_attribute_proposal(self, proposal: MISPShadowAttribute | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Discard a proposal. You cannot modify an existing proposal, only accept/discard

        :param proposal: attribute proposal to discard
        """
        proposal_id = get_uuid_or_id_from_abstract_misp(proposal)
        response = self._prepare_request('POST', f'shadowAttributes/discard/{proposal_id}')
        return self._check_json_response(response)

    # ## END Attribute Proposal ###

    # ## BEGIN Sighting ###

    def sightings(self, misp_entity: AbstractMISP | None = None,
                  org: MISPOrganisation | int | str | UUID | None = None,
                  pythonify: bool = False) -> dict[str, Any] | list[MISPSighting] | list[dict[str, Any]]:
        """Get the list of sightings related to a MISPEvent or a MISPAttribute (depending on type of misp_entity): https://www.misp-project.org/openapi/#tag/Sightings/operation/getSightingsByEventId

        :param misp_entity: MISP entity
        :param org: MISP organization
        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        if isinstance(misp_entity, MISPEvent):
            url = 'sightings/listSightings'
            to_post = {'context': 'event', 'id': misp_entity.id}
        elif isinstance(misp_entity, MISPAttribute):
            url = 'sightings/listSightings'
            to_post = {'context': 'attribute', 'id': misp_entity.id}
        else:
            url = 'sightings/index'
            to_post = {}

        if org is not None:
            org_id = get_uuid_or_id_from_abstract_misp(org)
            to_post['org_id'] = org_id

        r = self._prepare_request('POST', url, data=to_post)
        sightings = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or isinstance(sightings, dict):
            return sightings
        to_return = []
        for sighting in sightings:
            s = MISPSighting()
            s.from_dict(**sighting)
            to_return.append(s)
        return to_return

    def add_sighting(self, sighting: MISPSighting | dict[str, Any],
                     attribute: MISPAttribute | int | str | UUID | None = None,
                     pythonify: bool = False) -> dict[str, Any] | MISPSighting:
        """Add a new sighting (globally, or to a specific attribute): https://www.misp-project.org/openapi/#tag/Sightings/operation/addSighting and https://www.misp-project.org/openapi/#tag/Sightings/operation/getSightingsByEventId

        :param sighting: sighting to add
        :param attribute: specific attribute to modify with the sighting
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        if attribute:
            attribute_id = get_uuid_or_id_from_abstract_misp(attribute)
            r = self._prepare_request('POST', f'sightings/add/{attribute_id}', data=sighting)
        else:
            # Either the ID/UUID is in the sighting, or we want to add a sighting on all the attributes with the given value
            r = self._prepare_request('POST', 'sightings/add', data=sighting)
        new_sighting = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in new_sighting:
            return new_sighting
        s = MISPSighting()
        s.from_dict(**new_sighting)
        return s

    def delete_sighting(self, sighting: MISPSighting | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Delete a sighting from a MISP instance: https://www.misp-project.org/openapi/#tag/Sightings/operation/deleteSighting

        :param sighting: sighting to delete
        """
        sighting_id = get_uuid_or_id_from_abstract_misp(sighting)
        response = self._prepare_request('POST', f'sightings/delete/{sighting_id}')
        return self._check_json_response(response)

    # ## END Sighting ###

    # ## BEGIN Tags ###

    def tags(self, pythonify: bool = False, **kw_params) -> dict[str, Any] | list[MISPTag]:  # type: ignore[no-untyped-def]
        """Get the list of existing tags: https://www.misp-project.org/openapi/#tag/Tags/operation/getTags

        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        r = self._prepare_request('GET', 'tags/index', kw_params=kw_params)
        tags = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in tags:
            return tags['Tag']
        to_return = []
        for tag in tags['Tag']:
            t = MISPTag()
            t.from_dict(**tag)
            to_return.append(t)
        return to_return

    def get_tag(self, tag: MISPTag | int | str | UUID, pythonify: bool = False) -> dict[str, Any] | MISPTag:
        """Get a tag by id: https://www.misp-project.org/openapi/#tag/Tags/operation/getTagById

        :param tag: tag to get
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        tag_id = get_uuid_or_id_from_abstract_misp(tag)
        r = self._prepare_request('GET', f'tags/view/{tag_id}')
        tag_r = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in tag_r:
            return tag_r
        t = MISPTag()
        t.from_dict(**tag_r)
        return t

    def add_tag(self, tag: MISPTag, pythonify: bool = False) -> dict[str, Any] | MISPTag:
        """Add a new tag on a MISP instance: https://www.misp-project.org/openapi/#tag/Tags/operation/addTag
        The user calling this method needs the Tag Editor permission.
        It doesn't add a tag to an event, simply creates it on the MISP instance.

        :param tag: tag to add
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        r = self._prepare_request('POST', 'tags/add', data=tag)
        new_tag = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in new_tag:
            return new_tag
        t = MISPTag()
        t.from_dict(**new_tag)
        return t

    def enable_tag(self, tag: MISPTag, pythonify: bool = False) -> dict[str, Any] | MISPTag:
        """Enable a tag

        :param tag: tag to enable
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        tag.hide_tag = False
        return self.update_tag(tag, pythonify=pythonify)

    def disable_tag(self, tag: MISPTag, pythonify: bool = False) -> dict[str, Any] | MISPTag:
        """Disable a tag

        :param tag: tag to disable
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        tag.hide_tag = True
        return self.update_tag(tag, pythonify=pythonify)

    def update_tag(self, tag: MISPTag, tag_id: int | None = None, pythonify: bool = False) -> dict[str, Any] | MISPTag:
        """Edit only the provided parameters of a tag: https://www.misp-project.org/openapi/#tag/Tags/operation/editTag

        :param tag: tag to update
        :aram tag_id: tag ID to update
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        if tag_id is None:
            tid = get_uuid_or_id_from_abstract_misp(tag)
        else:
            tid = get_uuid_or_id_from_abstract_misp(tag_id)
        r = self._prepare_request('POST', f'tags/edit/{tid}', data=tag)
        updated_tag = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in updated_tag:
            return updated_tag
        t = MISPTag()
        t.from_dict(**updated_tag)
        return t

    def delete_tag(self, tag: MISPTag | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Delete a tag from a MISP instance: https://www.misp-project.org/openapi/#tag/Tags/operation/deleteTag

        :param tag: tag to delete
        """
        tag_id = get_uuid_or_id_from_abstract_misp(tag)
        response = self._prepare_request('POST', f'tags/delete/{tag_id}')
        return self._check_json_response(response)

    def search_tags(self, tagname: str, strict_tagname: bool = False, pythonify: bool = False) -> dict[str, Any] | list[MISPTag] | list[dict[str, Any]]:
        """Search for tags by name: https://www.misp-project.org/openapi/#tag/Tags/operation/searchTag

        :param tag_name: Name to search, use % for substrings matches.
        :param strict_tagname: only return tags matching exactly the tag name (so skipping synonyms and cluster's value)
        """
        query = {'tagname': tagname, 'strict_tagname': strict_tagname}
        response = self._prepare_request('POST', 'tags/search', data=query)
        normalized_response = self._check_json_response(response)
        if not (self.global_pythonify or pythonify) or isinstance(normalized_response, dict):
            return normalized_response
        to_return: list[MISPTag] = []
        for tag in normalized_response:
            t = MISPTag()
            t.from_dict(**tag)
            to_return.append(t)
        return to_return

    # ## END Tags ###

    # ## BEGIN Taxonomies ###

    def taxonomies(self, pythonify: bool = False) -> dict[str, Any] | list[MISPTaxonomy] | list[dict[str, Any]]:
        """Get all the taxonomies: https://www.misp-project.org/openapi/#tag/Taxonomies/operation/getTaxonomies

        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        r = self._prepare_request('GET', 'taxonomies/index')
        taxonomies = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or isinstance(taxonomies, dict):
            return taxonomies
        to_return = []
        for taxonomy in taxonomies:
            t = MISPTaxonomy()
            t.from_dict(**taxonomy)
            to_return.append(t)
        return to_return

    def get_taxonomy(self, taxonomy: MISPTaxonomy | int | str | UUID, pythonify: bool = False) -> dict[str, Any] | MISPTaxonomy:
        """Get a taxonomy by id or namespace from a MISP instance: https://www.misp-project.org/openapi/#tag/Taxonomies/operation/getTaxonomyById

        :param taxonomy: taxonomy to get
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        taxonomy_id = get_uuid_or_id_from_abstract_misp(taxonomy)
        r = self._prepare_request('GET', f'taxonomies/view/{taxonomy_id}')
        taxonomy_r = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in taxonomy_r:
            return taxonomy_r
        t = MISPTaxonomy()
        t.from_dict(**taxonomy_r)
        return t

    def enable_taxonomy(self, taxonomy: MISPTaxonomy | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Enable a taxonomy: https://www.misp-project.org/openapi/#tag/Taxonomies/operation/enableTaxonomy

        :param taxonomy: taxonomy to enable
        """
        taxonomy_id = get_uuid_or_id_from_abstract_misp(taxonomy)
        response = self._prepare_request('POST', f'taxonomies/enable/{taxonomy_id}')
        return self._check_json_response(response)

    def disable_taxonomy(self, taxonomy: MISPTaxonomy | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Disable a taxonomy: https://www.misp-project.org/openapi/#tag/Taxonomies/operation/disableTaxonomy

        :param taxonomy: taxonomy to disable
        """
        taxonomy_id = get_uuid_or_id_from_abstract_misp(taxonomy)
        self.disable_taxonomy_tags(taxonomy_id)
        response = self._prepare_request('POST', f'taxonomies/disable/{taxonomy_id}')
        try:
            return self._check_json_response(response)
        except PyMISPError:
            return self._check_json_response(response)

    def disable_taxonomy_tags(self, taxonomy: MISPTaxonomy | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Disable all the tags of a taxonomy

        :param taxonomy: taxonomy with tags to disable
        """
        taxonomy_id = get_uuid_or_id_from_abstract_misp(taxonomy)
        response = self._prepare_request('POST', f'taxonomies/disableTag/{taxonomy_id}')
        return self._check_json_response(response)

    def enable_taxonomy_tags(self, taxonomy: MISPTaxonomy | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Enable all the tags of a taxonomy. NOTE: this is automatically done when you call enable_taxonomy

        :param taxonomy: taxonomy with tags to enable
        """
        taxonomy_id = get_uuid_or_id_from_abstract_misp(taxonomy)
        t = self.get_taxonomy(taxonomy_id)
        if isinstance(t, MISPTaxonomy):
            if not t.enabled:
                # Can happen if global pythonify is enabled.
                raise PyMISPError(f"The taxonomy {t.namespace} is not enabled.")
        elif not t['Taxonomy']['enabled']:
            raise PyMISPError(f"The taxonomy {t['Taxonomy']['namespace']} is not enabled.")
        url = urljoin(self.root_url, f'taxonomies/addTag/{taxonomy_id}')
        response = self._prepare_request('POST', url)
        return self._check_json_response(response)

    def update_taxonomies(self) -> dict[str, Any] | list[dict[str, Any]]:
        """Update all the taxonomies: https://www.misp-project.org/openapi/#tag/Taxonomies/operation/updateTaxonomies"""
        response = self._prepare_request('POST', 'taxonomies/update')
        return self._check_json_response(response)

    def set_taxonomy_required(self, taxonomy: MISPTaxonomy | int | str, required: bool = False) -> dict[str, Any] | list[dict[str, Any]]:
        taxonomy_id = get_uuid_or_id_from_abstract_misp(taxonomy)
        url = urljoin(self.root_url, f'taxonomies/toggleRequired/{taxonomy_id}')
        payload = {
            "Taxonomy": {
                "required": required
            }
        }
        response = self._prepare_request('POST', url, data=payload)
        return self._check_json_response(response)

    # ## END Taxonomies ###

    # ## BEGIN Warninglists ###

    def warninglists(self, pythonify: bool = False) -> dict[str, Any] | list[MISPWarninglist]:
        """Get all the warninglists: https://www.misp-project.org/openapi/#tag/Warninglists/operation/getWarninglists

        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        r = self._prepare_request('GET', 'warninglists/index')
        warninglists = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in warninglists:
            return warninglists['Warninglists']
        to_return = []
        for warninglist in warninglists['Warninglists']:
            w = MISPWarninglist()
            w.from_dict(**warninglist)
            to_return.append(w)
        return to_return

    def get_warninglist(self, warninglist: MISPWarninglist | int | str | UUID, pythonify: bool = False) -> dict[str, Any] | MISPWarninglist:
        """Get a warninglist by id: https://www.misp-project.org/openapi/#tag/Warninglists/operation/getWarninglistById

        :param warninglist: warninglist to get
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        warninglist_id = get_uuid_or_id_from_abstract_misp(warninglist)
        r = self._prepare_request('GET', f'warninglists/view/{warninglist_id}')
        wl = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in wl:
            return wl
        w = MISPWarninglist()
        w.from_dict(**wl)
        return w

    def toggle_warninglist(self, warninglist_id: str | int | list[int] | None = None, warninglist_name: str | list[str] | None = None, force_enable: bool | None = None) -> dict[str, Any] | list[dict[str, Any]]:
        '''Toggle (enable/disable) the status of a warninglist by id: https://www.misp-project.org/openapi/#tag/Warninglists/operation/toggleEnableWarninglist

        :param warninglist_id: ID of the WarningList
        :param warninglist_name: name of the WarningList
        :param force_enable: Force the warning list in the enabled state (does nothing if already enabled) - None means toggle.
        '''
        if warninglist_id is None and warninglist_name is None:
            raise PyMISPError('Either warninglist_id or warninglist_name is required.')
        query: dict[str, list[str] | list[int] | bool] = {}
        if warninglist_id is not None:
            if isinstance(warninglist_id, list):
                query['id'] = warninglist_id
            else:
                query['id'] = [warninglist_id]  # type: ignore
        if warninglist_name is not None:
            if isinstance(warninglist_name, list):
                query['name'] = warninglist_name
            else:
                query['name'] = [warninglist_name]
        if force_enable is not None:
            query['enabled'] = force_enable
        response = self._prepare_request('POST', 'warninglists/toggleEnable', data=query)
        return self._check_json_response(response)

    def enable_warninglist(self, warninglist: MISPWarninglist | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Enable a warninglist

        :param warninglist: warninglist to enable
        """
        warninglist_id = get_uuid_or_id_from_abstract_misp(warninglist)
        return self.toggle_warninglist(warninglist_id=warninglist_id, force_enable=True)

    def disable_warninglist(self, warninglist: MISPWarninglist | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Disable a warninglist

        :param warninglist: warninglist to disable
        """
        warninglist_id = get_uuid_or_id_from_abstract_misp(warninglist)
        return self.toggle_warninglist(warninglist_id=warninglist_id, force_enable=False)

    def values_in_warninglist(self, value: Iterable[str]) -> dict[str, Any] | list[dict[str, Any]]:
        """Check if IOC values are in warninglist

        :param value: iterator with values to check
        """
        response = self._prepare_request('POST', 'warninglists/checkValue', data=value)
        try:
            return self._check_json_response(response)
        except PyMISPError:
            return self._check_json_response(response)

    def update_warninglists(self) -> dict[str, Any] | list[dict[str, Any]]:
        """Update all the warninglists: https://www.misp-project.org/openapi/#tag/Warninglists/operation/updateWarninglists"""
        response = self._prepare_request('POST', 'warninglists/update')
        return self._check_json_response(response)

    # ## END Warninglists ###

    # ## BEGIN Noticelist ###

    def noticelists(self, pythonify: bool = False) -> dict[str, Any] | list[MISPNoticelist] | list[dict[str, Any]]:
        """Get all the noticelists: https://www.misp-project.org/openapi/#tag/Noticelists/operation/getNoticelists

        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        r = self._prepare_request('GET', 'noticelists/index')
        noticelists = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or isinstance(noticelists, dict):
            return noticelists
        to_return = []
        for noticelist in noticelists:
            n = MISPNoticelist()
            n.from_dict(**noticelist)
            to_return.append(n)
        return to_return

    def get_noticelist(self, noticelist: MISPNoticelist | int | str | UUID, pythonify: bool = False) -> dict[str, Any] | MISPNoticelist:
        """Get a noticelist by id: https://www.misp-project.org/openapi/#tag/Noticelists/operation/getNoticelistById

        :param notistlist: Noticelist to get
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        noticelist_id = get_uuid_or_id_from_abstract_misp(noticelist)
        r = self._prepare_request('GET', f'noticelists/view/{noticelist_id}')
        noticelist_j = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in noticelist_j:
            return noticelist_j
        n = MISPNoticelist()
        n.from_dict(**noticelist_j)
        return n

    def enable_noticelist(self, noticelist: MISPNoticelist | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Enable a noticelist by id: https://www.misp-project.org/openapi/#tag/Noticelists/operation/toggleEnableNoticelist

        :param noticelist: Noticelist to enable
        """
        # FIXME: https://github.com/MISP/MISP/issues/4856
        # response = self._prepare_request('POST', f'noticelists/enable/{noticelist_id}')
        noticelist_id = get_uuid_or_id_from_abstract_misp(noticelist)
        response = self._prepare_request('POST', f'noticelists/enableNoticelist/{noticelist_id}/true')
        return self._check_json_response(response)

    def disable_noticelist(self, noticelist: MISPNoticelist | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Disable a noticelist by id

        :param noticelist: Noticelist to disable
        """
        # FIXME: https://github.com/MISP/MISP/issues/4856
        # response = self._prepare_request('POST', f'noticelists/disable/{noticelist_id}')
        noticelist_id = get_uuid_or_id_from_abstract_misp(noticelist)
        response = self._prepare_request('POST', f'noticelists/enableNoticelist/{noticelist_id}')
        return self._check_json_response(response)

    def update_noticelists(self) -> dict[str, Any] | list[dict[str, Any]]:
        """Update all the noticelists: https://www.misp-project.org/openapi/#tag/Noticelists/operation/updateNoticelists"""
        response = self._prepare_request('POST', 'noticelists/update')
        return self._check_json_response(response)

    # ## END Noticelist ###

    # ## BEGIN Correlation Exclusions ###

    def correlation_exclusions(self, pythonify: bool = False) -> dict[str, Any] | list[MISPCorrelationExclusion] | list[dict[str, Any]]:
        """Get all the correlation exclusions

        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        r = self._prepare_request('GET', 'correlation_exclusions')
        correlation_exclusions = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or isinstance(correlation_exclusions, dict):
            return correlation_exclusions
        to_return = []
        for correlation_exclusion in correlation_exclusions:
            c = MISPCorrelationExclusion()
            c.from_dict(**correlation_exclusion)
            to_return.append(c)
        return to_return

    def get_correlation_exclusion(self, correlation_exclusion: MISPCorrelationExclusion | int | str | UUID, pythonify: bool = False) -> dict[str, Any] | MISPCorrelationExclusion:
        """Get a correlation exclusion by ID

        :param correlation_exclusion: Correlation exclusion to get
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        exclusion_id = get_uuid_or_id_from_abstract_misp(correlation_exclusion)
        r = self._prepare_request('GET', f'correlation_exclusions/view/{exclusion_id}')
        correlation_exclusion_j = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in correlation_exclusion_j:
            return correlation_exclusion_j
        c = MISPCorrelationExclusion()
        c.from_dict(**correlation_exclusion_j)
        return c

    def add_correlation_exclusion(self, correlation_exclusion: MISPCorrelationExclusion, pythonify: bool = False) -> dict[str, Any] | MISPCorrelationExclusion:
        """Add a new correlation exclusion

        :param correlation_exclusion: correlation exclusion to add
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        r = self._prepare_request('POST', 'correlation_exclusions/add', data=correlation_exclusion)
        new_correlation_exclusion = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in new_correlation_exclusion:
            return new_correlation_exclusion
        c = MISPCorrelationExclusion()
        c.from_dict(**new_correlation_exclusion)
        return c

    def delete_correlation_exclusion(self, correlation_exclusion: MISPCorrelationExclusion | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Delete a correlation exclusion

        :param correlation_exclusion: The MISPCorrelationExclusion you wish to delete from MISP
        """
        exclusion_id = get_uuid_or_id_from_abstract_misp(correlation_exclusion)
        r = self._prepare_request('POST', f'correlation_exclusions/delete/{exclusion_id}')
        return self._check_json_response(r)

    def clean_correlation_exclusions(self) -> dict[str, Any] | list[dict[str, Any]]:
        """Initiate correlation exclusions cleanup"""
        r = self._prepare_request('POST', 'correlation_exclusions/clean')
        return self._check_json_response(r)

    # ## END Correlation Exclusions ###

    # ## BEGIN Galaxy ###

    def galaxies(
        self,
        withCluster: bool = False,
        pythonify: bool = False,
    ) -> dict[str, Any] | list[MISPGalaxy] | list[dict[str, Any]]:
        """Get all the galaxies: https://www.misp-project.org/openapi/#tag/Galaxies/operation/getGalaxies

        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        r = self._prepare_request('GET', 'galaxies/index')
        galaxies = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or isinstance(galaxies, dict):
            return galaxies
        to_return = []
        for galaxy in galaxies:
            g = MISPGalaxy()
            g.from_dict(**galaxy, withCluster=withCluster)
            to_return.append(g)
        return to_return

    def search_galaxy(
        self,
        value: str,
        withCluster: bool = False,
        pythonify: bool = False,
    ) -> dict[str, Any] | list[MISPGalaxy] | list[dict[str, Any]]:
        """Text search to find a matching galaxy name, namespace, description, or uuid."""
        r = self._prepare_request("POST", "galaxies", data={"value": value})
        galaxies = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or isinstance(galaxies, dict):
            return galaxies
        to_return = []
        for galaxy in galaxies:
            g = MISPGalaxy()
            g.from_dict(**galaxy, withCluster=withCluster)
            to_return.append(g)
        return to_return

    def get_galaxy(self, galaxy: MISPGalaxy | int | str | UUID, withCluster: bool = False, pythonify: bool = False) -> dict[str, Any] | MISPGalaxy:
        """Get a galaxy by id: https://www.misp-project.org/openapi/#tag/Galaxies/operation/getGalaxyById

        :param galaxy: galaxy to get
        :param withCluster: Include the clusters associated with the galaxy
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        galaxy_id = get_uuid_or_id_from_abstract_misp(galaxy)
        r = self._prepare_request('GET', f'galaxies/view/{galaxy_id}')
        galaxy_j = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in galaxy_j:
            return galaxy_j
        g = MISPGalaxy()
        g.from_dict(**galaxy_j, withCluster=withCluster)
        return g

    def search_galaxy_clusters(self, galaxy: MISPGalaxy | int | str | UUID, context: str = "all", searchall: str | None = None, pythonify: bool = False) -> dict[str, Any] | list[MISPGalaxyCluster] | list[dict[str, Any]]:
        """Searches the galaxy clusters within a specific galaxy: https://www.misp-project.org/openapi/#tag/Galaxy-Clusters/operation/getGalaxyClusters and https://www.misp-project.org/openapi/#tag/Galaxy-Clusters/operation/getGalaxyClusterById

        :param galaxy: The MISPGalaxy you wish to search in
        :param context: The context of how you want to search within the galaxy_
        :param searchall: The search you want to make against the galaxy and context
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """

        galaxy_id = get_uuid_or_id_from_abstract_misp(galaxy)
        allowed_context_types: list[str] = ["all", "default", "custom", "org", "orgc", "deleted"]
        if context not in allowed_context_types:
            raise PyMISPError(f"The context must be one of {', '.join(allowed_context_types)}")
        kw_params = {"context": context}
        if searchall:
            kw_params["searchall"] = searchall
        r = self._prepare_request('POST', f"galaxy_clusters/index/{galaxy_id}", data=kw_params)
        clusters_j = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or isinstance(clusters_j, dict):
            return clusters_j
        response = []
        for cluster in clusters_j:
            c = MISPGalaxyCluster()
            c.from_dict(**cluster)
            response.append(c)
        return response

    def update_galaxies(self) -> dict[str, Any] | list[dict[str, Any]]:
        """Update all the galaxies: https://www.misp-project.org/openapi/#tag/Galaxies/operation/updateGalaxies"""
        response = self._prepare_request('POST', 'galaxies/update')
        return self._check_json_response(response)

    def get_galaxy_cluster(self, galaxy_cluster: MISPGalaxyCluster | int | str | UUID, pythonify: bool = False) -> dict[str, Any] | MISPGalaxyCluster:
        """Gets a specific galaxy cluster

        :param galaxy_cluster: The MISPGalaxyCluster you want to get
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """

        cluster_id = get_uuid_or_id_from_abstract_misp(galaxy_cluster)
        r = self._prepare_request('GET', f'galaxy_clusters/view/{cluster_id}')
        cluster_j = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in cluster_j:
            return cluster_j
        gc = MISPGalaxyCluster()
        gc.from_dict(**cluster_j)
        return gc

    def add_galaxy_cluster(self, galaxy: MISPGalaxy | str | UUID, galaxy_cluster: MISPGalaxyCluster, pythonify: bool = False) -> dict[str, Any] | MISPGalaxyCluster:
        """Add a new galaxy cluster to a MISP Galaxy: https://www.misp-project.org/openapi/#tag/Galaxy-Clusters/operation/addGalaxyCluster

        :param galaxy: A MISPGalaxy (or UUID) where you wish to add the galaxy cluster
        :param galaxy_cluster: A MISPGalaxyCluster you wish to add
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """

        if getattr(galaxy_cluster, "default", False):
            # We can't add default galaxies
            raise PyMISPError('You are not able add a default galaxy cluster')
        galaxy_id = get_uuid_or_id_from_abstract_misp(galaxy)
        r = self._prepare_request('POST', f'galaxy_clusters/add/{galaxy_id}', data=galaxy_cluster)
        cluster_j = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in cluster_j:
            return cluster_j
        gc = MISPGalaxyCluster()
        gc.from_dict(**cluster_j)
        return gc

    def update_galaxy_cluster(self, galaxy_cluster: MISPGalaxyCluster, pythonify: bool = False) -> dict[str, Any] | MISPGalaxyCluster:
        """Update a custom galaxy cluster: https://www.misp-project.org/openapi/#tag/Galaxy-Clusters/operation/editGalaxyCluster

        ;param galaxy_cluster: The MISPGalaxyCluster you wish to update
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """

        if getattr(galaxy_cluster, "default", False):
            # We can't edit default galaxies
            raise PyMISPError('You are not able to update a default galaxy cluster')
        cluster_id = get_uuid_or_id_from_abstract_misp(galaxy_cluster)
        r = self._prepare_request('POST', f'galaxy_clusters/edit/{cluster_id}', data=galaxy_cluster)
        cluster_j = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in cluster_j:
            return cluster_j
        gc = MISPGalaxyCluster()
        gc.from_dict(**cluster_j)
        return gc

    def publish_galaxy_cluster(self, galaxy_cluster: MISPGalaxyCluster | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Publishes a galaxy cluster: https://www.misp-project.org/openapi/#tag/Galaxy-Clusters/operation/publishGalaxyCluster

        :param galaxy_cluster: The galaxy cluster you wish to publish
        """
        if isinstance(galaxy_cluster, MISPGalaxyCluster) and getattr(galaxy_cluster, "default", False):
            raise PyMISPError('You are not able to publish a default galaxy cluster')
        cluster_id = get_uuid_or_id_from_abstract_misp(galaxy_cluster)
        r = self._prepare_request('POST', f'galaxy_clusters/publish/{cluster_id}')
        response = self._check_json_response(r)
        return response

    def fork_galaxy_cluster(self, galaxy: MISPGalaxy | int | str | UUID, galaxy_cluster: MISPGalaxyCluster, pythonify: bool = False) -> dict[str, Any] | MISPGalaxyCluster:
        """Forks an existing galaxy cluster, creating a new one with matching attributes

        :param galaxy: The galaxy (or galaxy ID) where the cluster you want to fork resides
        :param galaxy_cluster: The galaxy cluster you wish to fork
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """

        galaxy_id = get_uuid_or_id_from_abstract_misp(galaxy)
        cluster_id = get_uuid_or_id_from_abstract_misp(galaxy_cluster)
        # Create a duplicate cluster from the cluster to fork
        forked_galaxy_cluster = MISPGalaxyCluster()
        forked_galaxy_cluster.from_dict(**galaxy_cluster)
        # Set the UUID and version it extends from the existing galaxy cluster
        forked_galaxy_cluster.extends_uuid = forked_galaxy_cluster.pop('uuid')
        forked_galaxy_cluster.extends_version = forked_galaxy_cluster.pop('version')
        r = self._prepare_request('POST', f'galaxy_clusters/add/{galaxy_id}/forkUUID:{cluster_id}', data=galaxy_cluster)
        cluster_j = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in cluster_j:
            return cluster_j
        gc = MISPGalaxyCluster()
        gc.from_dict(**cluster_j)
        return gc

    def delete_galaxy_cluster(self, galaxy_cluster: MISPGalaxyCluster | int | str | UUID, hard: bool=False) -> dict[str, Any] | list[dict[str, Any]]:
        """Deletes a galaxy cluster from MISP: https://www.misp-project.org/openapi/#tag/Galaxy-Clusters/operation/deleteGalaxyCluster

        :param galaxy_cluster: The MISPGalaxyCluster you wish to delete from MISP
        :param hard: flag for hard delete
        """

        if isinstance(galaxy_cluster, MISPGalaxyCluster) and getattr(galaxy_cluster, "default", False):
            raise PyMISPError('You are not able to delete a default galaxy cluster')
        data = {}
        if hard:
            data['hard'] = 1
        cluster_id = get_uuid_or_id_from_abstract_misp(galaxy_cluster)
        r = self._prepare_request('POST', f'galaxy_clusters/delete/{cluster_id}', data=data)
        return self._check_json_response(r)

    def add_galaxy_cluster_relation(self, galaxy_cluster_relation: MISPGalaxyClusterRelation) -> dict[str, Any] | list[dict[str, Any]]:
        """Add a galaxy cluster relation, cluster relation must include
        cluster UUIDs in both directions

        :param galaxy_cluster_relation: The MISPGalaxyClusterRelation to add
        """
        r = self._prepare_request('POST', 'galaxy_cluster_relations/add/', data=galaxy_cluster_relation)
        cluster_rel_j = self._check_json_response(r)
        return cluster_rel_j

    def update_galaxy_cluster_relation(self, galaxy_cluster_relation: MISPGalaxyClusterRelation) -> dict[str, Any] | list[dict[str, Any]]:
        """Update a galaxy cluster relation

        :param galaxy_cluster_relation: The MISPGalaxyClusterRelation to update
        """
        cluster_relation_id = get_uuid_or_id_from_abstract_misp(galaxy_cluster_relation)
        r = self._prepare_request('POST', f'galaxy_cluster_relations/edit/{cluster_relation_id}', data=galaxy_cluster_relation)
        cluster_rel_j = self._check_json_response(r)
        return cluster_rel_j

    def delete_galaxy_cluster_relation(self, galaxy_cluster_relation: MISPGalaxyClusterRelation | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Delete a galaxy cluster relation

        :param galaxy_cluster_relation: The MISPGalaxyClusterRelation to delete
        """
        cluster_relation_id = get_uuid_or_id_from_abstract_misp(galaxy_cluster_relation)
        r = self._prepare_request('POST', f'galaxy_cluster_relations/delete/{cluster_relation_id}')
        cluster_rel_j = self._check_json_response(r)
        return cluster_rel_j

    # ## END Galaxy ###

    # ## BEGIN Feed ###

    def feeds(self, pythonify: bool = False) -> dict[str, Any] | list[MISPFeed] | list[dict[str, Any]]:
        """Get the list of existing feeds: https://www.misp-project.org/openapi/#tag/Feeds/operation/getFeeds

        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        r = self._prepare_request('GET', 'feeds/index')
        feeds = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or isinstance(feeds, dict):
            return feeds
        to_return = []
        for feed in feeds:
            f = MISPFeed()
            f.from_dict(**feed)
            to_return.append(f)
        return to_return

    def get_feed(self, feed: MISPFeed | int | str | UUID, pythonify: bool = False) -> dict[str, Any] | MISPFeed:
        """Get a feed by id: https://www.misp-project.org/openapi/#tag/Feeds/operation/getFeedById

        :param feed: feed to get
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        feed_id = get_uuid_or_id_from_abstract_misp(feed)
        r = self._prepare_request('GET', f'feeds/view/{feed_id}')
        feed_j = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in feed_j:
            return feed_j
        f = MISPFeed()
        f.from_dict(**feed_j)
        return f

    def add_feed(self, feed: MISPFeed, pythonify: bool = False) -> dict[str, Any] | MISPFeed:
        """Add a new feed on a MISP instance: https://www.misp-project.org/openapi/#tag/Feeds/operation/addFeed

        :param feed: feed to add
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        # FIXME: https://github.com/MISP/MISP/issues/4834
        r = self._prepare_request('POST', 'feeds/add', data={'Feed': feed})
        new_feed = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in new_feed:
            return new_feed
        f = MISPFeed()
        f.from_dict(**new_feed)
        return f

    def enable_feed(self, feed: MISPFeed | int | str | UUID, pythonify: bool = False) -> dict[str, Any] | MISPFeed:
        """Enable a feed; fetching it will create event(s): https://www.misp-project.org/openapi/#tag/Feeds/operation/enableFeed

        :param feed: feed to enable
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        if not isinstance(feed, MISPFeed):
            feed_id = get_uuid_or_id_from_abstract_misp(feed)  # In case we have a UUID
            f = MISPFeed()
            f.id = feed_id
        else:
            f = feed
        f.enabled = True
        return self.update_feed(feed=f, pythonify=pythonify)

    def disable_feed(self, feed: MISPFeed | int | str | UUID, pythonify: bool = False) -> dict[str, Any] | MISPFeed:
        """Disable a feed: https://www.misp-project.org/openapi/#tag/Feeds/operation/disableFeed

        :param feed: feed to disable
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        if not isinstance(feed, MISPFeed):
            feed_id = get_uuid_or_id_from_abstract_misp(feed)  # In case we have a UUID
            f = MISPFeed()
            f.id = feed_id
        else:
            f = feed
        f.enabled = False
        return self.update_feed(feed=f, pythonify=pythonify)

    def enable_feed_cache(self, feed: MISPFeed | int | str | UUID, pythonify: bool = False) -> dict[str, Any] | MISPFeed:
        """Enable the caching of a feed

        :param feed: feed to enable caching
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        if not isinstance(feed, MISPFeed):
            feed_id = get_uuid_or_id_from_abstract_misp(feed)  # In case we have a UUID
            f = MISPFeed()
            f.id = feed_id
        else:
            f = feed
        f.caching_enabled = True
        return self.update_feed(feed=f, pythonify=pythonify)

    def disable_feed_cache(self, feed: MISPFeed | int | str | UUID, pythonify: bool = False) -> dict[str, Any] | MISPFeed:
        """Disable the caching of a feed

        :param feed: feed to disable caching
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        if not isinstance(feed, MISPFeed):
            feed_id = get_uuid_or_id_from_abstract_misp(feed)  # In case we have a UUID
            f = MISPFeed()
            f.id = feed_id
        else:
            f = feed
        f.caching_enabled = False
        return self.update_feed(feed=f, pythonify=pythonify)

    def update_feed(self, feed: MISPFeed, feed_id: int | None = None, pythonify: bool = False) -> dict[str, Any] | MISPFeed:
        """Update a feed on a MISP instance

        :param feed: feed to update
        :param feed_id: feed id
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        if feed_id is None:
            fid = get_uuid_or_id_from_abstract_misp(feed)
        else:
            fid = get_uuid_or_id_from_abstract_misp(feed_id)
        # FIXME: https://github.com/MISP/MISP/issues/4834
        r = self._prepare_request('POST', f'feeds/edit/{fid}', data={'Feed': feed})
        updated_feed = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in updated_feed:
            return updated_feed
        f = MISPFeed()
        f.from_dict(**updated_feed)
        return f

    def delete_feed(self, feed: MISPFeed | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Delete a feed from a MISP instance

        :param feed: feed to delete
        """
        feed_id = get_uuid_or_id_from_abstract_misp(feed)
        response = self._prepare_request('POST', f'feeds/delete/{feed_id}')
        return self._check_json_response(response)

    def fetch_feed(self, feed: MISPFeed | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Fetch one single feed by id: https://www.misp-project.org/openapi/#tag/Feeds/operation/fetchFromFeed

        :param feed: feed to fetch
        """
        feed_id = get_uuid_or_id_from_abstract_misp(feed)
        response = self._prepare_request('GET', f'feeds/fetchFromFeed/{feed_id}')
        return self._check_json_response(response)

    def cache_all_feeds(self) -> dict[str, Any] | list[dict[str, Any]]:
        """ Cache all the feeds: https://www.misp-project.org/openapi/#tag/Feeds/operation/cacheFeeds"""
        response = self._prepare_request('GET', 'feeds/cacheFeeds/all')
        return self._check_json_response(response)

    def cache_feed(self, feed: MISPFeed | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Cache a specific feed by id: https://www.misp-project.org/openapi/#tag/Feeds/operation/cacheFeeds

        :param feed: feed to cache
        """
        feed_id = get_uuid_or_id_from_abstract_misp(feed)
        response = self._prepare_request('GET', f'feeds/cacheFeeds/{feed_id}')
        return self._check_json_response(response)

    def cache_freetext_feeds(self) -> dict[str, Any] | list[dict[str, Any]]:
        """Cache all the freetext feeds"""
        response = self._prepare_request('GET', 'feeds/cacheFeeds/freetext')
        return self._check_json_response(response)

    def cache_misp_feeds(self) -> dict[str, Any] | list[dict[str, Any]]:
        """Cache all the MISP feeds"""
        response = self._prepare_request('GET', 'feeds/cacheFeeds/misp')
        return self._check_json_response(response)

    def compare_feeds(self) -> dict[str, Any] | list[dict[str, Any]]:
        """Generate the comparison matrix for all the MISP feeds"""
        response = self._prepare_request('GET', 'feeds/compareFeeds')
        return self._check_json_response(response)

    def load_default_feeds(self) -> dict[str, Any] | list[dict[str, Any]]:
        """Load all the default feeds."""
        response = self._prepare_request('POST', 'feeds/loadDefaultFeeds')
        return self._check_json_response(response)

    # ## END Feed ###

    # ## BEGIN Server ###

    def servers(self, pythonify: bool = False) -> dict[str, Any] | list[MISPServer] | list[dict[str, Any]]:
        """Get the existing servers the MISP instance can synchronise with: https://www.misp-project.org/openapi/#tag/Servers/operation/getServers

        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        r = self._prepare_request('GET', 'servers/index')
        servers = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or isinstance(servers, dict):
            return servers
        to_return = []
        for server in servers:
            s = MISPServer()
            s.from_dict(**server)
            to_return.append(s)
        return to_return

    def get_sync_config(self, pythonify: bool = False) -> dict[str, Any] | MISPServer:
        """Get the sync server config.
        WARNING: This method only works if the user calling it is a sync user

        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        r = self._prepare_request('GET', 'servers/createSync')
        server = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in server:
            return server
        s = MISPServer()
        s.from_dict(**server)
        return s

    def import_server(self, server: MISPServer, pythonify: bool = False) -> dict[str, Any] | MISPServer:
        """Import a sync server config received from get_sync_config

        :param server: sync server config
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        r = self._prepare_request('POST', 'servers/import', data=server)
        server_j = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in server_j:
            return server_j
        s = MISPServer()
        s.from_dict(**server_j)
        return s

    def add_server(self, server: MISPServer, pythonify: bool = False) -> dict[str, Any] | MISPServer:
        """Add a server to synchronise with: https://www.misp-project.org/openapi/#tag/Servers/operation/getServers
        Note: You probably want to use PyMISP.get_sync_config and PyMISP.import_server instead

        :param server: sync server config
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        r = self._prepare_request('POST', 'servers/add', data=server)
        server_j = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in server_j:
            return server_j
        s = MISPServer()
        s.from_dict(**server_j)
        return s

    def update_server(self, server: MISPServer, server_id: int | None = None, pythonify: bool = False) -> dict[str, Any] | MISPServer:
        """Update a server to synchronise with: https://www.misp-project.org/openapi/#tag/Servers/operation/getServers

        :param server: sync server config
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        if server_id is None:
            sid = get_uuid_or_id_from_abstract_misp(server)
        else:
            sid = get_uuid_or_id_from_abstract_misp(server_id)
        r = self._prepare_request('POST', f'servers/edit/{sid}', data=server)
        updated_server = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in updated_server:
            return updated_server
        s = MISPServer()
        s.from_dict(**updated_server)
        return s

    def delete_server(self, server: MISPServer | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Delete a sync server: https://www.misp-project.org/openapi/#tag/Servers/operation/getServers

        :param server: sync server config
        """
        server_id = get_uuid_or_id_from_abstract_misp(server)
        response = self._prepare_request('POST', f'servers/delete/{server_id}')
        return self._check_json_response(response)

    def server_pull(self, server: MISPServer | int | str | UUID, event: MISPEvent | int | str | UUID | None = None) -> dict[str, Any] | list[dict[str, Any]]:
        """Initialize a pull from a sync server, optionally limited to one event: https://www.misp-project.org/openapi/#tag/Servers/operation/pullServer

        :param server: sync server config
        :param event: event
        """
        server_id = get_uuid_or_id_from_abstract_misp(server)
        if event:
            event_id = get_uuid_or_id_from_abstract_misp(event)
            url = f'servers/pull/{server_id}/{event_id}'
        else:
            url = f'servers/pull/{server_id}'
        response = self._prepare_request('GET', url)
        # FIXME: can we pythonify?
        return self._check_json_response(response)

    def server_push(self, server: MISPServer | int | str | UUID, event: MISPEvent | int | str | UUID | None = None) -> dict[str, Any] | list[dict[str, Any]]:
        """Initialize a push to a sync server, optionally limited to one event: https://www.misp-project.org/openapi/#tag/Servers/operation/pushServer

        :param server: sync server config
        :param event: event
        """
        server_id = get_uuid_or_id_from_abstract_misp(server)
        if event:
            event_id = get_uuid_or_id_from_abstract_misp(event)
            url = f'servers/push/{server_id}/{event_id}'
        else:
            url = f'servers/push/{server_id}'
        response = self._prepare_request('GET', url)
        # FIXME: can we pythonify?
        return self._check_json_response(response)

    def test_server(self, server: MISPServer | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Test if a sync link is working as expected

        :param server: sync server config
        """
        server_id = get_uuid_or_id_from_abstract_misp(server)
        response = self._prepare_request('POST', f'servers/testConnection/{server_id}')
        return self._check_json_response(response)

    # ## END Server ###

    # ## BEGIN Sharing group ###

    def sharing_groups(self, pythonify: bool = False) -> dict[str, Any] | list[MISPSharingGroup] | list[dict[str, Any]]:
        """Get the existing sharing groups: https://www.misp-project.org/openapi/#tag/Sharing-Groups/operation/getSharingGroup

        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        r = self._prepare_request('GET', 'sharingGroups/index')
        sharing_groups = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or isinstance(sharing_groups, dict):
            return sharing_groups
        to_return = []
        for sharing_group in sharing_groups:
            s = MISPSharingGroup()
            s.from_dict(**sharing_group)
            to_return.append(s)
        return to_return

    def get_sharing_group(self, sharing_group: MISPSharingGroup | int | str | UUID, pythonify: bool = False) -> dict[str, Any] | MISPSharingGroup:
        """Get a sharing group: https://www.misp-project.org/openapi/#tag/Sharing-Groups/operation/getSharingGroupById

        :param sharing_group: sharing group to find
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        sharing_group_id = get_uuid_or_id_from_abstract_misp(sharing_group)
        r = self._prepare_request('GET', f'sharing_groups/view/{sharing_group_id}')
        sharing_group_resp = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in sharing_group_resp:
            return sharing_group_resp
        s = MISPSharingGroup()
        s.from_dict(**sharing_group_resp)
        return s

    def add_sharing_group(self, sharing_group: MISPSharingGroup, pythonify: bool = False) -> dict[str, Any] | MISPSharingGroup:
        """Add a new sharing group: https://www.misp-project.org/openapi/#tag/Sharing-Groups/operation/addSharingGroup

        :param sharing_group: sharing group to add
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        r = self._prepare_request('POST', 'sharingGroups/add', data=sharing_group)
        sharing_group_j = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in sharing_group_j:
            return sharing_group_j
        s = MISPSharingGroup()
        s.from_dict(**sharing_group_j)
        return s

    def update_sharing_group(self, sharing_group: MISPSharingGroup | dict[str, Any], sharing_group_id: int | None = None, pythonify: bool = False) -> dict[str, Any] | MISPSharingGroup:
        """Update sharing group parameters: https://www.misp-project.org/openapi/#tag/Sharing-Groups/operation/editSharingGroup

        :param sharing_group: MISP Sharing Group
        :param sharing_group_id Sharing group ID
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        if sharing_group_id is None:
            sid = get_uuid_or_id_from_abstract_misp(sharing_group)
        else:
            sid = get_uuid_or_id_from_abstract_misp(sharing_group_id)
        sharing_group.pop('modified', None)  # Quick fix for https://github.com/MISP/PyMISP/issues/1049 - remove when fixed in MISP.
        r = self._prepare_request('POST', f'sharing_groups/edit/{sid}', data=sharing_group)
        updated_sharing_group = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in updated_sharing_group:
            return updated_sharing_group
        s = MISPSharingGroup()
        s.from_dict(**updated_sharing_group)
        return s

    def sharing_group_exists(self, sharing_group: MISPSharingGroup | int | str | UUID) -> bool:
        """Fast check if sharing group exists.

        :param sharing_group: Sharing group to check
        """
        sharing_group_id = get_uuid_or_id_from_abstract_misp(sharing_group)
        r = self._prepare_request('HEAD', f'sharing_groups/view/{sharing_group_id}')
        return self._check_head_response(r)

    def delete_sharing_group(self, sharing_group: MISPSharingGroup | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Delete a sharing group: https://www.misp-project.org/openapi/#tag/Sharing-Groups/operation/deleteSharingGroup

        :param sharing_group: sharing group to delete
        """
        sharing_group_id = get_uuid_or_id_from_abstract_misp(sharing_group)
        response = self._prepare_request('POST', f'sharingGroups/delete/{sharing_group_id}')
        return self._check_json_response(response)

    def add_org_to_sharing_group(self, sharing_group: MISPSharingGroup | int | str | UUID,
                                 organisation: MISPOrganisation | int | str | UUID, extend: bool = False) -> dict[str, Any] | list[dict[str, Any]]:
        '''Add an organisation to a sharing group: https://www.misp-project.org/openapi/#tag/Sharing-Groups/operation/addOrganisationToSharingGroup

        :param sharing_group: Sharing group's local instance ID, or Sharing group's global UUID
        :param organisation: Organisation's local instance ID, or Organisation's global UUID, or Organisation's name as known to the curent instance
        :param extend: Allow the organisation to extend the group
        '''
        sharing_group_id = get_uuid_or_id_from_abstract_misp(sharing_group)
        organisation_id = get_uuid_or_id_from_abstract_misp(organisation)
        to_jsonify = {'sg_id': sharing_group_id, 'org_id': organisation_id, 'extend': extend}
        response = self._prepare_request('POST', 'sharingGroups/addOrg', data=to_jsonify)
        return self._check_json_response(response)

    def remove_org_from_sharing_group(self, sharing_group: MISPSharingGroup | int | str | UUID,
                                      organisation: MISPOrganisation | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        '''Remove an organisation from a sharing group: https://www.misp-project.org/openapi/#tag/Sharing-Groups/operation/removeOrganisationFromSharingGroup

        :param sharing_group: Sharing group's local instance ID, or Sharing group's global UUID
        :param organisation: Organisation's local instance ID, or Organisation's global UUID, or Organisation's name as known to the curent instance
        '''
        sharing_group_id = get_uuid_or_id_from_abstract_misp(sharing_group)
        organisation_id = get_uuid_or_id_from_abstract_misp(organisation)
        to_jsonify = {'sg_id': sharing_group_id, 'org_id': organisation_id}
        response = self._prepare_request('POST', 'sharingGroups/removeOrg', data=to_jsonify)
        return self._check_json_response(response)

    def add_server_to_sharing_group(self, sharing_group: MISPSharingGroup | int | str | UUID,
                                    server: MISPServer | int | str | UUID, all_orgs: bool = False) -> dict[str, Any] | list[dict[str, Any]]:
        '''Add a server to a sharing group: https://www.misp-project.org/openapi/#tag/Sharing-Groups/operation/addServerToSharingGroup

        :param sharing_group: Sharing group's local instance ID, or Sharing group's global UUID
        :param server: Server's local instance ID, or URL of the Server, or Server's name as known to the curent instance
        :param all_orgs: Add all the organisations of the server to the group
        '''
        sharing_group_id = get_uuid_or_id_from_abstract_misp(sharing_group)
        server_id = get_uuid_or_id_from_abstract_misp(server)
        to_jsonify = {'sg_id': sharing_group_id, 'server_id': server_id, 'all_orgs': all_orgs}
        response = self._prepare_request('POST', 'sharingGroups/addServer', data=to_jsonify)
        return self._check_json_response(response)

    def remove_server_from_sharing_group(self, sharing_group: MISPSharingGroup | int | str | UUID,
                                         server: MISPServer | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        '''Remove a server from a sharing group: https://www.misp-project.org/openapi/#tag/Sharing-Groups/operation/removeServerFromSharingGroup

        :param sharing_group: Sharing group's local instance ID, or Sharing group's global UUID
        :param server: Server's local instance ID, or URL of the Server, or Server's name as known to the curent instance
        '''
        sharing_group_id = get_uuid_or_id_from_abstract_misp(sharing_group)
        server_id = get_uuid_or_id_from_abstract_misp(server)
        to_jsonify = {'sg_id': sharing_group_id, 'server_id': server_id}
        response = self._prepare_request('POST', 'sharingGroups/removeServer', data=to_jsonify)
        return self._check_json_response(response)

    # ## END Sharing groups ###

    # ## BEGIN Organisation ###

    def organisations(self, scope: str="local", search: str | None = None, pythonify: bool = False) -> dict[str, Any] | list[MISPOrganisation] | list[dict[str, Any]]:
        """Get all the organisations: https://www.misp-project.org/openapi/#tag/Organisations/operation/getOrganisations

        :param scope: scope of organizations to get
        :param search: The search to make against the list of organisations
        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        url_path = f'organisations/index/scope:{scope}'
        if search:
            url_path += f"/searchall:{search}"

        r = self._prepare_request('GET', url_path)
        organisations = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or isinstance(organisations, dict):
            return organisations
        to_return = []
        for organisation in organisations:
            o = MISPOrganisation()
            o.from_dict(**organisation)
            to_return.append(o)
        return to_return

    def get_organisation(self, organisation: MISPOrganisation | int | str | UUID, pythonify: bool = False) -> dict[str, Any] | MISPOrganisation:
        """Get an organisation by id: https://www.misp-project.org/openapi/#tag/Organisations/operation/getOrganisationById

        :param organisation: organization to get
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        organisation_id = get_uuid_or_id_from_abstract_misp(organisation)
        r = self._prepare_request('GET', f'organisations/view/{organisation_id}')
        organisation_j = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in organisation_j:
            return organisation_j
        o = MISPOrganisation()
        o.from_dict(**organisation_j)
        return o

    def organisation_exists(self, organisation: MISPOrganisation | int | str | UUID) -> bool:
        """Fast check if organisation exists.

        :param organisation: Organisation to check
        """
        organisation_id = get_uuid_or_id_from_abstract_misp(organisation)
        r = self._prepare_request('HEAD', f'organisations/view/{organisation_id}')
        return self._check_head_response(r)

    def add_organisation(self, organisation: MISPOrganisation, pythonify: bool = False) -> dict[str, Any] | MISPOrganisation:
        """Add an organisation: https://www.misp-project.org/openapi/#tag/Organisations/operation/addOrganisation

        :param organisation: organization to add
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        r = self._prepare_request('POST', 'admin/organisations/add', data=organisation)
        new_organisation = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in new_organisation:
            return new_organisation
        o = MISPOrganisation()
        o.from_dict(**new_organisation)
        return o

    def update_organisation(self, organisation: MISPOrganisation, organisation_id: int | None = None, pythonify: bool = False) -> dict[str, Any] | MISPOrganisation:
        """Update an organisation: https://www.misp-project.org/openapi/#tag/Organisations/operation/editOrganisation

        :param organisation: organization to update
        :param organisation_id: id to update
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        if organisation_id is None:
            oid = get_uuid_or_id_from_abstract_misp(organisation)
        else:
            oid = get_uuid_or_id_from_abstract_misp(organisation_id)
        r = self._prepare_request('POST', f'admin/organisations/edit/{oid}', data=organisation)
        updated_organisation = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in updated_organisation:
            return updated_organisation
        o = MISPOrganisation()
        o.from_dict(**organisation)
        return o

    def delete_organisation(self, organisation: MISPOrganisation | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Delete an organisation by id: https://www.misp-project.org/openapi/#tag/Organisations/operation/deleteOrganisation

        :param organisation: organization to delete
        """
        # NOTE: MISP in inconsistent and currently require "delete" in the path and doesn't support HTTP DELETE
        organisation_id = get_uuid_or_id_from_abstract_misp(organisation)
        response = self._prepare_request('POST', f'admin/organisations/delete/{organisation_id}')
        return self._check_json_response(response)

    # ## END Organisation ###

    # ## BEGIN User ###

    def users(self, search: str | None = None, organisation: int | None = None, pythonify: bool = False) -> dict[str, Any] | list[MISPUser] | list[dict[str, Any]]:
        """Get all the users, or a filtered set of users: https://www.misp-project.org/openapi/#tag/Users/operation/getUsers

        :param search: The search to make against the list of users
        :param organisation: The ID of an organisation to filter against
        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        urlpath = 'admin/users/index'
        if search:
            urlpath += f'/value:{search}'
        if organisation:
            organisation_id = get_uuid_or_id_from_abstract_misp(organisation)
            urlpath += f"/searchorg:{organisation_id}"
        r = self._prepare_request('GET', urlpath)
        users = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or isinstance(users, dict):
            return users
        to_return = []
        for user in users:
            u = MISPUser()
            u.from_dict(**user)
            to_return.append(u)
        return to_return

    def get_user(self, user: MISPUser | int | str | UUID = 'me', pythonify: bool = False, expanded: bool = False) -> dict[str, Any] | MISPUser | tuple[MISPUser, MISPRole, list[MISPUserSetting]]:
        """Get a user by id: https://www.misp-project.org/openapi/#tag/Users/operation/getUsers

        :param user: user to get; `me` means the owner of the API key doing the query
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        :param expanded: Also returns a MISPRole and a MISPUserSetting. Only taken in account if pythonify is True.
        """
        user_id = get_uuid_or_id_from_abstract_misp(user)
        r = self._prepare_request('GET', f'users/view/{user_id}')
        user_j = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in user_j:
            return user_j
        u = MISPUser()
        u.from_dict(**user_j)
        if not expanded:
            return u
        else:
            role = MISPRole()
            role.from_dict(**user_j['Role'])
            usersettings = []
            if user_j['UserSetting']:
                for name, value in user_j['UserSetting'].items():
                    us = MISPUserSetting()
                    us.from_dict(**{'name': name, 'value': value})
                    usersettings.append(us)
            return u, role, usersettings

    def get_new_authkey(self, user: MISPUser | int | str | UUID = 'me') -> str:
        '''Get a new authorization key for a specific user, defaults to user doing the call: https://www.misp-project.org/openapi/#tag/AuthKeys/operation/addAuthKey

        :param user: The owner of the key
        '''
        user_id = get_uuid_or_id_from_abstract_misp(user)
        r = self._prepare_request('POST', f'/auth_keys/add/{user_id}', data={})
        authkey = self._check_json_response(r)
        if 'AuthKey' in authkey and 'authkey_raw' in authkey['AuthKey']:
            return authkey['AuthKey']['authkey_raw']
        else:
            raise PyMISPUnexpectedResponse(f'Unable to get authkey: {authkey}')

    def add_user(self, user: MISPUser, pythonify: bool = False) -> dict[str, Any] | MISPUser:
        """Add a new user: https://www.misp-project.org/openapi/#tag/Users/operation/addUser

        :param user: user to add
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        r = self._prepare_request('POST', 'admin/users/add', data=user)
        user_j = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in user_j:
            return user_j
        u = MISPUser()
        u.from_dict(**user_j)
        return u

    def update_user(self, user: MISPUser, user_id: int | None = None, pythonify: bool = False) -> dict[str, Any] | MISPUser:
        """Update a user on a MISP instance: https://www.misp-project.org/openapi/#tag/Users/operation/editUser

        :param user: user to update
        :param user_id: id to update
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        if user_id is None:
            uid = get_uuid_or_id_from_abstract_misp(user)
        else:
            uid = get_uuid_or_id_from_abstract_misp(user_id)
        url = f'users/edit/{uid}'
        if self._current_role.perm_admin or self._current_role.perm_site_admin:
            url = f'admin/{url}'
        r = self._prepare_request('POST', url, data=user)
        updated_user = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in updated_user:
            return updated_user
        e = MISPUser()
        e.from_dict(**updated_user)
        return e

    def delete_user(self, user: MISPUser | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Delete a user by id: https://www.misp-project.org/openapi/#tag/Users/operation/deleteUser

        :param user: user to delete
        """
        # NOTE: MISP in inconsistent and currently require "delete" in the path and doesn't support HTTP DELETE
        user_id = get_uuid_or_id_from_abstract_misp(user)
        response = self._prepare_request('POST', f'admin/users/delete/{user_id}')
        return self._check_json_response(response)

    def change_user_password(self, new_password: str) -> dict[str, Any] | list[dict[str, Any]]:
        """Change the password of the curent user:

        :param new_password: password to set
        """
        response = self._prepare_request('POST', 'users/change_pw', data={'password': new_password})
        return self._check_json_response(response)

    def user_registrations(self, pythonify: bool = False) -> dict[str, Any] | list[MISPInbox] | list[dict[str, Any]]:
        """Get all the user registrations

        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        r = self._prepare_request('GET', 'users/registrations/index')
        registrations = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or isinstance(registrations, dict):
            return registrations
        to_return = []
        for registration in registrations:
            i = MISPInbox()
            i.from_dict(**registration)
            to_return.append(i)
        return to_return

    def accept_user_registration(self, registration: MISPInbox | int | str | UUID,
                                 organisation: MISPOrganisation | int | str | UUID | None = None,
                                 role: MISPRole | int | str | None = None,
                                 perm_sync: bool = False, perm_publish: bool = False,
                                 perm_admin: bool = False,
                                 unsafe_fallback: bool = False) -> dict[str, Any] | list[dict[str, Any]]:
        """Accept a user registration

        :param registration: the registration to accept
        :param organisation: user organization
        :param role: user role
        :param perm_sync: indicator for sync
        :param perm_publish: indicator for publish
        :param perm_admin: indicator for admin
        :param unsafe_fallback: indicator for unsafe fallback
        """
        registration_id = get_uuid_or_id_from_abstract_misp(registration)
        if role:
            role_id = role_id = get_uuid_or_id_from_abstract_misp(role)
        else:
            for _r in self.roles(pythonify=True):
                if not isinstance(_r, MISPRole):
                    continue
                if _r.default_role:  # type: ignore
                    role_id = get_uuid_or_id_from_abstract_misp(_r)
                    break
            else:
                raise PyMISPError('Unable to find default role')

        organisation_id = None
        if organisation:
            organisation_id = get_uuid_or_id_from_abstract_misp(organisation)
        elif unsafe_fallback and isinstance(registration, MISPInbox):
            if 'org_uuid' in registration.data:
                org = self.get_organisation(registration.data['org_uuid'], pythonify=True)
                if isinstance(org, MISPOrganisation):
                    organisation_id = org.id

        if unsafe_fallback and isinstance(registration, MISPInbox):
            # Blindly use request from user, and instance defaults.
            to_post = {'User': {'org_id': organisation_id, 'role_id': role_id,
                                'perm_sync': registration.data['perm_sync'],
                                'perm_publish': registration.data['perm_publish'],
                                'perm_admin': registration.data['perm_admin']}}
        else:
            to_post = {'User': {'org_id': organisation_id, 'role_id': role_id,
                                'perm_sync': perm_sync, 'perm_publish': perm_publish,
                                'perm_admin': perm_admin}}

        r = self._prepare_request('POST', f'users/acceptRegistrations/{registration_id}', data=to_post)
        return self._check_json_response(r)

    def discard_user_registration(self, registration: MISPInbox | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Discard a user registration

        :param registration: the registration to discard
        """
        registration_id = get_uuid_or_id_from_abstract_misp(registration)
        r = self._prepare_request('POST', f'users/discardRegistrations/{registration_id}')
        return self._check_json_response(r)

    # ## END User ###

    # ## BEGIN Role ###

    def roles(self, pythonify: bool = False) -> dict[str, Any] | list[MISPRole] | list[dict[str, Any]]:
        """Get the existing roles

        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        r = self._prepare_request('GET', 'roles/index')
        roles = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or isinstance(roles, dict):
            return roles
        to_return = []
        for role in roles:
            nr = MISPRole()
            nr.from_dict(**role)
            to_return.append(nr)
        return to_return

    def set_default_role(self, role: MISPRole | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Set a default role for the new user accounts

        :param role: the default role to set
        """
        role_id = get_uuid_or_id_from_abstract_misp(role)
        url = urljoin(self.root_url, f'admin/roles/set_default/{role_id}')
        response = self._prepare_request('POST', url)
        return self._check_json_response(response)

    # ## END Role ###

    # ## BEGIN Decaying Models ###

    def update_decaying_models(self) -> dict[str, Any] | list[dict[str, Any]]:
        """Update all the Decaying models"""
        response = self._prepare_request('POST', 'decayingModel/update')
        return self._check_json_response(response)

    def decaying_models(self, pythonify: bool = False) -> dict[str, Any] | list[MISPDecayingModel] | list[dict[str, Any]]:
        """Get all the decaying models

        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output
        """
        r = self._prepare_request('GET', 'decayingModel/index')
        models = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or isinstance(models, dict):
            return models
        to_return = []
        for model in models:
            n = MISPDecayingModel()
            n.from_dict(**model)
            to_return.append(n)
        return to_return

    def enable_decaying_model(self, decaying_model: MISPDecayingModel | int | str) -> dict[str, Any] | list[dict[str, Any]]:
        """Enable a decaying Model"""
        if isinstance(decaying_model, MISPDecayingModel):
            decaying_model_id = decaying_model.id
        else:
            decaying_model_id = int(decaying_model)
        response = self._prepare_request('POST', f'decayingModel/enable/{decaying_model_id}')
        return self._check_json_response(response)

    def disable_decaying_model(self, decaying_model: MISPDecayingModel | int | str) -> dict[str, Any] | list[dict[str, Any]]:
        """Disable a decaying Model"""
        if isinstance(decaying_model, MISPDecayingModel):
            decaying_model_id = decaying_model.id
        else:
            decaying_model_id = int(decaying_model)
        response = self._prepare_request('POST', f'decayingModel/disable/{decaying_model_id}')
        return self._check_json_response(response)

    # ## END Decaying Models ###

    # ## BEGIN Search methods ###

    def search(self, controller: str = 'events', return_format: str = 'json',  # type: ignore[no-untyped-def]
               limit: int | None = None, page: int | None = None,
               value: SearchParameterTypes | None = None,
               type_attribute: SearchParameterTypes | None = None,
               category: SearchParameterTypes | None = None,
               org: SearchParameterTypes | None = None,
               tags: SearchParameterTypes | None = None,
               event_tags: SearchParameterTypes | None = None,
               quick_filter: str | None = None, quickFilter: str | None = None,
               date_from: datetime | date | int | str | float | None | None = None,
               date_to: datetime | date | int | str | float | None | None = None,
               eventid: SearchType | None = None,
               with_attachments: bool | None = None, withAttachments: bool | None = None,
               metadata: bool | None = None,
               uuid: str | None = None,
               publish_timestamp: None | (datetime | date | int | str | float | None
                                          | tuple[datetime | date | int | str | float | None,
                                                  datetime | date | int | str | float | None]
                                          ) = None,
               last: None | (datetime | date | int | str | float | None
                             | tuple[datetime | date | int | str | float | None,
                                     datetime | date | int | str | float | None]
                             ) = None,
               timestamp: None | (datetime | date | int | str | float | None
                                  | tuple[datetime | date | int | str | float | None,
                                          datetime | date | int | str | float | None]
                                  ) = None,
               published: bool | None = None,
               enforce_warninglist: bool | None = None, enforceWarninglist: bool | None = None,
               to_ids: ToIDSType | list[ToIDSType] | None = None,
               deleted: str | None = None,
               include_event_uuid: bool | None = None, includeEventUuid: bool | None = None,
               include_event_tags: bool | None = None, includeEventTags: bool | None = None,
               event_timestamp: datetime | date | int | str | float | None | None = None,
               sg_reference_only: bool | None = None,
               eventinfo: str | None = None,
               searchall: bool | None = None,
               requested_attributes: str | None = None,
               include_context: bool | None = None, includeContext: bool | None = None,
               headerless: bool | None = None,
               include_sightings: bool | None = None, includeSightings: bool | None = None,
               include_correlations: bool | None = None, includeCorrelations: bool | None = None,
               include_decay_score: bool | None = None, includeDecayScore: bool | None = None,
               object_name: str | None = None,
               exclude_decayed: bool | None = None,
               sharinggroup: int | list[int] | None = None,
               pythonify: bool | None = False,
               **kwargs) -> dict[str, Any] | str | list[MISPEvent | MISPAttribute | MISPObject] | list[dict[str, Any]]:
        '''Search in the MISP instance

        :param controller: Controller to search on, it can be `events`, `objects`, `attributes`. The response will either be a list of events, objects, or attributes.
                           Reference documentation for each controller:

                               * events: https://www.misp-project.org/openapi/#tag/Events/operation/restSearchEvents
                               * attributes: https://www.misp-project.org/openapi/#tag/Attributes/operation/restSearchAttributes
                               * objects: N/A

        :param return_format: Set the return format of the search (Currently supported: json, xml, openioc, suricata, snort - more formats are being moved to restSearch with the goal being that all searches happen through this API). Can be passed as the first parameter after restSearch or via the JSON payload.
        :param limit: Limit the number of results returned, depending on the scope (for example 10 attributes or 10 full events).
        :param page: If a limit is set, sets the page to be returned. page 3, limit 100 will return records 201->300).
        :param value: Search for the given value in the attributes' value field.
        :param type_attribute: The attribute type, any valid MISP attribute type is accepted.
        :param category: The attribute category, any valid MISP attribute category is accepted.
        :param org: Search by the creator organisation by supplying the organisation identifier.
        :param tags: Tags to search or to exclude. You can pass a list, or the output of `build_complex_query`
        :param event_tags: Tags to search or to exclude at the event level. You can pass a list, or the output of `build_complex_query`
        :param quick_filter: The string passed to this field will ignore all of the other arguments. MISP will return an xml / json (depending on the header sent) of all events that have a sub-string match on value in the event info, event orgc, or any of the attribute value1 / value2 fields, or in the attribute comment.
        :param date_from: Events with the date set to a date after the one specified. This filter will use the date of the event.
        :param date_to: Events with the date set to a date before the one specified. This filter will use the date of the event.
        :param eventid: The events that should be included / excluded from the search
        :param with_attachments: If set, encodes the attachments / zipped malware samples as base64 in the data field within each attribute
        :param metadata: Only the metadata (event, tags, relations) is returned, attributes and proposals are omitted.
        :param uuid: Restrict the results by uuid.
        :param publish_timestamp: Restrict the results by the last publish timestamp (newer than).
        :param timestamp: Restrict the results by the timestamp (last edit). Any event with a timestamp newer than the given timestamp will be returned. In case you are dealing with /attributes as scope, the attribute's timestamp will be used for the lookup. The input can be a timestamp or a short-hand time description (7d or 24h for example). You can also pass a list with two values to set a time range (for example ["14d", "7d"]).
        :param published: Set whether published or unpublished events should be returned. Do not set the parameter if you want both.
        :param enforce_warninglist: Remove any attributes from the result that would cause a hit on a warninglist entry.
        :param to_ids: By default all attributes are returned that match the other filter parameters, regardless of their to_ids setting. To restrict the returned data set to to_ids only attributes set this parameter to 1. 0 for the ones with to_ids set to False.
        :param deleted: If this parameter is set to 1, it will only return soft-deleted attributes. ["0", "1"] will return the active ones as well as the soft-deleted ones.
        :param include_event_uuid: Instead of just including the event ID, also include the event UUID in each of the attributes.
        :param include_event_tags: Include the event level tags in each of the attributes.
        :param event_timestamp: Only return attributes from events that have received a modification after the given timestamp.
        :param sg_reference_only: If this flag is set, sharing group objects will not be included, instead only the sharing group ID is set.
        :param eventinfo: Filter on the event's info field.
        :param searchall: Search for a full or a substring (delimited by % for substrings) in the event info, event tags, attribute tags, attribute values or attribute comment fields.
        :param requested_attributes: [CSV only] Select the fields that you wish to include in the CSV export. By setting event level fields additionally, includeContext is not required to get event metadata.
        :param include_context: [Attribute only] Include the event data with each attribute. [CSV output] Add event level metadata in every line of the CSV.
        :param headerless: [CSV Only] The CSV created when this setting is set to true will not contain the header row.
        :param include_sightings: [JSON Only - Attribute] Include the sightings of the matching attributes.
        :param include_decay_score: Include the decay score at attribute level.
        :param include_correlations: [JSON Only - attribute] Include the correlations of the matching attributes.
        :param object_name: [objects controller only] Search for objects with that name
        :param exclude_decayed: [attributes controller only] Exclude the decayed attributes from the response
        :param sharinggroup: Filter by sharing group ID(s)
        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM

        Deprecated:

        :param quickFilter: synonym for quick_filter
        :param withAttachments: synonym for with_attachments
        :param last: synonym for publish_timestamp
        :param enforceWarninglist: synonym for enforce_warninglist
        :param includeEventUuid: synonym for include_event_uuid
        :param includeEventTags: synonym for include_event_tags
        :param includeContext: synonym for include_context

        '''

        return_formats = ('openioc', 'json', 'xml', 'suricata', 'snort', 'text', 'rpz', 'csv', 'cache', 'stix-xml',
                          'stix', 'stix2', 'yara', 'yara-json', 'attack', 'attack-sightings', 'context', 'context-markdown')

        if controller not in ('events', 'attributes', 'objects'):
            raise ValueError('controller has to be in {}'.format(', '.join(['events', 'attributes', 'objects'])))

        # Deprecated stuff / synonyms
        if quickFilter is not None:
            quick_filter = quickFilter
        if withAttachments is not None:
            with_attachments = withAttachments
        if last is not None:
            publish_timestamp = last
        if enforceWarninglist is not None:
            enforce_warninglist = enforceWarninglist
        if includeEventUuid is not None:
            include_event_uuid = includeEventUuid
        if includeEventTags is not None:
            include_event_tags = includeEventTags
        if includeContext is not None:
            include_context = includeContext
        if includeDecayScore is not None:
            include_decay_score = includeDecayScore
        if includeCorrelations is not None:
            include_correlations = includeCorrelations
        if includeSightings is not None:
            include_sightings = includeSightings
        # Add all the parameters in kwargs are aimed at modules, or other 3rd party components, and cannot be sanitized.
        # They are passed as-is.
        query = kwargs

        if return_format not in return_formats:
            raise ValueError('return_format has to be in {}'.format(', '.join(return_formats)))
        if return_format == 'stix-xml':
            query['returnFormat'] = 'stix'
        else:
            query['returnFormat'] = return_format

        query['page'] = page
        query['limit'] = limit
        query['value'] = value
        query['type'] = type_attribute
        query['category'] = category
        query['org'] = org
        query['tags'] = tags
        query['event_tags'] = event_tags
        query['quickFilter'] = quick_filter
        query['from'] = self._make_timestamp(date_from)
        query['to'] = self._make_timestamp(date_to)
        query['eventid'] = eventid
        query['withAttachments'] = self._make_misp_bool(with_attachments)
        query['metadata'] = self._make_misp_bool(metadata)
        query['uuid'] = uuid
        if publish_timestamp is not None:
            if isinstance(publish_timestamp, (list, tuple)):
                query['publish_timestamp'] = (self._make_timestamp(publish_timestamp[0]), self._make_timestamp(publish_timestamp[1]))
            else:
                query['publish_timestamp'] = self._make_timestamp(publish_timestamp)
        if timestamp is not None:
            if isinstance(timestamp, (list, tuple)):
                query['timestamp'] = (self._make_timestamp(timestamp[0]), self._make_timestamp(timestamp[1]))
            else:
                query['timestamp'] = self._make_timestamp(timestamp)
        query['published'] = published
        query['enforceWarninglist'] = self._make_misp_bool(enforce_warninglist)
        if to_ids is not None:
            if to_ids not in [0, 1, '0', '1']:
                raise ValueError('to_ids has to be in 0 or 1')
            query['to_ids'] = to_ids
        query['deleted'] = deleted
        query['includeEventUuid'] = self._make_misp_bool(include_event_uuid)
        query['includeEventTags'] = self._make_misp_bool(include_event_tags)
        if event_timestamp is not None:
            if isinstance(event_timestamp, (list, tuple)):
                query['event_timestamp'] = (self._make_timestamp(event_timestamp[0]), self._make_timestamp(event_timestamp[1]))
            else:
                query['event_timestamp'] = self._make_timestamp(event_timestamp)
        query['sgReferenceOnly'] = self._make_misp_bool(sg_reference_only)
        query['eventinfo'] = eventinfo
        query['searchall'] = searchall
        query['requested_attributes'] = requested_attributes
        query['includeContext'] = self._make_misp_bool(include_context)
        query['headerless'] = self._make_misp_bool(headerless)
        query['includeSightings'] = self._make_misp_bool(include_sightings)
        query['includeDecayScore'] = self._make_misp_bool(include_decay_score)
        query['includeCorrelations'] = self._make_misp_bool(include_correlations)
        query['object_name'] = object_name
        query['excludeDecayed'] = self._make_misp_bool(exclude_decayed)
        query['sharinggroup'] = sharinggroup

        url = urljoin(self.root_url, f'{controller}/restSearch')
        if return_format == 'stix-xml':
            response = self._prepare_request('POST', url, data=query, output_type='xml')
        else:
            response = self._prepare_request('POST', url, data=query)

        if return_format == 'csv':
            normalized_response_text = self._check_response(response)
            if (self.global_pythonify or pythonify) and not headerless:
                return self._csv_to_dict(normalized_response_text)  # type: ignore
            else:
                return normalized_response_text
        elif return_format not in ['json', 'yara-json']:
            return self._check_response(response)

        normalized_response: list[dict[str, Any]] | dict[str, Any]
        if controller in ['events', 'objects']:
            # This one is truly fucked: event returns a list, attributes doesn't.
            normalized_response = self._check_json_response(response)
        elif controller == 'attributes':
            normalized_response = self._check_json_response(response)

        if 'errors' in normalized_response:
            return normalized_response

        if return_format == 'json' and self.global_pythonify or pythonify:
            # The response is in json, we can convert it to a list of pythonic MISP objects
            to_return: list[MISPEvent | MISPAttribute | MISPObject] = []
            if controller == 'events':
                if isinstance(normalized_response, dict):
                    return normalized_response
                for e in normalized_response:
                    me = MISPEvent()
                    me.load(e)
                    to_return.append(me)
            elif controller == 'attributes':
                # FIXME: obvs, this is hurting my soul. We need something generic.
                for a in normalized_response['Attribute']:  # type: ignore[call-overload]
                    ma = MISPAttribute()
                    ma.from_dict(**a)
                    if 'Event' in ma:
                        me = MISPEvent()
                        me.from_dict(**ma.Event)
                        ma.Event = me
                    if 'RelatedAttribute' in ma:
                        related_attributes = []
                        for ra in ma.RelatedAttribute:
                            r_attribute = MISPAttribute()
                            r_attribute.from_dict(**ra)
                            if 'Event' in r_attribute:
                                me = MISPEvent()
                                me.from_dict(**r_attribute.Event)
                                r_attribute.Event = me
                            related_attributes.append(r_attribute)
                        ma.RelatedAttribute = related_attributes
                    if 'Sighting' in ma:
                        sightings = []
                        for sighting in ma.Sighting:
                            s = MISPSighting()
                            s.from_dict(**sighting)
                            sightings.append(s)
                        ma.Sighting = sightings
                    to_return.append(ma)
            elif controller == 'objects':
                if isinstance(normalized_response, dict):
                    return normalized_response
                for o in normalized_response:
                    mo = MISPObject(o['Object']['name'])
                    mo.from_dict(**o)
                    to_return.append(mo)
            return to_return

        return normalized_response

    def search_index(self,
                     all: str | None = None,
                     attribute: str | None = None,
                     email: str | None = None,
                     published: bool | None = None,
                     hasproposal: bool | None = None,
                     eventid: SearchType | None = None,
                     tags: SearchParameterTypes | None = None,
                     date_from: datetime | date | int | str | float | None | None = None,
                     date_to: datetime | date | int | str | float | None | None = None,
                     eventinfo: str | None = None,
                     threatlevel: list[SearchType] | None = None,
                     distribution: list[SearchType] | None = None,
                     analysis: list[SearchType] | None = None,
                     org: SearchParameterTypes | None = None,
                     timestamp: None | (datetime | date | int | str | float | None
                                        | tuple[datetime | date | int | str | float | None,
                                                datetime | date | int | str | float | None]
                                        ) = None,
                     publish_timestamp: None | (datetime | date | int | str | float | None
                                                | tuple[datetime | date | int | str | float | None,
                                                        datetime | date | int | str | float | None]
                                                ) = None,
                     sharinggroup: list[SearchType] | None = None,
                     minimal: bool | None = None,
                     sort: str | None = None,
                     desc: bool | None = None,
                     limit: int | None = None,
                     page: int | None = None,
                     pythonify: bool | None = None) -> dict[str, Any] | list[MISPEvent] | list[dict[str, Any]]:
        """Search event metadata shown on the event index page. Using ! in front of a value
        means NOT, except for parameters date_from, date_to and timestamp which cannot be negated.
        Criteria are AND-ed together; values in lists are OR-ed together. Return matching events
        with metadata but no attributes or objects; also see minimal parameter.

        :param all: Search for a full or a substring (delimited by % for substrings) in the
            event info, event tags, attribute tags, attribute values or attribute comment fields.
        :param attribute: Filter on attribute's value.
        :param email: Filter on user's email.
        :param published: Set whether published or unpublished events should be returned.
            Do not set the parameter if you want both.
        :param hasproposal: Filter for events containing proposal(s).
        :param eventid: The events that should be included / excluded from the search
        :param tags: Tags to search or to exclude. You can pass a list, or the output of
            `build_complex_query`
        :param date_from: Events with the date set to a date after the one specified.
            This filter will use the date of the event.
        :param date_to: Events with the date set to a date before the one specified.
            This filter will use the date of the event.
        :param eventinfo: Filter on the event's info field.
        :param threatlevel: Threat level(s) (1,2,3,4) | list
        :param distribution: Distribution level(s) (0,1,2,3) | list
        :param analysis: Analysis level(s) (0,1,2) | list
        :param org: Search by the creator organisation by supplying the organisation identifier.
        :param timestamp: Restrict the results by the timestamp (last edit). Any event with a
            timestamp newer than the given timestamp will be returned. In case you are dealing
            with /attributes as scope, the attribute's timestamp will be used for the lookup.
        :param publish_timestamp: Filter on event's publish timestamp.
        :param sharinggroup: Restrict by a sharing group | list
        :param minimal: Return only event ID, UUID, timestamp, sighting_timestamp and published.
        :param sort: The field to sort the events by, such as 'id', 'date', 'attribute_count'.
        :param desc: Whether to sort events ascending (default) or descending.
        :param limit: Limit the number of events returned
        :param page: If a limit is set, sets the page to be returned. page 3, limit 100 will return records 201->300).
        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output.
            Warning: it might use a lot of RAM
        """
        query = locals()
        query.pop('self')
        query.pop('pythonify')
        if query.get('date_from'):
            query['datefrom'] = self._make_timestamp(query.pop('date_from'))
        if query.get('date_to'):
            query['dateuntil'] = self._make_timestamp(query.pop('date_to'))
        if isinstance(query.get('sharinggroup'), list):
            query['sharinggroup'] = '|'.join([str(sg) for sg in query['sharinggroup']])
        if query.get('timestamp') is not None:
            timestamp = query.pop('timestamp')
            if isinstance(timestamp, (list, tuple)):
                query['timestamp'] = (self._make_timestamp(timestamp[0]), self._make_timestamp(timestamp[1]))
            else:
                query['timestamp'] = self._make_timestamp(timestamp)
        if query.get("sort"):
            query["direction"] = "desc" if desc else "asc"
        url = urljoin(self.root_url, 'events/index')
        response = self._prepare_request('POST', url, data=query)
        normalized_response = self._check_json_response(response)

        if not (self.global_pythonify or pythonify) or isinstance(normalized_response, dict):
            return normalized_response
        to_return = []
        for e_meta in normalized_response:
            me = MISPEvent()
            me.from_dict(**e_meta)
            to_return.append(me)
        return to_return

    def search_sightings(self, context: str | None = None,
                         context_id: SearchType | None = None,
                         type_sighting: str | None = None,
                         date_from: datetime | date | int | str | float | None | None = None,
                         date_to: datetime | date | int | str | float | None | None = None,
                         publish_timestamp: None | (datetime | date | int | str | float | None
                                                    | tuple[datetime | date | int | str | float | None,
                                                            datetime | date | int | str | float | None]
                                                    ) = None,
                         last: None | (datetime | date | int | str | float | None
                                       | tuple[datetime | date | int | str | float | None,
                                               datetime | date | int | str | float | None]
                                       ) = None,
                         org: SearchType | None = None,
                         source: str | None = None,
                         include_attribute: bool | None = None,
                         include_event_meta: bool | None = None,
                         pythonify: bool | None = False
                         ) -> dict[str, Any] | list[dict[str, MISPEvent | MISPAttribute | MISPSighting]]:
        '''Search sightings

        :param context: The context of the search. Can be either "attribute", "event", or nothing (will then match on events and attributes).
        :param context_id: Only relevant if context is either "attribute" or "event". Then it is the relevant ID.
        :param type_sighting: Type of sighting
        :param date_from: Events with the date set to a date after the one specified. This filter will use the date of the event.
        :param date_to: Events with the date set to a date before the one specified. This filter will use the date of the event.
        :param publish_timestamp: Restrict the results by the last publish timestamp (newer than).
        :param org: Search by the creator organisation by supplying the organisation identifier.
        :param source: Source of the sighting
        :param include_attribute: Include the attribute.
        :param include_event_meta: Include the meta information of the event.

        Deprecated:

        :param last: synonym for publish_timestamp

        :Example:

        >>> misp.search_sightings(publish_timestamp='30d') # search sightings for the last 30 days on the instance
        [ ... ]
        >>> misp.search_sightings(context='attribute', context_id=6, include_attribute=True) # return list of sighting for attribute 6 along with the attribute itself
        [ ... ]
        >>> misp.search_sightings(context='event', context_id=17, include_event_meta=True, org=2) # return list of sighting for event 17 filtered with org id 2
        '''
        query: dict[str, Any] = {'returnFormat': 'json'}
        if context is not None:
            if context not in ['attribute', 'event']:
                raise ValueError('context has to be in {}'.format(', '.join(['attribute', 'event'])))
            url_path = f'sightings/restSearch/{context}'
        else:
            url_path = 'sightings/restSearch'
        if isinstance(context_id, (MISPEvent, MISPAttribute)):
            context_id = get_uuid_or_id_from_abstract_misp(context_id)
        query['id'] = context_id
        query['type'] = type_sighting
        query['from'] = date_from
        query['to'] = date_to
        query['last'] = publish_timestamp
        query['org_id'] = org
        query['source'] = source
        query['includeAttribute'] = include_attribute
        query['includeEvent'] = include_event_meta

        url = urljoin(self.root_url, url_path)
        response = self._prepare_request('POST', url, data=query)
        normalized_response = self._check_json_response(response)
        if not (self.global_pythonify or pythonify) or isinstance(normalized_response, dict):
            return normalized_response

        if self.global_pythonify or pythonify:
            to_return = []
            for s in normalized_response:
                entries: dict[str, MISPEvent | MISPAttribute | MISPSighting] = {}
                s_data = s['Sighting']
                if include_event_meta:
                    e = s_data.pop('Event')
                    me = MISPEvent()
                    me.from_dict(**e)
                    entries['event'] = me
                if include_attribute:
                    a = s_data.pop('Attribute')
                    ma = MISPAttribute()
                    ma.from_dict(**a)
                    entries['attribute'] = ma
                ms = MISPSighting()
                ms.from_dict(**s_data)
                entries['sighting'] = ms
                to_return.append(entries)
            return to_return
        return normalized_response

    def search_logs(self, limit: int | None = None, page: int | None = None,
                    log_id: int | None = None, title: str | None = None,
                    created: datetime | date | int | str | float | None | None = None, model: str | None = None,
                    action: str | None = None, user_id: int | None = None,
                    change: str | None = None, email: str | None = None,
                    org: str | None = None, description: str | None = None,
                    ip: str | None = None, pythonify: bool | None = False) -> dict[str, Any] | list[MISPLog] | list[dict[str, Any]]:
        '''Search in logs

        Note: to run substring queries simply append/prepend/encapsulate the search term with %

        :param limit: Limit the number of results returned, depending on the scope (for example 10 attributes or 10 full events).
        :param page: If a limit is set, sets the page to be returned. page 3, limit 100 will return records 201->300).
        :param log_id: Log ID
        :param title: Log Title
        :param created: Creation timestamp
        :param model: Model name that generated the log entry
        :param action: The thing that was done
        :param user_id: ID of the user doing the action
        :param change: Change that occured
        :param email: Email of the user
        :param org: Organisation of the User doing the action
        :param description: Description of the action
        :param ip: Origination IP of the User doing the action
        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        '''
        query = locals()
        query.pop('self')
        query.pop('pythonify')
        if log_id is not None:
            query['id'] = query.pop('log_id')
        if created is not None and isinstance(created, datetime):
            query['created'] = query.pop('created').timestamp()

        response = self._prepare_request('POST', 'admin/logs/index', data=query)
        normalized_response = self._check_json_response(response)
        if not (self.global_pythonify or pythonify) or isinstance(normalized_response, dict):
            return normalized_response

        to_return = []
        for log in normalized_response:
            ml = MISPLog()
            ml.from_dict(**log)
            to_return.append(ml)
        return to_return

    def search_feeds(self, value: SearchParameterTypes | None = None, pythonify: bool | None = False) -> dict[str, Any] | list[MISPFeed] | list[dict[str, Any]]:
        '''Search in the feeds cached on the servers'''
        response = self._prepare_request('POST', 'feeds/searchCaches', data={'value': value})
        normalized_response = self._check_json_response(response)
        if not (self.global_pythonify or pythonify) or isinstance(normalized_response, dict):
            return normalized_response
        to_return = []
        for feed in normalized_response:
            f = MISPFeed()
            f.from_dict(**feed)
            to_return.append(f)
        return to_return

    # ## END Search methods ###

    # ## BEGIN Communities ###

    def communities(self, pythonify: bool = False) -> dict[str, Any] | list[MISPCommunity] | list[dict[str, Any]]:
        """Get all the communities

        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        r = self._prepare_request('GET', 'communities/index')
        communities = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or isinstance(communities, dict):
            return communities
        to_return = []
        for community in communities:
            c = MISPCommunity()
            c.from_dict(**community)
            to_return.append(c)
        return to_return

    def get_community(self, community: MISPCommunity | int | str | UUID, pythonify: bool = False) -> dict[str, Any] | MISPCommunity:
        """Get a community by id from a MISP instance

        :param community: community to get
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        community_id = get_uuid_or_id_from_abstract_misp(community)
        r = self._prepare_request('GET', f'communities/view/{community_id}')
        community_j = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in community_j:
            return community_j
        c = MISPCommunity()
        c.from_dict(**community_j)
        return c

    def request_community_access(self, community: MISPCommunity | int | str | UUID,
                                 requestor_email_address: str | None = None,
                                 requestor_gpg_key: str | None = None,
                                 requestor_organisation_name: str | None = None,
                                 requestor_organisation_uuid: str | None = None,
                                 requestor_organisation_description: str | None = None,
                                 message: str | None = None, sync: bool = False,
                                 anonymise_requestor_server: bool = False,
                                 mock: bool = False) -> dict[str, Any] | list[dict[str, Any]]:
        """Request the access to a community

        :param community: community to request access
        :param requestor_email_address: requestor email
        :param requestor_gpg_key: requestor key
        :param requestor_organisation_name: requestor org name
        :param requestor_organisation_uuid: requestor org ID
        :param requestor_organisation_description: requestor org desc
        :param message: requestor message
        :param sync: synchronize flag
        :param anonymise_requestor_server: anonymise flag
        :param mock: mock flag
        """
        community_id = get_uuid_or_id_from_abstract_misp(community)
        to_post = {'org_name': requestor_organisation_name,
                   'org_uuid': requestor_organisation_uuid,
                   'org_description': requestor_organisation_description,
                   'email': requestor_email_address, 'gpgkey': requestor_gpg_key,
                   'message': message, 'anonymise': anonymise_requestor_server, 'sync': sync,
                   'mock': mock}
        r = self._prepare_request('POST', f'communities/requestAccess/{community_id}', data=to_post)
        return self._check_json_response(r)

    # ## END Communities ###

    # ## BEGIN Event Delegation ###

    def event_delegations(self, pythonify: bool = False) -> dict[str, Any] | list[MISPEventDelegation] | list[dict[str, Any]]:
        """Get all the event delegations

        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        r = self._prepare_request('GET', 'eventDelegations')
        delegations = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or isinstance(delegations, dict):
            return delegations
        to_return = []
        for delegation in delegations:
            d = MISPEventDelegation()
            d.from_dict(**delegation)
            to_return.append(d)
        return to_return

    def accept_event_delegation(self, delegation: MISPEventDelegation | int | str, pythonify: bool = False) -> dict[str, Any] | list[dict[str, Any]]:
        """Accept the delegation of an event

        :param delegation: event delegation to accept
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        delegation_id = get_uuid_or_id_from_abstract_misp(delegation)
        r = self._prepare_request('POST', f'eventDelegations/acceptDelegation/{delegation_id}')
        return self._check_json_response(r)

    def discard_event_delegation(self, delegation: MISPEventDelegation | int | str, pythonify: bool = False) -> dict[str, Any] | list[dict[str, Any]]:
        """Discard the delegation of an event

        :param delegation: event delegation to discard
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        delegation_id = get_uuid_or_id_from_abstract_misp(delegation)
        r = self._prepare_request('POST', f'eventDelegations/deleteDelegation/{delegation_id}')
        return self._check_json_response(r)

    def delegate_event(self, event: MISPEvent | int | str | UUID | None = None,
                       organisation: MISPOrganisation | int | str | UUID | None = None,
                       event_delegation: MISPEventDelegation | None = None,
                       distribution: int = -1, message: str = '', pythonify: bool = False) -> dict[str, Any] | MISPEventDelegation:
        """Delegate an event. Either event and organisation OR event_delegation are required

        :param event: event to delegate
        :param organisation: organization
        :param event_delegation: event delegation
        :param distribution: distribution == -1 means recipient decides
        :param message: message
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        if event and organisation:
            event_id = get_uuid_or_id_from_abstract_misp(event)
            organisation_id = get_uuid_or_id_from_abstract_misp(organisation)
            data = {'event_id': event_id, 'org_id': organisation_id, 'distribution': distribution, 'message': message}
            r = self._prepare_request('POST', f'eventDelegations/delegateEvent/{event_id}', data=data)
        elif event_delegation:
            r = self._prepare_request('POST', f'eventDelegations/delegateEvent/{event_delegation.event_id}', data=event_delegation)
        else:
            raise PyMISPError('Either event and organisation OR event_delegation are required.')
        delegation_j = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or 'errors' in delegation_j:
            return delegation_j
        d = MISPEventDelegation()
        d.from_dict(**delegation_j)
        return d

    # ## END Event Delegation ###

    # ## BEGIN Others ###

    def push_event_to_ZMQ(self, event: MISPEvent | int | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Force push an event by id on ZMQ

        :param event: the event to push
        """
        event_id = get_uuid_or_id_from_abstract_misp(event)
        response = self._prepare_request('POST', f'events/pushEventToZMQ/{event_id}.json')
        return self._check_json_response(response)

    def direct_call(self, url: str, data: dict[str, Any] | None = None, params: Mapping[str, Any] = {}, kw_params: Mapping[str, Any] = {}) -> Any:
        """Very lightweight call that posts a data blob (python dictionary or json string) on the URL

        :param url: URL to post to
        :param data: data to post
        :param params: dict with parameters for request
        :param kw_params: dict with keyword parameters for request
        """
        if data is None:
            response = self._prepare_request('GET', url, params=params, kw_params=kw_params)
        else:
            response = self._prepare_request('POST', url, data=data, params=params, kw_params=kw_params)
        return self._check_response(response, lenient_response_type=True)

    def freetext(self, event: MISPEvent | int | str | UUID, string: str, adhereToWarninglists: bool | str = False,  # type: ignore[no-untyped-def]
                 distribution: int | None = None, returnMetaAttributes: bool = False, pythonify: bool = False, **kwargs) -> dict[str, Any] | list[MISPAttribute] | list[dict[str, Any]]:
        """Pass a text to the freetext importer

        :param event: event
        :param string: query
        :param adhereToWarninglists: flag
        :param distribution: distribution == -1 means recipient decides
        :param returnMetaAttributes: flag
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        :param kwargs: kwargs passed to prepare_request
        """

        event_id = get_uuid_or_id_from_abstract_misp(event)
        query: dict[str, Any] = {"value": string}
        wl_params = [False, True, 'soft']
        if adhereToWarninglists in wl_params:
            query['adhereToWarninglists'] = adhereToWarninglists
        else:
            raise PyMISPError('Invalid parameter, adhereToWarninglists Can only be False, True, or soft')
        if distribution is not None:
            query['distribution'] = distribution
        if returnMetaAttributes:
            query['returnMetaAttributes'] = returnMetaAttributes
        r = self._prepare_request('POST', f'events/freeTextImport/{event_id}', data=query, **kwargs)
        attributes = self._check_json_response(r)
        if returnMetaAttributes or not (self.global_pythonify or pythonify) or isinstance(attributes, dict):
            return attributes
        to_return = []
        for attribute in attributes:
            a = MISPAttribute()
            a.from_dict(**attribute)
            to_return.append(a)
        return to_return

    def upload_stix(self, path: str | Path | BytesIO | StringIO | None = None,
                    data: str | bytes | None = None, version: str = '2') -> requests.Response:
        """Upload a STIX file to MISP.

        :param path: Path to the STIX on the disk (can be a path-like object, or a pseudofile)
        :param data: stix object
        :param version: Can be 1 or 2
        """
        to_post: str | bytes
        if path is not None:
            if isinstance(path, (str, Path)):
                with open(path, 'rb') as f:
                    to_post = f.read()
            else:
                to_post = path.read()
        elif data is not None:
            to_post = data
        else:
            raise MISPServerError("please fill path or data parameter")

        if str(version) == '1':
            url = urljoin(self.root_url, 'events/upload_stix')
            response = self._prepare_request('POST', url, data=to_post, output_type='xml', content_type='xml')
        else:
            url = urljoin(self.root_url, 'events/upload_stix/2')
            response = self._prepare_request('POST', url, data=to_post)
        return response

    # ## END Others ###

    # ## BEGIN Statistics ###

    def attributes_statistics(self, context: str = 'type', percentage: bool = False) -> dict[str, Any] | list[dict[str, Any]]:
        """Get attribute statistics from the MISP instance

        :param context: "type" or "category"
        :param percentage: get percentages
        """
        # FIXME: https://github.com/MISP/MISP/issues/4874
        if context not in ['type', 'category']:
            raise PyMISPError('context can only be "type" or "category"')
        if percentage:
            path = f'attributes/attributeStatistics/{context}/true'
        else:
            path = f'attributes/attributeStatistics/{context}'
        response = self._prepare_request('GET', path)
        return self._check_json_response(response)

    def tags_statistics(self, percentage: bool = False, name_sort: bool = False) -> dict[str, Any] | list[dict[str, Any]]:
        """Get tag statistics from the MISP instance

        :param percentage: get percentages
        :param name_sort: sort by name
        """
        # FIXME: https://github.com/MISP/MISP/issues/4874
        # NOTE: https://github.com/MISP/MISP/issues/4879
        if percentage:
            p = 'true'
        else:
            p = 'false'
        if name_sort:
            ns = 'true'
        else:
            ns = 'false'
        response = self._prepare_request('GET', f'tags/tagStatistics/{p}/{ns}')
        return self._check_json_response(response)

    def users_statistics(self, context: str = 'data') -> dict[str, Any] | list[dict[str, Any]]:
        """Get user statistics from the MISP instance

        :param context: one of 'data', 'orgs', 'users', 'tags', 'attributehistogram', 'sightings', 'galaxyMatrix'
        """
        availables_contexts = ['data', 'orgs', 'users', 'tags', 'attributehistogram', 'sightings', 'galaxyMatrix']
        if context not in availables_contexts:
            raise PyMISPError("context can only be {','.join(availables_contexts)}")
        response = self._prepare_request('GET', f'users/statistics/{context}')
        try:
            return self._check_json_response(response)
        except PyMISPError:
            return self._check_json_response(response)

    # ## END Statistics ###

    # ## BEGIN User Settings ###

    def user_settings(self, pythonify: bool = False) -> dict[str, Any] | list[MISPUserSetting] | list[dict[str, Any]]:
        """Get all the user settings: https://www.misp-project.org/openapi/#tag/UserSettings/operation/getUserSettings

        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        r = self._prepare_request('GET', 'userSettings/index')
        user_settings = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or isinstance(user_settings, dict):
            return user_settings
        to_return = []
        for user_setting in user_settings:
            u = MISPUserSetting()
            u.from_dict(**user_setting)
            to_return.append(u)
        return to_return

    def get_user_setting(self, user_setting: str, user: MISPUser | int | str | UUID | None = None,
                         pythonify: bool = False) -> dict[str, Any] | MISPUserSetting:
        """Get a user setting: https://www.misp-project.org/openapi/#tag/UserSettings/operation/getUserSettingById

        :param user_setting: name of user setting
        :param user: user
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        query: dict[str, Any] = {'setting': user_setting}
        if user:
            query['user_id'] = get_uuid_or_id_from_abstract_misp(user)
        response = self._prepare_request('POST', 'userSettings/getSetting', data=query)
        user_setting_j = self._check_json_response(response)
        if not (self.global_pythonify or pythonify) or 'errors' in user_setting_j:
            return user_setting_j
        u = MISPUserSetting()
        u.from_dict(**user_setting_j)
        return u

    def set_user_setting(self, user_setting: str, value: str | dict[str, Any], user: MISPUser | int | str | UUID | None = None,
                         pythonify: bool = False) -> dict[str, Any] | MISPUserSetting:
        """Set a user setting: https://www.misp-project.org/openapi/#tag/UserSettings/operation/setUserSetting

        :param user_setting: name of user setting
        :param value: value to set
        :param user: user
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        query: dict[str, Any] = {'setting': user_setting}
        if isinstance(value, dict):
            value = str(dumps(value)) if HAS_ORJSON else dumps(value)
        query['value'] = value
        if user:
            query['user_id'] = get_uuid_or_id_from_abstract_misp(user)
        response = self._prepare_request('POST', 'userSettings/setSetting', data=query)
        user_setting_j = self._check_json_response(response)
        if not (self.global_pythonify or pythonify) or 'errors' in user_setting_j:
            return user_setting_j
        u = MISPUserSetting()
        u.from_dict(**user_setting_j)
        return u

    def delete_user_setting(self, user_setting: str, user: MISPUser | int | str | UUID | None = None) -> dict[str, Any] | list[dict[str, Any]]:
        """Delete a user setting: https://www.misp-project.org/openapi/#tag/UserSettings/operation/deleteUserSettingById

        :param user_setting: name of user setting
        :param user: user
        """
        query: dict[str, Any] = {'setting': user_setting}
        if user:
            query['user_id'] = get_uuid_or_id_from_abstract_misp(user)
        response = self._prepare_request('POST', 'userSettings/delete', data=query)
        return self._check_json_response(response)

    # ## END User Settings ###

    # ## BEGIN Blocklists ###

    def event_blocklists(self, pythonify: bool = False) -> dict[str, Any] | list[MISPEventBlocklist] | list[dict[str, Any]]:
        """Get all the blocklisted events

        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        r = self._prepare_request('GET', 'eventBlocklists/index')
        event_blocklists = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or isinstance(event_blocklists, dict):
            return event_blocklists
        to_return = []
        for event_blocklist in event_blocklists:
            ebl = MISPEventBlocklist()
            ebl.from_dict(**event_blocklist)
            to_return.append(ebl)
        return to_return

    def organisation_blocklists(self, pythonify: bool = False) -> dict[str, Any] | list[MISPOrganisationBlocklist] | list[dict[str, Any]]:
        """Get all the blocklisted organisations

        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM
        """
        r = self._prepare_request('GET', 'orgBlocklists/index')
        organisation_blocklists = self._check_json_response(r)
        if not (self.global_pythonify or pythonify) or isinstance(organisation_blocklists, dict):
            return organisation_blocklists
        to_return = []
        for organisation_blocklist in organisation_blocklists:
            obl = MISPOrganisationBlocklist()
            obl.from_dict(**organisation_blocklist)
            to_return.append(obl)
        return to_return

    def _add_entries_to_blocklist(self, blocklist_type: str, uuids: str | list[str], **kwargs) -> dict[str, Any] | list[dict[str, Any]]:  # type: ignore[no-untyped-def]
        if blocklist_type == 'event':
            url = 'eventBlocklists/add'
        elif blocklist_type == 'organisation':
            url = 'orgBlocklists/add'
        else:
            raise PyMISPError('blocklist_type can only be "event" or "organisation"')
        if isinstance(uuids, str):
            uuids = [uuids]
        data = {'uuids': uuids}
        if kwargs:
            data.update({k: v for k, v in kwargs.items() if v})
        r = self._prepare_request('POST', url, data=data)
        return self._check_json_response(r)

    def add_event_blocklist(self, uuids: str | list[str], comment: str | None = None,
                            event_info: str | None = None, event_orgc: str | None = None) -> dict[str, Any] | list[dict[str, Any]]:
        """Add a new event in the blocklist

        :param uuids: UUIDs
        :param comment: comment
        :param event_info: event information
        :param event_orgc: event organization
        """
        return self._add_entries_to_blocklist('event', uuids=uuids, comment=comment, event_info=event_info, event_orgc=event_orgc)

    def add_organisation_blocklist(self, uuids: str | list[str], comment: str | None = None,
                                   org_name: str | None = None) -> dict[str, Any] | list[dict[str, Any]]:
        """Add a new organisation in the blocklist

        :param uuids: UUIDs
        :param comment: comment
        :param org_name: organization name
        """
        return self._add_entries_to_blocklist('organisation', uuids=uuids, comment=comment, org_name=org_name)

    def _update_entries_in_blocklist(self, blocklist_type: str, uuid, **kwargs) -> dict[str, Any] | list[dict[str, Any]]:  # type: ignore[no-untyped-def]
        if blocklist_type == 'event':
            url = f'eventBlocklists/edit/{uuid}'
        elif blocklist_type == 'organisation':
            url = f'orgBlocklists/edit/{uuid}'
        else:
            raise PyMISPError('blocklist_type can only be "event" or "organisation"')
        data = {k: v for k, v in kwargs.items() if v}
        r = self._prepare_request('POST', url, data=data)
        return self._check_json_response(r)

    def update_event_blocklist(self, event_blocklist: MISPEventBlocklist, event_blocklist_id: int | str | UUID | None = None, pythonify: bool = False) -> dict[str, Any] | MISPEventBlocklist:
        """Update an event in the blocklist

        :param event_blocklist: event block list
        :param event_blocklist_id: event block lisd id
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        if event_blocklist_id is None:
            eblid = get_uuid_or_id_from_abstract_misp(event_blocklist)
        else:
            eblid = get_uuid_or_id_from_abstract_misp(event_blocklist_id)
        updated_event_blocklist = self._update_entries_in_blocklist('event', eblid, **event_blocklist)
        if not (self.global_pythonify or pythonify) or 'errors' in updated_event_blocklist:
            return updated_event_blocklist
        e = MISPEventBlocklist()
        e.from_dict(**updated_event_blocklist)
        return e

    def update_organisation_blocklist(self, organisation_blocklist: MISPOrganisationBlocklist, organisation_blocklist_id: int | str | UUID | None = None, pythonify: bool = False) -> dict[str, Any] | MISPOrganisationBlocklist:
        """Update an organisation in the blocklist

        :param organisation_blocklist: organization block list
        :param organisation_blocklist_id: organization block lisd id
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        if organisation_blocklist_id is None:
            oblid = get_uuid_or_id_from_abstract_misp(organisation_blocklist)
        else:
            oblid = get_uuid_or_id_from_abstract_misp(organisation_blocklist_id)
        updated_organisation_blocklist = self._update_entries_in_blocklist('organisation', oblid, **organisation_blocklist)
        if not (self.global_pythonify or pythonify) or 'errors' in updated_organisation_blocklist:
            return updated_organisation_blocklist
        o = MISPOrganisationBlocklist()
        o.from_dict(**updated_organisation_blocklist)
        return o

    def delete_event_blocklist(self, event_blocklist: MISPEventBlocklist | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Delete a blocklisted event by id

        :param event_blocklist: event block list to delete
        """
        event_blocklist_id = get_uuid_or_id_from_abstract_misp(event_blocklist)
        response = self._prepare_request('POST', f'eventBlocklists/delete/{event_blocklist_id}')
        return self._check_json_response(response)

    def delete_organisation_blocklist(self, organisation_blocklist: MISPOrganisationBlocklist | str | UUID) -> dict[str, Any] | list[dict[str, Any]]:
        """Delete a blocklisted organisation by id

        :param organisation_blocklist: organization block list to delete
        """
        org_blocklist_id = get_uuid_or_id_from_abstract_misp(organisation_blocklist)
        response = self._prepare_request('POST', f'orgBlocklists/delete/{org_blocklist_id}')
        return self._check_json_response(response)

    # ## END Blocklists ###

    # ## BEGIN Global helpers ###

    def change_sharing_group_on_entity(self, misp_entity: MISPEvent | MISPAttribute | MISPObject,
                                       sharing_group_id: int, pythonify: bool = False) -> dict[str, Any] | MISPEvent | MISPObject | MISPAttribute | MISPShadowAttribute:
        """Change the sharing group of an event, an attribute, or an object

        :param misp_entity: entity to change
        :param sharing_group_id: group to change
        :param pythonify: Returns a PyMISP Object instead of the plain json output
        """
        misp_entity.distribution = 4      # Needs to be 'Sharing group'
        if 'SharingGroup' in misp_entity:  # Delete former SharingGroup information
            del misp_entity.SharingGroup
        misp_entity.sharing_group_id = sharing_group_id  # Set new sharing group id
        if isinstance(misp_entity, MISPEvent):
            return self.update_event(misp_entity, pythonify=pythonify)

        if isinstance(misp_entity, MISPObject):
            return self.update_object(misp_entity, pythonify=pythonify)

        if isinstance(misp_entity, MISPAttribute):
            return self.update_attribute(misp_entity, pythonify=pythonify)

        raise PyMISPError('The misp_entity must be MISPEvent, MISPObject or MISPAttribute')

    def tag(self, misp_entity: AbstractMISP | str | dict[str, Any], tag: MISPTag | str,
            local: bool = False, relationship_type: str | None = None) -> dict[str, Any] | list[dict[str, Any]]:
        """Tag an event or an attribute.

        :param misp_entity: a MISPEvent, a MISP Attribute, or a UUID
        :param tag: tag to add
        :param local: whether to tag locally
        :param relationship_type: Type of relationship between the tag and the attribute or event
        """
        uuid = get_uuid_or_id_from_abstract_misp(misp_entity)
        if isinstance(tag, MISPTag):
            tag_name = tag.name if 'name' in tag else ""
        else:
            tag_name = tag
        to_post = {'uuid': uuid, 'tag': tag_name, 'local': local}
        if relationship_type:
            to_post['relationship_type'] = relationship_type
        response = self._prepare_request('POST', 'tags/attachTagToObject', data=to_post)
        return self._check_json_response(response)

    def untag(self, misp_entity: AbstractMISP | str | dict[str, Any], tag: MISPTag | str) -> dict[str, Any] | list[dict[str, Any]]:
        """Untag an event or an attribute

        :param misp_entity: misp_entity can be a UUID
        :param tag: tag to remove
        """
        uuid = get_uuid_or_id_from_abstract_misp(misp_entity)
        if isinstance(tag, MISPTag):
            tag_name = tag.name if 'name' in tag else ""
        else:
            tag_name = tag
        to_post = {'uuid': uuid, 'tag': tag_name}
        response = self._prepare_request('POST', 'tags/removeTagFromObject', data=to_post)
        return self._check_json_response(response)

    def build_complex_query(self, or_parameters: list[SearchType] | None = None,
                            and_parameters: list[SearchType] | None = None,
                            not_parameters: list[SearchType] | None = None) -> dict[str, list[SearchType]]:
        '''Build a complex search query. MISP expects a dictionary with AND, OR and NOT keys.'''
        to_return = {}
        if and_parameters:
            if isinstance(and_parameters, str):
                to_return['AND'] = [and_parameters]
            else:
                to_return['AND'] = [p for p in and_parameters if p]
        if not_parameters:
            if isinstance(not_parameters, str):
                to_return['NOT'] = [not_parameters]
            else:
                to_return['NOT'] = [p for p in not_parameters if p]
        if or_parameters:
            if isinstance(or_parameters, str):
                to_return['OR'] = [or_parameters]
            else:
                to_return['OR'] = [p for p in or_parameters if p]
        return to_return

    # ## END Global helpers ###

    # ## MISP internal tasks ###

    def get_all_functions(self, not_implemented: bool = False) -> list[str]:
        '''Get all methods available via the API, including ones that are not implemented.'''
        response = self._prepare_request('GET', 'servers/queryACL/printAllFunctionNames')
        functions = self._check_json_response(response)
        # Format as URLs
        paths = []
        for controller, methods in functions.items():
            if controller == '*':
                continue
            for method in methods:
                if method.startswith('admin_'):
                    path = f'admin/{controller}/{method[6:]}'
                else:
                    path = f'{controller}/{method}'
                paths.append(path)

        if not not_implemented:
            return [str(path)]

        with open(__file__) as f:
            content = f.read()

        not_implemented_paths: list[str] = []
        for path in paths:
            if path not in content:
                not_implemented_paths.append(path)

        return not_implemented_paths

    # ## Internal methods ###

    def _old_misp(self, minimal_version_required: tuple[int], removal_date: str | date | datetime, method: str | None = None, message: str | None = None) -> bool:
        if self._misp_version >= minimal_version_required:
            return False
        if isinstance(removal_date, (datetime, date)):
            removal_date = removal_date.isoformat()
        to_print = f'The instance of MISP you are using is outdated. Unless you update your MISP instance, {method} will stop working after {removal_date}.'
        if message:
            to_print += f' {message}'
        warnings.warn(to_print, DeprecationWarning)
        return True

    def _make_misp_bool(self, parameter: bool | str | None = None) -> int:
        '''MISP wants 0 or 1 for bool, so we avoid True/False '0', '1' '''
        if parameter is None:
            return 0
        return 1 if int(parameter) else 0

    def _make_timestamp(self, value: datetime | date | int | str | float | None) -> str | int | float | None:
        '''Catch-all method to normalize anything that can be converted to a timestamp'''
        if not value:
            return None
        if isinstance(value, datetime):
            return value.timestamp()

        if isinstance(value, date):
            return datetime.combine(value, datetime.max.time()).timestamp()

        if isinstance(value, str):
            if value.isdigit():
                return value
            try:
                float(value)
                return value
            except ValueError:
                # The value can also be '1d', '10h', ...
                return value
        return value

    def _check_json_response(self, response: requests.Response) -> dict[str, Any] | list[dict[str, Any]]:
        r = self._check_response(response, expect_json=True)
        if isinstance(r, (dict, list)):
            return r
        # Else: an exception was raised anyway
        raise PyMISPUnexpectedResponse(f'A dict was expected, got a string: {r}')

    def _check_head_response(self, response: requests.Response) -> bool:
        if response.status_code == 200:
            return True
        elif response.status_code == 404:
            return False
        else:
            raise MISPServerError(f'Error code {response.status_code} for HEAD request')

    def _check_response(self, response: requests.Response, lenient_response_type: bool = False, expect_json: bool = False) -> dict[str, Any] | str:
        """Check if the response from the server is not an unexpected error"""
        if response.status_code >= 500:
            headers_without_auth = {h_name: h_value for h_name, h_value in response.request.headers.items() if h_value != self.key}
            logger.critical(everything_broken.format(headers_without_auth, response.request.body, response.text))
            raise MISPServerError(f'Error code 500:\n{response.text}')

        if 400 <= response.status_code < 500:
            # The server returns a json message with the error details
            try:
                error_message = loads(response.content)
            except Exception:
                raise MISPServerError(f'Error code {response.status_code}:\n{response.text}')

            logger.error(f'Something went wrong ({response.status_code}): {error_message}')
            return {'errors': (response.status_code, error_message)}

        # At this point, we had no error.

        try:
            response_json = loads(response.content)
            logger.debug(response_json)
            if isinstance(response_json, dict) and response_json.get('response') is not None:
                # Cleanup.
                response_json = response_json['response']
            return response_json
        except Exception:
            logger.debug(response.text)
            if expect_json:
                error_msg = f'Unexpected response (size: {len(response.text)}) from server: {response.text}'
                raise PyMISPUnexpectedResponse(error_msg)
            if lenient_response_type and not response.headers['Content-Type'].startswith('application/json'):
                return response.text
            if not response.content:
                # Empty response
                logger.error('Got an empty response.')
                return {'errors': 'The response is empty.'}
            return response.text

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}(url={self.root_url})'

    def _prepare_request(self, request_type: str, url: str, data: Iterable[Any] | Mapping[str, Any] | AbstractMISP | bytes | None = None,
                         params: Mapping[str, Any] = {}, kw_params: Mapping[str, Any] = {},
                         output_type: str = 'json', content_type: str = 'json') -> requests.Response:
        '''Prepare a request for python-requests'''
        if url[0] == '/':
            # strip it: it will fail if MISP is in a sub directory
            url = url[1:]
        # Cake PHP being an idiot, it doesn't accept %20 (space) in the URL path,
        # so we need to make it a + instead and hope for the best
        url = url.replace(' ', '+')
        url = urljoin(self.root_url, url)
        d: bytes | str | None = None
        if data is not None:
            if isinstance(data, bytes):
                d = data
            else:
                if isinstance(data, dict):
                    # Remove None values.
                    data = {k: v for k, v in data.items() if v is not None}
                d = dumps(data, default=pymisp_json_default)

        logger.debug('%s - %s', request_type, url)
        if d is not None:
            logger.debug(d)

        if kw_params:
            # CakePHP params in URL
            to_append_url = '/'.join([f'{k}:{v}' for k, v in kw_params.items()])
            url = f'{url}/{to_append_url}'

        req = requests.Request(request_type, url, data=d, params=params)
        req.auth = self.auth
        prepped = self.__session.prepare_request(req)
        prepped.headers.update(
            {'Accept': f'application/{output_type}',
             'content-type': f'application/{content_type}'})
        logger.debug(prepped.headers)
        settings = self.__session.merge_environment_settings(req.url, proxies=self.proxies or {}, stream=None,
                                                             verify=self.ssl, cert=self.cert)
        return self.__session.send(prepped, timeout=self.timeout, **settings)

    def _csv_to_dict(self, csv_content: str) -> list[dict[str, Any]]:
        '''Makes a list of dict out of a csv file (requires headers)'''
        fieldnames, lines = csv_content.split('\n', 1)
        fields = fieldnames.split(',')
        to_return = []
        for line in csv.reader(lines.split('\n')):
            if line:
                to_return.append({fname: value for fname, value in zip(fields, line)})
        return to_return
