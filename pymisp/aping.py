#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import TypeVar, Optional, Tuple, List, Dict, Union
from datetime import date, datetime
import csv
from pathlib import Path
import logging
from urllib.parse import urljoin
import json
import requests
from requests.auth import AuthBase
import re
from uuid import UUID

from . import __version__
from .exceptions import MISPServerError, PyMISPUnexpectedResponse, PyMISPNotImplementedYet, PyMISPError, NoURL, NoKey
from .api import everything_broken, PyMISP
from .mispevent import MISPEvent, MISPAttribute, MISPSighting, MISPLog, MISPObject, MISPUser, MISPOrganisation, MISPShadowAttribute, MISPWarninglist, MISPTaxonomy, MISPGalaxy, MISPNoticelist, MISPObjectReference, MISPObjectTemplate, MISPSharingGroup, MISPRole, MISPServer, MISPFeed
from .abstract import MISPEncode, MISPTag, AbstractMISP

SearchType = TypeVar('SearchType', str, int)
# str: string to search / list: values to search (OR) / dict: {'OR': [list], 'NOT': [list], 'AND': [list]}
SearchParameterTypes = TypeVar('SearchParameterTypes', str, List[SearchType], Dict[str, SearchType])
DateTypes = TypeVar('DateTypes', datetime, date, SearchType, float)
DateInterval = TypeVar('DateInterval', DateTypes, Tuple[DateTypes, DateTypes])

ToIDSType = TypeVar('ToIDSType', str, int, bool)

logger = logging.getLogger('pymisp')


class ExpandedPyMISP(PyMISP):
    """Python API for MISP

    :param url: URL of the MISP instance you want to connect to
    :param key: API key of the user you want to use
    :param ssl: can be True or False (to check ot not the validity of the certificate. Or a CA_BUNDLE in case of self signed certificate (the concatenation of all the *.crt of the chain)
    :param debug: Write all the debug information to stderr
    :param proxies: Proxy dict as describes here: http://docs.python-requests.org/en/master/user/advanced/#proxies
    :param cert: Client certificate, as described there: http://docs.python-requests.org/en/master/user/advanced/#client-side-certificates
    :param auth: The auth parameter is passed directly to requests, as described here: http://docs.python-requests.org/en/master/user/authentication/
    :param tool: The software using PyMISP (string), used to set a unique user-agent
    """

    def __init__(self, url: str, key: str, ssl=True, debug: bool=False, proxies: dict={},
                 cert: Tuple[str, tuple]=None, auth: AuthBase=None, tool: str=''):
        if not url:
            raise NoURL('Please provide the URL of your MISP instance.')
        if not key:
            raise NoKey('Please provide your authorization key.')

        self.root_url = url
        self.key = key
        self.ssl = ssl
        self.proxies = proxies
        self.cert = cert
        self.auth = auth
        self.tool = tool

        self.resources_path = Path(__file__).parent / 'data'
        if debug:
            logger.setLevel(logging.DEBUG)
            logger.info('To configure logging in your script, leave it to None and use the following: import logging; logging.getLogger(\'pymisp\').setLevel(logging.DEBUG)')

        try:
            # Make sure the MISP instance is working and the URL is valid
            response = self.recommended_pymisp_version
            if response.get('errors'):
                logger.warning(response.get('errors')[0])
            else:
                pymisp_version_tup = tuple(int(x) for x in __version__.split('.'))
                recommended_version_tup = tuple(int(x) for x in response['version'].split('.'))
                if recommended_version_tup < pymisp_version_tup[:3]:
                    logger.info(f"The version of PyMISP recommended by the MISP instance (response['version']) is older than the one you're using now ({__version__}). If you have a problem, please upgrade the MISP instance or use an older PyMISP version.")
                elif pymisp_version_tup[:3] < recommended_version_tup:
                    logger.warning(f"The version of PyMISP recommended by the MI)SP instance ({response['version']}) is newer than the one you're using now ({__version__}). Please upgrade PyMISP.")

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

    @property
    def remote_acl(self):
        """This should return an empty list, unless the ACL is outdated."""
        response = self._prepare_request('GET', 'events/queryACL.json')
        return self._check_response(response, expect_json=True)

    @property
    def describe_types_local(self):
        '''Returns the content of describe types from the package'''
        with (self.resources_path / 'describeTypes.json').open() as f:
            describe_types = json.load(f)
        return describe_types['result']

    @property
    def describe_types_remote(self):
        '''Returns the content of describe types from the remote instance'''
        response = self._prepare_request('GET', 'attributes/describeTypes.json')
        describe_types = self._check_response(response, expect_json=True)
        return describe_types['result']

    @property
    def recommended_pymisp_version(self):
        """Returns the recommended API version from the server"""
        response = self._prepare_request('GET', 'servers/getPyMISPVersion.json')
        return self._check_response(response, expect_json=True)

    @property
    def version(self):
        """Returns the version of PyMISP you're curently using"""
        return {'version': __version__}

    @property
    def pymisp_version_master(self):
        """Get the most recent version of PyMISP from github"""
        r = requests.get('https://raw.githubusercontent.com/MISP/PyMISP/master/pymisp/__init__.py')
        if r.status_code == 200:
            version = re.findall("__version__ = '(.*)'", r.text)
            return {'version': version[0]}
        return {'error': 'Impossible to retrieve the version of the master branch.'}

    @property
    def misp_instance_version(self):
        """Returns the version of the instance."""
        response = self._prepare_request('GET', 'servers/getVersion.json')
        return self._check_response(response, expect_json=True)

    @property
    def misp_instance_version_master(self):
        """Get the most recent version from github"""
        r = requests.get('https://raw.githubusercontent.com/MISP/MISP/2.4/VERSION.json')
        if r.status_code == 200:
            master_version = json.loads(r.text)
            return {'version': '{}.{}.{}'.format(master_version['major'], master_version['minor'], master_version['hotfix'])}
        return {'error': 'Impossible to retrieve the version of the master branch.'}

    # ## BEGIN Event ##

    def get_event(self, event: Union[MISPEvent, int, str, UUID], pythonify: bool=True):
        '''Get an event from a MISP instance'''
        event_id = self.__get_uuid_or_id_from_abstract_misp(event)
        event = self._prepare_request('GET', f'events/{event_id}')
        event = self._check_response(event, expect_json=True)
        if not pythonify or 'errors' in event:
            return event
        e = MISPEvent()
        e.load(event)
        return e

    def add_event(self, event: MISPEvent, pythonify: bool=True):
        '''Add a new event on a MISP instance'''
        new_event = self._prepare_request('POST', 'events', data=event)
        new_event = self._check_response(new_event, expect_json=True)
        if not pythonify or 'errors' in new_event:
            return new_event
        e = MISPEvent()
        e.load(new_event)
        return e

    def update_event(self, event: MISPEvent, event_id: int=None, pythonify: bool=True):
        '''Update an event on a MISP instance'''
        if event_id is None:
            event_id = self.__get_uuid_or_id_from_abstract_misp(event)
        updated_event = self._prepare_request('POST', f'events/{event_id}', data=event)
        updated_event = self._check_response(updated_event, expect_json=True)
        if not pythonify or 'errors' in updated_event:
            return updated_event
        e = MISPEvent()
        e.load(updated_event)
        return e

    def delete_event(self, event: Union[MISPEvent, int, str, UUID]):
        '''Delete an event from a MISP instance'''
        event_id = self.__get_uuid_or_id_from_abstract_misp(event)
        response = self._prepare_request('DELETE', f'events/delete/{event_id}')
        return self._check_response(response, expect_json=True)

    def publish(self, event_id: int, alert: bool=False):
        """Publish the event with one single HTTP POST.
        The default is to not send a mail as it is assumed this method is called on update.
        """
        if alert:
            response = self._prepare_request('POST', f'events/alert/{event_id}')
        else:
            response = self._prepare_request('POST', f'events/publish/{event_id}')
        return self._check_response(response, expect_json=True)

    # ## END Event ###

    # ## BEGIN Object ###

    def get_object(self, misp_object: Union[MISPObject, int, str, UUID], pythonify: bool=True):
        '''Get an object from the remote MISP instance'''
        object_id = self.__get_uuid_or_id_from_abstract_misp(misp_object)
        misp_object = self._prepare_request('GET', f'objects/view/{object_id}')
        misp_object = self._check_response(misp_object, expect_json=True)
        if not pythonify or 'errors' in misp_object:
            return misp_object
        o = MISPObject(misp_object['Object']['name'])
        o.from_dict(**misp_object)
        return o

    def add_object(self, event: Union[MISPEvent, int, str, UUID], misp_object: MISPObject, pythonify: bool=True):
        '''Add a MISP Object to an existing MISP event'''
        event_id = self.__get_uuid_or_id_from_abstract_misp(event)
        new_object = self._prepare_request('POST', f'objects/add/{event_id}', data=misp_object)
        new_object = self._check_response(new_object, expect_json=True)
        if not pythonify or 'errors' in new_object:
            return new_object
        o = MISPObject(new_object['Object']['name'])
        o.from_dict(**new_object)
        return o

    def update_object(self, misp_object: MISPObject, object_id: int=None, pythonify: bool=True):
        '''Update an object on a MISP instance'''
        if object_id is None:
            object_id = self.__get_uuid_or_id_from_abstract_misp(misp_object)
        updated_object = self._prepare_request('POST', f'objects/edit/{object_id}', data=misp_object)
        updated_object = self._check_response(updated_object, expect_json=True)
        if not pythonify or 'errors' in updated_object:
            return updated_object
        o = MISPObject(updated_object['Object']['name'])
        o.from_dict(**updated_object)
        return o

    def delete_object(self, misp_object: Union[MISPObject, int, str, UUID]):
        '''Delete an object from a MISP instance'''
        # FIXME: MISP doesn't support DELETE on this endpoint
        object_id = self.__get_uuid_or_id_from_abstract_misp(misp_object)
        response = self._prepare_request('POST', f'objects/delete/{object_id}')
        return self._check_response(response, expect_json=True)

    def add_object_reference(self, misp_object_reference: MISPObjectReference, pythonify: bool=False):
        """Add a reference to an object"""
        object_reference = self._prepare_request('POST', 'object_references/add', misp_object_reference)
        object_reference = self._check_response(object_reference, expect_json=True)
        if not pythonify or 'errors' in object_reference:
            return object_reference
        r = MISPObjectReference()
        r.from_dict(**object_reference)
        return r

    def delete_object_reference(self, object_reference: Union[MISPObjectReference, int, str, UUID]):
        """Delete a reference to an object"""
        object_reference_id = self.__get_uuid_or_id_from_abstract_misp(object_reference)
        response = self._prepare_request('POST', f'object_references/delete/{object_reference_id}')
        return self._check_response(response, expect_json=True)

    # Object templates

    def object_templates(self, pythonify=False):
        """Get all the object templates."""
        object_templates = self._prepare_request('GET', 'objectTemplates')
        object_templates = self._check_response(object_templates, expect_json=True)
        if not pythonify or 'errors' in object_templates:
            return object_templates
        to_return = []
        for object_template in object_templates:
            o = MISPObjectTemplate()
            o.from_dict(**object_template)
            to_return.append(o)
        return to_return

    def get_object_template(self, object_template: Union[MISPObjectTemplate, int, str, UUID], pythonify=False):
        """Gets the full object template corresponting the UUID passed as parameter"""
        object_template_id = self.__get_uuid_or_id_from_abstract_misp(object_template)
        object_template = self._prepare_request('GET', f'objectTemplates/view/{object_template_id}')
        object_template = self._check_response(object_template, expect_json=True)
        if not pythonify or 'errors' in object_template:
            return object_template
        t = MISPObjectTemplate()
        t.from_dict(**object_template)
        return t

    def update_object_templates(self):
        """Trigger an update of the object templates"""
        response = self._prepare_request('POST', 'objectTemplates/update')
        return self._check_response(response, expect_json=True)

    # ## END Object ###

    # ## BEGIN Attribute ###

    def get_attribute(self, attribute: Union[MISPAttribute, int, str, UUID], pythonify: bool=True):
        '''Get an attribute from a MISP instance'''
        attribute_id = self.__get_uuid_or_id_from_abstract_misp(attribute)
        attribute = self._prepare_request('GET', f'attributes/view/{attribute_id}')
        attribute = self._check_response(attribute, expect_json=True)
        if not pythonify or 'errors' in attribute:
            return attribute
        a = MISPAttribute()
        a.from_dict(**attribute)
        return a

    def add_attribute(self, event: Union[MISPEvent, int, str, UUID], attribute: MISPAttribute, pythonify: bool=True):
        '''Add an attribute to an existing MISP event'''
        event_id = self.__get_uuid_or_id_from_abstract_misp(event)
        new_attribute = self._prepare_request('POST', f'attributes/add/{event_id}', data=attribute)
        if new_attribute.status_code == 403:
            # Re-try with a proposal
            return self.add_attribute_proposal(event_id, attribute, pythonify)
        new_attribute = self._check_response(new_attribute, expect_json=True)
        if not pythonify or 'errors' in new_attribute:
            return new_attribute
        a = MISPAttribute()
        a.from_dict(**new_attribute)
        return a

    def update_attribute(self, attribute: MISPAttribute, attribute_id: int=None, pythonify: bool=True):
        '''Update an attribute on a MISP instance'''
        if attribute_id is None:
            attribute_id = self.__get_uuid_or_id_from_abstract_misp(attribute)
        updated_attribute = self._prepare_request('POST', f'attributes/edit/{attribute_id}', data=attribute)
        if updated_attribute.status_code == 403:
            # Re-try with a proposal
            return self.update_attribute_proposal(attribute_id, attribute, pythonify)
        updated_attribute = self._check_response(updated_attribute, expect_json=True)
        if not pythonify or 'errors' in updated_attribute:
            return updated_attribute
        a = MISPAttribute()
        a.from_dict(**updated_attribute)
        return a

    def delete_attribute(self, attribute: Union[MISPAttribute, int, str, UUID]):
        '''Delete an attribute from a MISP instance'''
        attribute_id = self.__get_uuid_or_id_from_abstract_misp(attribute)
        response = self._prepare_request('POST', f'attributes/delete/{attribute_id}')
        if response.status_code == 403:
            # Re-try with a proposal
            return self.delete_attribute_proposal(attribute_id)
        return self._check_response(response, expect_json=True)

    # ## END Attribute ###

    # ## BEGIN Attribute Proposal ###

    def get_attribute_proposal(self, proposal: Union[MISPShadowAttribute, int, str, UUID], pythonify: bool=True):
        proposal_id = self.__get_uuid_or_id_from_abstract_misp(proposal)
        attribute_proposal = self._prepare_request('GET', f'shadow_attributes/view/{proposal_id}')
        attribute_proposal = self._check_response(attribute_proposal, expect_json=True)
        if not pythonify or 'errors' in attribute_proposal:
            return attribute_proposal
        a = MISPShadowAttribute()
        a.from_dict(**attribute_proposal)
        return a

    # NOTE: the tree following method have a very specific meaning, look at the comments

    def add_attribute_proposal(self, event: Union[MISPEvent, int, str, UUID], attribute: MISPAttribute, pythonify: bool=True):
        '''Propose a new attribute in an event'''
        event_id = self.__get_uuid_or_id_from_abstract_misp(event)
        # FIXME: attribute needs to be a complete MISPAttribute: https://github.com/MISP/MISP/issues/4868
        new_attribute_proposal = self._prepare_request('POST', f'shadow_attributes/add/{event_id}', data=attribute)
        new_attribute_proposal = self._check_response(new_attribute_proposal, expect_json=True)
        if not pythonify or 'errors' in new_attribute_proposal:
            return new_attribute_proposal
        a = MISPShadowAttribute()
        a.from_dict(**new_attribute_proposal)
        return a

    def update_attribute_proposal(self, initial_attribute: Union[MISPAttribute, int, str, UUID], attribute: MISPAttribute, pythonify: bool=True):
        '''Propose a change for an attribute'''
        # FIXME: inconsistency in MISP: https://github.com/MISP/MISP/issues/4857
        initial_attribute_id = self.__get_uuid_or_id_from_abstract_misp(initial_attribute)
        attribute = {'ShadowAttribute': attribute}
        update_attribute_proposal = self._prepare_request('POST', f'shadow_attributes/edit/{initial_attribute_id}', data=attribute)
        update_attribute_proposal = self._check_response(update_attribute_proposal, expect_json=True)
        if not pythonify or 'errors' in update_attribute_proposal:
            return update_attribute_proposal
        a = MISPShadowAttribute()
        a.from_dict(**update_attribute_proposal)
        return a

    def delete_attribute_proposal(self, attribute: Union[MISPAttribute, int, str, UUID]):
        '''Propose the deletion of an attribute'''
        attribute_id = self.__get_uuid_or_id_from_abstract_misp(attribute)
        response = self._prepare_request('POST', f'shadow_attributes/delete/{attribute_id}')
        return self._check_response(response, expect_json=True)

    # NOTE: You cannot modify an existing proposal, only accept/discard

    def accept_attribute_proposal(self, proposal: Union[MISPShadowAttribute, int, str, UUID]):
        '''Accept a proposal'''
        proposal_id = self.__get_uuid_or_id_from_abstract_misp(proposal)
        response = self._prepare_request('POST', f'shadow_attributes/accept/{proposal_id}')
        return self._check_response(response, expect_json=True)

    def discard_attribute_proposal(self, proposal: Union[MISPShadowAttribute, int, str, UUID]):
        '''Discard a proposal'''
        proposal_id = self.__get_uuid_or_id_from_abstract_misp(proposal)
        response = self._prepare_request('POST', f'shadow_attributes/discard/{proposal_id}')
        return self._check_response(response, expect_json=True)

    # ## END Attribute Proposal ###

    # ## BEGIN Sighting ###

    def sightings(self, misp_entity: AbstractMISP, org: Union[MISPOrganisation, int, str, UUID]=None, pythonify=False):
        """Get the list of sighting related to a MISPEvent or a MISPAttribute (depending on type of misp_entity)"""
        # FIXME: https://github.com/MISP/MISP/issues/4875
        if isinstance(misp_entity, MISPEvent):
            scope = 'event'
        elif isinstance(misp_entity, MISPAttribute):
            scope = 'attribute'
        else:
            raise PyMISPError('misp_entity can only be a MISPEvent or a MISPAttribute')
        if org is not None:
            org_id = self.__get_uuid_or_id_from_abstract_misp(org)
            url = f'sightings/listSightings/{misp_entity.id}/{scope}/{org_id}'
        else:
            url = f'sightings/listSightings/{misp_entity.id}/{scope}'
        sightings = self._prepare_request('POST', url)
        sightings = self._check_response(sightings, expect_json=True)
        if not pythonify or 'errors' in sightings:
            return sightings
        to_return = []
        for sighting in sightings:
            s = MISPSighting()
            s.from_dict(**sighting)
            to_return.append(s)
        return to_return

    def add_sighting(self, sighting: MISPSighting, attribute: Union[MISPAttribute, int, str, UUID]=None):
        '''Add a new sighting (globally, or to a specific attribute)'''
        # FIXME: no pythonify possible: https://github.com/MISP/MISP/issues/4867
        pythonify = False
        if attribute:
            attribute_id = self.__get_uuid_or_id_from_abstract_misp(attribute)
            new_sighting = self._prepare_request('POST', f'sightings/add/{attribute_id}', data=sighting)
        else:
            # Either the ID/UUID is in the sighting, or we want to add a sighting on all the attributes with the given value
            new_sighting = self._prepare_request('POST', f'sightings/add', data=sighting)
        new_sighting = self._check_response(new_sighting, expect_json=True)
        if not pythonify or 'errors' in new_sighting:
            return new_sighting
        s = MISPSighting()
        s.from_dict(**new_sighting)
        return s

    # ## END Sighting ###

    # ## BEGIN Tags ###

    def tags(self, pythonify: bool=False):
        """Get the list of existing tags."""
        tags = self._prepare_request('GET', 'tags')
        tags = self._check_response(tags, expect_json=True)
        if not pythonify or 'errors' in tags:
            return tags['Tag']
        to_return = []
        for tag in tags['Tag']:
            t = MISPTag()
            t.from_dict(**tag)
            to_return.append(t)
        return to_return

    def get_tag(self, tag: Union[MISPTag, int, str, UUID], pythonify: bool=False):
        """Get a tag by id."""
        tag_id = self.__get_uuid_or_id_from_abstract_misp(tag)
        tag = self._prepare_request('GET', f'tags/view/{tag_id}')
        tag = self._check_response(tag, expect_json=True)
        if not pythonify or 'errors' in tag:
            return tag
        t = MISPTag()
        t.from_dict(**tag)
        return t

    def add_tag(self, tag: MISPTag, pythonify: bool=True):
        '''Add a new tag on a MISP instance'''
        new_tag = self._prepare_request('POST', 'tags/add', data=tag)
        new_tag = self._check_response(new_tag, expect_json=True)
        if not pythonify or 'errors' in new_tag:
            return new_tag
        t = MISPTag()
        t.from_dict(**new_tag)
        return t

    def enable_tag(self, tag: MISPTag, pythonify: bool=False):
        """Enable a tag."""
        tag.hide_tag = False
        return self.update_tag(tag, pythonify=pythonify)

    def disable_tag(self, tag: MISPTag, pythonify: bool=False):
        """Disable a tag."""
        tag.hide_tag = True
        return self.update_tag(tag, pythonify=pythonify)

    def update_tag(self, tag: MISPTag, tag_id: int=None, pythonify: bool=False):
        """Edit only the provided parameters of a tag."""
        if tag_id is None:
            tag_id = self.__get_uuid_or_id_from_abstract_misp(tag)
        # FIXME: inconsistency in MISP: https://github.com/MISP/MISP/issues/4852
        tag = {'Tag': tag}
        updated_tag = self._prepare_request('POST', f'tags/edit/{tag_id}', data=tag)
        updated_tag = self._check_response(updated_tag, expect_json=True)
        if not pythonify or 'errors' in updated_tag:
            return updated_tag
        t = MISPTag()
        t.from_dict(**updated_tag)
        return t

    def delete_tag(self, tag: Union[MISPTag, int, str, UUID]):
        '''Delete an attribute from a MISP instance'''
        tag_id = self.__get_uuid_or_id_from_abstract_misp(tag)
        response = self._prepare_request('POST', f'tags/delete/{tag_id}')
        return self._check_response(response, expect_json=True)

    # ## END Tags ###

    # ## BEGIN Taxonomies ###

    def update_taxonomies(self):
        """Update all the taxonomies."""
        response = self._prepare_request('POST', 'taxonomies/update')
        return self._check_response(response, expect_json=True)

    def taxonomies(self, pythonify: bool=False):
        """Get all the taxonomies."""
        taxonomies = self._prepare_request('GET', 'taxonomies')
        taxonomies = self._check_response(taxonomies, expect_json=True)
        if not pythonify or 'errors' in taxonomies:
            return taxonomies
        to_return = []
        for taxonomy in taxonomies:
            t = MISPTaxonomy()
            t.from_dict(**taxonomy)
            to_return.append(t)
        return to_return

    def get_taxonomy(self, taxonomy: Union[MISPTaxonomy, int, str, UUID], pythonify: bool=False):
        """Get a taxonomy from a MISP instance."""
        taxonomy_id = self.__get_uuid_or_id_from_abstract_misp(taxonomy)
        taxonomy = self._prepare_request('GET', f'taxonomies/view/{taxonomy_id}')
        taxonomy = self._check_response(taxonomy, expect_json=True)
        if not pythonify or 'errors' in taxonomy:
            return taxonomy
        t = MISPTaxonomy()
        t.from_dict(**taxonomy)
        return t

    def enable_taxonomy(self, taxonomy: Union[MISPTaxonomy, int, str, UUID]):
        """Enable a taxonomy."""
        taxonomy_id = self.__get_uuid_or_id_from_abstract_misp(taxonomy)
        response = self._prepare_request('POST', f'taxonomies/enable/{taxonomy_id}')
        return self._check_response(response, expect_json=True)

    def disable_taxonomy(self, taxonomy: Union[MISPTaxonomy, int, str, UUID]):
        """Disable a taxonomy."""
        taxonomy_id = self.__get_uuid_or_id_from_abstract_misp(taxonomy)
        self.disable_taxonomy_tags(taxonomy_id)
        response = self._prepare_request('POST', f'taxonomies/disable/{taxonomy_id}')
        return self._check_response(response, expect_json=True)

    def disable_taxonomy_tags(self, taxonomy: Union[MISPTaxonomy, int, str, UUID]):
        """Disable all the tags of a taxonomy."""
        taxonomy_id = self.__get_uuid_or_id_from_abstract_misp(taxonomy)
        response = self._prepare_request('POST', f'taxonomies/disableTag/{taxonomy_id}')
        return self._check_response(response, expect_json=True)

    def enable_taxonomy_tags(self, taxonomy: Union[MISPTaxonomy, int, str, UUID]):
        """Enable all the tags of a taxonomy.
        NOTE: this automatically done when you call enable_taxonomy."""
        taxonomy_id = self.__get_uuid_or_id_from_abstract_misp(taxonomy)
        taxonomy = self.get_taxonomy(taxonomy_id)
        if not taxonomy['Taxonomy']['enabled']:
            raise PyMISPError(f"The taxonomy {taxonomy['Taxonomy']['name']} is not enabled.")
        url = urljoin(self.root_url, 'taxonomies/addTag/{}'.format(taxonomy_id))
        response = self._prepare_request('POST', url)
        return self._check_response(response, expect_json=True)

    # ## END Taxonomies ###

    # ## BEGIN Warninglists ###

    def warninglists(self, pythonify: bool=False):
        """Get all the warninglists."""
        warninglists = self._prepare_request('GET', 'warninglists')
        warninglists = self._check_response(warninglists, expect_json=True)
        if not pythonify or 'errors' in warninglists:
            return warninglists['Warninglists']
        to_return = []
        for warninglist in warninglists['Warninglists']:
            w = MISPWarninglist()
            w.from_dict(**warninglist)
            to_return.append(w)
        return to_return

    def get_warninglist(self, warninglist: Union[MISPWarninglist, int, str, UUID], pythonify: bool=False):
        """Get a warninglist."""
        warninglist_id = self.__get_uuid_or_id_from_abstract_misp(warninglist)
        warninglist = self._prepare_request('GET', f'warninglists/view/{warninglist_id}')
        warninglist = self._check_response(warninglist, expect_json=True)
        if not pythonify or 'errors' in warninglist:
            return warninglist
        w = MISPWarninglist()
        w.from_dict(**warninglist)
        return w

    def toggle_warninglist(self, warninglist_id: List[int]=None, warninglist_name: List[str]=None,
                           force_enable: bool=False):
        '''Toggle (enable/disable) the status of a warninglist by ID.
        :param warninglist_id: ID of the WarningList
        :param force_enable: Force the warning list in the enabled state (does nothing is already enabled)
        '''
        if warninglist_id is None and warninglist_name is None:
            raise PyMISPError('Either warninglist_id or warninglist_name is required.')
        query = {}
        if warninglist_id is not None:
            if not isinstance(warninglist_id, list):
                warninglist_id = [warninglist_id]
            query['id'] = warninglist_id
        if warninglist_name is not None:
            if not isinstance(warninglist_name, list):
                warninglist_name = [warninglist_name]
            query['name'] = warninglist_name
        if force_enable:
            query['enabled'] = force_enable
        response = self._prepare_request('POST', 'warninglists/toggleEnable', data=json.dumps(query))
        return self._check_response(response, expect_json=True)

    def update_warninglists(self):
        """Update all the warninglists."""
        response = self._prepare_request('POST', 'warninglists/update')
        return self._check_response(response, expect_json=True)

    def enable_warninglist(self, warninglist: Union[MISPWarninglist, int, str, UUID]):
        """Enable a warninglist."""
        warninglist_id = self.__get_uuid_or_id_from_abstract_misp(warninglist)
        return self.toggle_warninglist(warninglist_id=warninglist_id, force_enable=True)

    def disable_warninglist(self, warninglist: Union[MISPWarninglist, int, str, UUID]):
        """Disable a warninglist."""
        warninglist_id = self.__get_uuid_or_id_from_abstract_misp(warninglist)
        return self.toggle_warninglist(warninglist_id=warninglist_id, force_enable=False)

    def values_in_warninglist(self, value: list):
        """Check if IOC values are in warninglist"""
        response = self._prepare_request('POST', 'warninglists/checkValue', data=json.dumps(value))
        return self._check_response(response, expect_json=True)

    # ## END Warninglists ###

    # ## BEGIN Noticelist ###

    def noticelists(self, pythonify=False):
        """Get all the noticelists."""
        noticelists = self._prepare_request('GET', 'noticelists')
        noticelists = self._check_response(noticelists, expect_json=True)
        if not pythonify or 'errors' in noticelists:
            return noticelists
        to_return = []
        for noticelist in noticelists:
            n = MISPNoticelist()
            n.from_dict(**noticelist)
            to_return.append(n)
        return to_return

    def get_noticelist(self, noticelist: Union[MISPNoticelist, int, str, UUID], pythonify=False):
        """Get a noticelist by id."""
        noticelist_id = self.__get_uuid_or_id_from_abstract_misp(noticelist)
        noticelist = self._prepare_request('GET', f'noticelists/view/{noticelist_id}')
        noticelist = self._check_response(noticelist, expect_json=True)
        if not pythonify or 'errors' in noticelist:
            return noticelist
        n = MISPNoticelist()
        n.from_dict(**noticelist)
        return n

    def enable_noticelist(self, noticelist: Union[MISPNoticelist, int, str, UUID]):
        """Enable a noticelist by id."""
        # FIXME: https://github.com/MISP/MISP/issues/4856
        # response = self._prepare_request('POST', f'noticelists/enable/{noticelist_id}')
        noticelist_id = self.__get_uuid_or_id_from_abstract_misp(noticelist)
        response = self._prepare_request('POST', f'noticelists/enableNoticelist/{noticelist_id}/true')
        return self._check_response(response, expect_json=True)

    def disable_noticelist(self, noticelist: Union[MISPNoticelist, int, str, UUID]):
        """Disable a noticelist by id."""
        # FIXME: https://github.com/MISP/MISP/issues/4856
        # response = self._prepare_request('POST', f'noticelists/disable/{noticelist_id}')
        noticelist_id = self.__get_uuid_or_id_from_abstract_misp(noticelist)
        response = self._prepare_request('POST', f'noticelists/enableNoticelist/{noticelist_id}')
        return self._check_response(response, expect_json=True)

    def update_noticelists(self):
        """Update all the noticelists."""
        response = self._prepare_request('POST', 'noticelists/update')
        return self._check_response(response, expect_json=True)

    # ## END Noticelist ###

    # ## BEGIN Galaxy ###

    def galaxies(self, pythonify=False):
        """Get all the galaxies."""
        galaxies = self._prepare_request('GET', 'galaxies')
        galaxies = self._check_response(galaxies, expect_json=True)
        if not pythonify or 'errors' in galaxies:
            return galaxies
        to_return = []
        for galaxy in galaxies:
            g = MISPGalaxy()
            g.from_dict(**galaxy)
            to_return.append(g)
        return to_return

    def get_galaxy(self, galaxy: Union[MISPGalaxy, int, str, UUID], pythonify=False):
        """Get a galaxy by id."""
        galaxy_id = self.__get_uuid_or_id_from_abstract_misp(galaxy)
        galaxy = self._prepare_request('GET', f'galaxies/view/{galaxy_id}')
        galaxy = self._check_response(galaxy, expect_json=True)
        if not pythonify or 'errors' in galaxy:
            return galaxy
        g = MISPGalaxy()
        g.from_dict(**galaxy)
        return g

    def update_galaxies(self):
        """Update all the galaxies."""
        response = self._prepare_request('POST', 'galaxies/update')
        return self._check_response(response, expect_json=True)

    # ## END Galaxy ###

    # ## BEGIN Feed ###

    def feeds(self, pythonify: bool=False):
        """Get the list of existing feeds."""
        feeds = self._prepare_request('GET', 'feeds')
        feeds = self._check_response(feeds, expect_json=True)
        if not pythonify or 'errors' in feeds:
            return feeds
        to_return = []
        for feed in feeds:
            f = MISPFeed()
            f.from_dict(**feed)
            to_return.append(f)
        return to_return

    def get_feed(self, feed: Union[MISPFeed, int, str, UUID], pythonify: bool=False):
        """Get a feed by id."""
        feed_id = self.__get_uuid_or_id_from_abstract_misp(feed)
        feed = self._prepare_request('GET', f'feeds/view/{feed_id}')
        feed = self._check_response(feed, expect_json=True)
        if not pythonify or 'errors' in feed:
            return feed
        f = MISPFeed()
        f.from_dict(**feed)
        return f

    def add_feed(self, feed: MISPFeed, pythonify: bool=False):
        '''Add a new feed on a MISP instance'''
        # FIXME: https://github.com/MISP/MISP/issues/4834
        feed = {'Feed': feed}
        new_feed = self._prepare_request('POST', 'feeds/add', data=feed)
        new_feed = self._check_response(new_feed, expect_json=True)
        if not pythonify or 'errors' in new_feed:
            return new_feed
        f = MISPFeed()
        f.from_dict(**new_feed)
        return f

    def enable_feed(self, feed: Union[MISPFeed, int, str, UUID], pythonify: bool=False):
        '''Enable a feed (fetching it will create event(s)'''
        if not isinstance(feed, MISPFeed):
            feed_id = self.__get_uuid_or_id_from_abstract_misp(feed)  # In case we have a UUID
            feed = MISPFeed()
            feed.id = feed_id
            feed.enabled = True
        return self.update_feed(feed=feed, pythonify=pythonify)

    def disable_feed(self, feed: Union[MISPFeed, int, str, UUID], pythonify: bool=False):
        '''Disable a feed'''
        if not isinstance(feed, MISPFeed):
            feed_id = self.__get_uuid_or_id_from_abstract_misp(feed)  # In case we have a UUID
            feed = MISPFeed()
            feed.id = feed_id
            feed.enabled = False
        return self.update_feed(feed=feed, pythonify=pythonify)

    def enable_feed_cache(self, feed: Union[MISPFeed, int, str, UUID], pythonify: bool=False):
        '''Enable the caching of a feed'''
        if not isinstance(feed, MISPFeed):
            feed_id = self.__get_uuid_or_id_from_abstract_misp(feed)  # In case we have a UUID
            feed = MISPFeed()
            feed.id = feed_id
            feed.caching_enabled = True
        return self.update_feed(feed=feed, pythonify=pythonify)

    def disable_feed_cache(self, feed: Union[MISPFeed, int, str, UUID], pythonify: bool=False):
        '''Disable the caching of a feed'''
        if not isinstance(feed, MISPFeed):
            feed_id = self.__get_uuid_or_id_from_abstract_misp(feed)  # In case we have a UUID
            feed = MISPFeed()
            feed.id = feed_id
            feed.caching_enabled = False
        return self.update_feed(feed=feed, pythonify=pythonify)

    def update_feed(self, feed: MISPFeed, feed_id: int=None, pythonify: bool=False):
        '''Update a feed on a MISP instance'''
        if feed_id is None:
            feed_id = self.__get_uuid_or_id_from_abstract_misp(feed)
        # FIXME: https://github.com/MISP/MISP/issues/4834
        feed = {'Feed': feed}
        updated_feed = self._prepare_request('POST', f'feeds/edit/{feed_id}', data=feed)
        updated_feed = self._check_response(updated_feed, expect_json=True)
        if not pythonify or 'errors' in updated_feed:
            return updated_feed
        f = MISPFeed()
        f.from_dict(**updated_feed)
        return f

    def delete_feed(self, feed: Union[MISPFeed, int, str, UUID]):
        '''Delete a feed from a MISP instance'''
        feed_id = self.__get_uuid_or_id_from_abstract_misp(feed)
        response = self._prepare_request('POST', f'feeds/delete/{feed_id}')
        return self._check_response(response, expect_json=True)

    def fetch_feed(self, feed: Union[MISPFeed, int, str, UUID]):
        """Fetch one single feed"""
        feed_id = self.__get_uuid_or_id_from_abstract_misp(feed)
        response = self._prepare_request('GET', f'feeds/fetchFromFeed/{feed_id}')
        return self._check_response(response)

    def cache_all_feeds(self):
        """ Cache all the feeds"""
        response = self._prepare_request('GET', 'feeds/cacheFeeds/all')
        return self._check_response(response)

    def cache_feed(self, feed: Union[MISPFeed, int, str, UUID]):
        """Cache a specific feed"""
        feed_id = self.__get_uuid_or_id_from_abstract_misp(feed)
        response = self._prepare_request('GET', f'feeds/cacheFeeds/{feed_id}')
        return self._check_response(response)

    def cache_freetext_feeds(self):
        """Cache all the freetext feeds"""
        response = self._prepare_request('GET', 'feeds/cacheFeeds/freetext')
        return self._check_response(response)

    def cache_misp_feeds(self):
        """Cache all the MISP feeds"""
        response = self._prepare_request('GET', 'feeds/cacheFeeds/misp')
        return self._check_response(response)

    def compare_feeds(self):
        """Generate the comparison matrix for all the MISP feeds"""
        response = self._prepare_request('GET', 'feeds/compareFeeds')
        return self._check_response(response)

    # ## END Feed ###

    # ## BEGIN Server ###

    def servers(self, pythonify=False):
        """Get the existing servers the MISP instance can synchronise with"""
        servers = self._prepare_request('GET', 'servers')
        servers = self._check_response(servers, expect_json=True)
        if not pythonify or 'errors' in servers:
            return servers
        to_return = []
        for server in servers:
            s = MISPServer()
            s.from_dict(**server)
            to_return.append(s)
        return to_return

    def add_server(self, server: MISPServer, pythonify: bool=True):
        """Add a server to synchronise with"""
        server = self._prepare_request('POST', f'servers/add', data=server)
        server = self._check_response(server, expect_json=True)
        if not pythonify or 'errors' in server:
            return server
        s = MISPServer()
        s.from_dict(**server)
        return s

    def update_server(self, server: MISPServer, server_id: int=None, pythonify: bool=True):
        '''Update a server to synchronise with'''
        if server_id is None:
            server_id = self.__get_uuid_or_id_from_abstract_misp(server)
        updated_server = self._prepare_request('POST', f'servers/edit/{server_id}', data=server)
        updated_server = self._check_response(updated_server, expect_json=True)
        if not pythonify or 'errors' in updated_server:
            return updated_server
        s = MISPServer()
        s.from_dict(**updated_server)
        return s

    def delete_server(self, server: Union[MISPServer, int, str, UUID]):
        '''Delete a sync server'''
        server_id = self.__get_uuid_or_id_from_abstract_misp(server)
        response = self._prepare_request('POST', f'servers/delete/{server_id}')
        return self._check_response(response, expect_json=True)

    def server_pull(self, server: Union[MISPServer, int, str, UUID], event: Union[MISPEvent, int, str, UUID]=None):
        '''Initialize a pull from a sync server'''
        server_id = self.__get_uuid_or_id_from_abstract_misp(server)
        # FIXME: POST & data
        if event:
            event_id = self.__get_uuid_or_id_from_abstract_misp(event)
            url = f'servers/pull/{server_id}/{event_id}'
        else:
            url = f'servers/pull/{server_id}'
        response = self._prepare_request('GET', url)
        # FIXME: can we pythonify?
        return self._check_response(response)

    def server_push(self, server: Union[MISPServer, int, str, UUID], event: Union[MISPEvent, int, str, UUID]=None):
        '''Initialize a push to a sync server'''
        server_id = self.__get_uuid_or_id_from_abstract_misp(server)
        # FIXME: POST & data
        if event:
            event_id = self.__get_uuid_or_id_from_abstract_misp(event)
            url = f'servers/push/{server_id}/{event_id}'
        else:
            url = f'servers/push/{server_id}'
        response = self._prepare_request('GET', url)
        # FIXME: can we pythonify?
        return self._check_response(response)

    # ## END Server ###

    # ## BEGIN Sharing group ###

    def sharing_groups(self, pythonify: bool=False):
        """Get the existing sharing groups"""
        sharing_groups = self._prepare_request('GET', 'sharing_groups')
        sharing_groups = self._check_response(sharing_groups, expect_json=True)
        if not pythonify or 'errors' in sharing_groups:
            return sharing_groups
        to_return = []
        for sharing_group in sharing_groups:
            s = MISPSharingGroup()
            s.from_dict(**sharing_group)
            to_return.append(s)
        return to_return

    def add_sharing_group(self, sharing_group: MISPSharingGroup, pythonify: bool=True):
        """Add a new sharing group"""
        sharing_group = self._prepare_request('POST', f'sharing_groups/add', data=sharing_group)
        sharing_group = self._check_response(sharing_group, expect_json=True)
        # FIXME: https://github.com/MISP/MISP/issues/4882
        sharing_group = sharing_group[0]
        if not pythonify or 'errors' in sharing_group:
            return sharing_group
        s = MISPSharingGroup()
        s.from_dict(**sharing_group)
        return s

    def delete_sharing_group(self, sharing_group: Union[MISPSharingGroup, int, str, UUID]):
        """Delete a sharing group"""
        sharing_group_id = self.__get_uuid_or_id_from_abstract_misp(sharing_group)
        response = self._prepare_request('POST', f'sharing_groups/delete/{sharing_group_id}')
        return self._check_response(response, expect_json=True)

    def add_org_to_sharing_group(self, sharing_group: Union[MISPSharingGroup, int, str, UUID],
                                 organisation: Union[MISPOrganisation, int, str, UUID], extend: bool=False):
        '''Add an organisation to a sharing group.
        :sharing_group: Sharing group's local instance ID, or Sharing group's global UUID
        :organisation: Organisation's local instance ID, or Organisation's global UUID, or Organisation's name as known to the curent instance
        :extend: Allow the organisation to extend the group
        '''
        sharing_group_id = self.__get_uuid_or_id_from_abstract_misp(sharing_group)
        organisation_id = self.__get_uuid_or_id_from_abstract_misp(organisation)
        to_jsonify = {'sg_id': sharing_group_id, 'org_id': organisation_id, 'extend': extend}
        response = self._prepare_request('POST', 'sharingGroups/addOrg', data=to_jsonify)
        return self._check_response(response)

    def remove_org_from_sharing_group(self, sharing_group: Union[MISPSharingGroup, int, str, UUID],
                                      organisation: Union[MISPOrganisation, int, str, UUID]):
        '''Remove an organisation from a sharing group.
        :sharing_group: Sharing group's local instance ID, or Sharing group's global UUID
        :organisation: Organisation's local instance ID, or Organisation's global UUID, or Organisation's name as known to the curent instance
        '''
        sharing_group_id = self.__get_uuid_or_id_from_abstract_misp(sharing_group)
        organisation_id = self.__get_uuid_or_id_from_abstract_misp(organisation)
        to_jsonify = {'sg_id': sharing_group_id, 'org_id': organisation_id}
        response = self._prepare_request('POST', 'sharingGroups/removeOrg', data=to_jsonify)
        return self._check_response(response)

    def add_server_to_sharing_group(self, sharing_group: Union[MISPSharingGroup, int, str, UUID],
                                    server: Union[MISPServer, int, str, UUID], all_orgs: bool=False):
        '''Add a server to a sharing group.
        :sharing_group: Sharing group's local instance ID, or Sharing group's global UUID
        :server: Server's local instance ID, or URL of the Server, or Server's name as known to the curent instance
        :all_orgs: Add all the organisations of the server to the group
        '''
        sharing_group_id = self.__get_uuid_or_id_from_abstract_misp(sharing_group)
        server_id = self.__get_uuid_or_id_from_abstract_misp(server)
        to_jsonify = {'sg_id': sharing_group_id, 'server_id': server_id, 'all_orgs': all_orgs}
        response = self._prepare_request('POST', 'sharingGroups/addServer', data=to_jsonify)
        return self._check_response(response)

    def remove_server_from_sharing_group(self, sharing_group: Union[MISPSharingGroup, int, str, UUID],
                                         server: Union[MISPServer, int, str, UUID]):
        '''Remove a server from a sharing group.
        :sharing_group: Sharing group's local instance ID, or Sharing group's global UUID
        :server: Server's local instance ID, or URL of the Server, or Server's name as known to the curent instance
        '''
        sharing_group_id = self.__get_uuid_or_id_from_abstract_misp(sharing_group)
        server_id = self.__get_uuid_or_id_from_abstract_misp(server)
        to_jsonify = {'sg_id': sharing_group_id, 'server_id': server_id}
        response = self._prepare_request('POST', 'sharingGroups/removeServer', data=to_jsonify)
        return self._check_response(response)

    # ## END Sharing groups ###

    # ## BEGIN Organisation ###

    def organisations(self, scope="local", pythonify=False):
        """Get all the organisations."""
        organisations = self._prepare_request('GET', f'organisations/index/scope:{scope}')
        organisations = self._check_response(organisations, expect_json=True)
        if not pythonify or 'errors' in organisations:
            return organisations
        to_return = []
        for organisation in organisations:
            o = MISPOrganisation()
            o.from_dict(**organisation)
            to_return.append(o)
        return to_return

    def get_organisation(self, organisation: Union[MISPOrganisation, int, str, UUID], pythonify: bool=True):
        '''Get an organisation.'''
        organisation_id = self.__get_uuid_or_id_from_abstract_misp(organisation)
        organisation = self._prepare_request('GET', f'organisations/view/{organisation_id}')
        organisation = self._check_response(organisation, expect_json=True)
        if not pythonify or 'errors' in organisation:
            return organisation
        o = MISPOrganisation()
        o.from_dict(**organisation)
        return o

    def add_organisation(self, organisation: MISPOrganisation, pythonify: bool=True):
        '''Add an organisation'''
        new_organisation = self._prepare_request('POST', f'admin/organisations/add', data=organisation)
        new_organisation = self._check_response(new_organisation, expect_json=True)
        if not pythonify or 'errors' in new_organisation:
            return new_organisation
        o = MISPOrganisation()
        o.from_dict(**new_organisation)
        return o

    def update_organisation(self, organisation: MISPOrganisation, organisation_id: int=None, pythonify: bool=True):
        '''Update an organisation'''
        if organisation_id is None:
            organisation_id = self.__get_uuid_or_id_from_abstract_misp(organisation)
        updated_organisation = self._prepare_request('POST', f'admin/organisations/edit/{organisation_id}', data=organisation)
        updated_organisation = self._check_response(updated_organisation, expect_json=True)
        if not pythonify or 'errors' in updated_organisation:
            return updated_organisation
        o = MISPOrganisation()
        o.from_dict(**organisation)
        return o

    def delete_organisation(self, organisation: Union[MISPOrganisation, int, str, UUID]):
        '''Delete an organisation'''
        # NOTE: MISP in inconsistent and currently require "delete" in the path and doesn't support HTTP DELETE
        organisation_id = self.__get_uuid_or_id_from_abstract_misp(organisation)
        response = self._prepare_request('POST', f'admin/organisations/delete/{organisation_id}')
        return self._check_response(response, expect_json=True)

    # ## END Organisation ###

    # ## BEGIN User ###

    def users(self, pythonify=False):
        """Get all the users."""
        users = self._prepare_request('GET', 'admin/users')
        users = self._check_response(users, expect_json=True)
        if not pythonify or 'errors' in users:
            return users
        to_return = []
        for user in users:
            u = MISPUser()
            u.from_dict(**user)
            to_return.append(u)
        return to_return

    def get_user(self, user: Union[MISPUser, int, str, UUID]='me', pythonify: bool=False):
        '''Get a user. `me` means the owner of the API key doing the query.'''
        user_id = self.__get_uuid_or_id_from_abstract_misp(user)
        user = self._prepare_request('GET', f'users/view/{user_id}')
        user = self._check_response(user, expect_json=True)
        if not pythonify or 'errors' in user:
            return user
        u = MISPUser()
        u.from_dict(**user)
        return u

    def add_user(self, user: MISPUser, pythonify: bool=False):
        '''Add a new user'''
        user = self._prepare_request('POST', f'admin/users/add', data=user)
        user = self._check_response(user, expect_json=True)
        if not pythonify or 'errors' in user:
            return user
        u = MISPUser()
        u.from_dict(**user)
        return u

    def update_user(self, user: MISPUser, user_id: int=None, pythonify: bool=False):
        '''Update an event on a MISP instance'''
        if user_id is None:
            user_id = self.__get_uuid_or_id_from_abstract_misp(user)
        updated_user = self._prepare_request('POST', f'admin/users/edit/{user_id}', data=user)
        updated_user = self._check_response(updated_user, expect_json=True)
        if not pythonify or 'errors' in updated_user:
            return updated_user
        e = MISPUser()
        e.from_dict(**updated_user)
        return e

    def delete_user(self, user: Union[MISPUser, int, str, UUID]):
        '''Delete a user'''
        # NOTE: MISP in inconsistent and currently require "delete" in the path and doesn't support HTTP DELETE
        user_id = self.__get_uuid_or_id_from_abstract_misp(user)
        response = self._prepare_request('POST', f'admin/users/delete/{user_id}')
        return self._check_response(response, expect_json=True)

    # ## END User ###

    # ## BEGIN Role ###

    def roles(self, pythonify: bool=False):
        """Get the existing roles"""
        roles = self._prepare_request('GET', 'roles')
        roles = self._check_response(roles, expect_json=True)
        if not pythonify or 'errors' in roles:
            return roles
        to_return = []
        for role in roles:
            r = MISPRole()
            r.from_dict(**role)
            to_return.append(r)
        return to_return

    def set_default_role(self, role: Union[MISPRole, int, str, UUID]):
        role_id = self.__get_uuid_or_id_from_abstract_misp(role)
        url = urljoin(self.root_url, f'/admin/roles/set_default/{role_id}')
        response = self._prepare_request('POST', url)
        return self._check_response(response, expect_json=True)

    # ## END Role ###

    # ## BEGIN Search methods ###

    def search(self, controller: str='events', return_format: str='json',
               limit: Optional[int]=None, page: Optional[int]=None,
               value: Optional[SearchParameterTypes]=None,
               type_attribute: Optional[SearchParameterTypes]=None,
               category: Optional[SearchParameterTypes]=None,
               org: Optional[SearchParameterTypes]=None,
               tags: Optional[SearchParameterTypes]=None,
               quick_filter: Optional[str]=None, quickFilter: Optional[str]=None,
               date_from: Optional[DateTypes]=None,
               date_to: Optional[DateTypes]=None,
               eventid: Optional[SearchType]=None,
               with_attachments: Optional[bool]=None, withAttachments: Optional[bool]=None,
               metadata: Optional[bool]=None,
               uuid: Optional[str]=None,
               publish_timestamp: Optional[DateInterval]=None, last: Optional[DateInterval]=None,
               timestamp: Optional[DateInterval]=None,
               published: Optional[bool]=None,
               enforce_warninglist: Optional[bool]=None, enforceWarninglist: Optional[bool]=None,
               to_ids: Optional[Union[ToIDSType, List[ToIDSType]]]=None,
               deleted: Optional[str]=None,
               include_event_uuid: Optional[str]=None, includeEventUuid: Optional[str]=None,
               event_timestamp: Optional[DateTypes]=None,
               sg_reference_only: Optional[bool]=None,
               eventinfo: Optional[str]=None,
               searchall: Optional[bool]=None,
               requested_attributes: Optional[str]=None,
               include_context: Optional[bool]=None, includeContext: Optional[bool]=None,
               headerless: Optional[bool]=None,
               pythonify: Optional[bool]=False,
               **kwargs):
        '''Search in the MISP instance

        :param returnFormat: Set the return format of the search (Currently supported: json, xml, openioc, suricata, snort - more formats are being moved to restSearch with the goal being that all searches happen through this API). Can be passed as the first parameter after restSearch or via the JSON payload.
        :param limit: Limit the number of results returned, depending on the scope (for example 10 attributes or 10 full events).
        :param page: If a limit is set, sets the page to be returned. page 3, limit 100 will return records 201->300).
        :param value: Search for the given value in the attributes' value field.
        :param type_attribute: The attribute type, any valid MISP attribute type is accepted.
        :param category: The attribute category, any valid MISP attribute category is accepted.
        :param org: Search by the creator organisation by supplying the organisation identifier.
        :param tags: Tags to search or to exclude. You can pass a list, or the output of `build_complex_query`
        :param quick_filter: The string passed to this field will ignore all of the other arguments. MISP will return an xml / json (depending on the header sent) of all events that have a sub-string match on value in the event info, event orgc, or any of the attribute value1 / value2 fields, or in the attribute comment.
        :param date_from: Events with the date set to a date after the one specified. This filter will use the date of the event.
        :param date_to: Events with the date set to a date before the one specified. This filter will use the date of the event.
        :param eventid: The events that should be included / excluded from the search
        :param with_attachments: If set, encodes the attachments / zipped malware samples as base64 in the data field within each attribute
        :param metadata: Only the metadata (event, tags, relations) is returned, attributes and proposals are omitted.
        :param uuid: Restrict the results by uuid.
        :param publish_timestamp: Restrict the results by the last publish timestamp (newer than).
        :param timestamp: Restrict the results by the timestamp (last edit). Any event with a timestamp newer than the given timestamp will be returned. In case you are dealing with /attributes as scope, the attribute's timestamp will be used for the lookup.
        :param published: Set whether published or unpublished events should be returned. Do not set the parameter if you want both.
        :param enforce_warninglist: Remove any attributes from the result that would cause a hit on a warninglist entry.
        :param to_ids: By default all attributes are returned that match the other filter parameters, irregardless of their to_ids setting. To restrict the returned data set to to_ids only attributes set this parameter to 1. 0 for the ones with to_ids set to False.
        :param deleted: If this parameter is set to 1, it will return soft-deleted attributes along with active ones. By using "only" as a parameter it will limit the returned data set to soft-deleted data only.
        :param include_event_uuid: Instead of just including the event ID, also include the event UUID in each of the attributes.
        :param event_timestamp: Only return attributes from events that have received a modification after the given timestamp.
        :param sg_reference_only: If this flag is set, sharing group objects will not be included, instead only the sharing group ID is set.
        :param eventinfo: Filter on the event's info field.
        :param searchall: Search for a full or a substring (delimited by % for substrings) in the event info, event tags, attribute tags, attribute values or attribute comment fields.
        :param requested_attributes: [CSV only] Select the fields that you wish to include in the CSV export. By setting event level fields additionally, includeContext is not required to get event metadata.
        :param include_context: [CSV Only] Include the event data with each attribute.
        :param headerless: [CSV Only] The CSV created when this setting is set to true will not contain the header row.
        :param pythonify: Returns a list of PyMISP Objects instead of the plain json output. Warning: it might use a lot of RAM

        Deprecated:

        :param quickFilter: synponym for quick_filter
        :param withAttachments: synonym for with_attachments
        :param last: synonym for publish_timestamp
        :param enforceWarninglist: synonym for enforce_warninglist
        :param includeEventUuid: synonym for include_event_uuid
        :param includeContext: synonym for include_context

        '''

        return_formats = ['openioc', 'json', 'xml', 'suricata', 'snort', 'text', 'rpz', 'csv', 'cache', 'stix', 'stix2']

        if controller not in ['events', 'attributes', 'objects', 'sightings']:
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
        if includeContext is not None:
            include_context = includeContext

        # Add all the parameters in kwargs are aimed at modules, or other 3rd party components, and cannot be sanitized.
        # They are passed as-is.
        query = kwargs

        if return_format not in return_formats:
            raise ValueError('return_format has to be in {}'.format(', '.join(return_formats)))
        query['returnFormat'] = return_format

        query['page'] = page
        query['limit'] = limit
        query['value'] = value
        query['type'] = type_attribute
        query['category'] = category
        query['org'] = org
        query['tags'] = tags
        query['quickFilter'] = quick_filter
        query['from'] = self._make_timestamp(date_from)
        query['to'] = self._make_timestamp(date_to)
        query['eventid'] = eventid
        query['withAttachments'] = with_attachments
        query['metadata'] = metadata
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
        query['enforceWarninglist'] = enforce_warninglist
        if to_ids is not None:
            if int(to_ids) not in [0, 1]:
                raise ValueError('to_ids has to be in {}'.format(', '.join([0, 1])))
            query['to_ids'] = to_ids
        query['deleted'] = deleted
        query['includeEventUuid'] = include_event_uuid
        if event_timestamp is not None:
            if isinstance(event_timestamp, (list, tuple)):
                query['event_timestamp'] = (self._make_timestamp(event_timestamp[0]), self._make_timestamp(event_timestamp[1]))
            else:
                query['event_timestamp'] = self._make_timestamp(event_timestamp)
        query['sgReferenceOnly'] = sg_reference_only
        query['eventinfo'] = eventinfo
        query['searchall'] = searchall
        query['requested_attributes'] = requested_attributes
        query['includeContext'] = include_context
        query['headerless'] = headerless
        url = urljoin(self.root_url, f'{controller}/restSearch')
        response = self._prepare_request('POST', url, data=query)
        if return_format == 'json':
            normalized_response = self._check_response(response, expect_json=True)
        else:
            normalized_response = self._check_response(response)

        if return_format == 'csv' and pythonify and not headerless:
            return self._csv_to_dict(normalized_response)
        elif 'errors' in normalized_response:
            return normalized_response
        elif return_format == 'json' and pythonify:
            # The response is in json, we can convert it to a list of pythonic MISP objects
            to_return = []
            if controller == 'events':
                for e in normalized_response:
                    me = MISPEvent()
                    me.load(e)
                    to_return.append(me)
            elif controller == 'attributes':
                for a in normalized_response.get('Attribute'):
                    ma = MISPAttribute()
                    ma.from_dict(**a)
                    to_return.append(ma)
            elif controller == 'objects':
                raise PyMISPNotImplementedYet('Not implemented yet')
            return to_return
        else:
            return normalized_response

    def search_index(self, published: Optional[bool]=None, eventid: Optional[SearchType]=None,
                     tags: Optional[SearchParameterTypes]=None,
                     date_from: Optional[DateTypes]=None,
                     date_to: Optional[DateTypes]=None,
                     eventinfo: Optional[str]=None,
                     threatlevel: Optional[List[SearchType]]=None,
                     distribution: Optional[List[SearchType]]=None,
                     analysis: Optional[List[SearchType]]=None,
                     org: Optional[SearchParameterTypes]=None,
                     timestamp: Optional[DateInterval]=None,
                     pythonify: Optional[bool]=None):
        """Search only at the index level. Using ! in front of a value means NOT (default is OR)

        :param published: Set whether published or unpublished events should be returned. Do not set the parameter if you want both.
        :param eventid: The events that should be included / excluded from the search
        :param tags: Tags to search or to exclude. You can pass a list, or the output of `build_complex_query`
        :param date_from: Events with the date set to a date after the one specified. This filter will use the date of the event.
        :param date_to: Events with the date set to a date before the one specified. This filter will use the date of the event.
        :param eventinfo: Filter on the event's info field.
        :param threatlevel: Threat level(s) (1,2,3,4) | list
        :param distribution: Distribution level(s) (0,1,2,3) | list
        :param analysis: Analysis level(s) (0,1,2) | list
        :param org: Search by the creator organisation by supplying the organisation identifier.
        :param timestamp: Restrict the results by the timestamp (last edit). Any event with a timestamp newer than the given timestamp will be returned. In case you are dealing with /attributes as scope, the attribute's timestamp will be used for the lookup.
        :param pythonify: Returns a list of PyMISP Objects instead or the plain json output. Warning: it might use a lot of RAM
        """
        query = locals()
        query.pop('self')
        query.pop('pythonify')
        if query.get('date_from'):
            query['datefrom'] = self._make_timestamp(query.pop('date_from'))
        if query.get('date_to'):
            query['dateuntil'] = self._make_timestamp(query.pop('date_to'))

        if query.get('timestamp') is not None:
            timestamp = query.pop('timestamp')
            if isinstance(timestamp, (list, tuple)):
                query['timestamp'] = (self._make_timestamp(timestamp[0]), self._make_timestamp(timestamp[1]))
            else:
                query['timestamp'] = self._make_timestamp(timestamp)

        url = urljoin(self.root_url, 'events/index')
        response = self._prepare_request('POST', url, data=query)
        normalized_response = self._check_response(response, expect_json=True)

        if not pythonify:
            return normalized_response
        to_return = []
        for e_meta in normalized_response:
            me = MISPEvent()
            me.from_dict(**e_meta)
            to_return.append(me)
        return to_return

    def search_sightings(self, context: Optional[str]=None,
                         context_id: Optional[SearchType]=None,
                         type_sighting: Optional[str]=None,
                         date_from: Optional[DateTypes]=None,
                         date_to: Optional[DateTypes]=None,
                         publish_timestamp: Optional[DateInterval]=None, last: Optional[DateInterval]=None,
                         org: Optional[SearchType]=None,
                         source: Optional[str]=None,
                         include_attribute: Optional[bool]=None,
                         include_event_meta: Optional[bool]=None,
                         pythonify: Optional[bool]=False
                         ):
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
        query = {'returnFormat': 'json'}
        if context is not None:
            if context not in ['attribute', 'event']:
                raise ValueError('context has to be in {}'.format(', '.join(['attribute', 'event'])))
            url_path = f'sightings/restSearch/{context}'
        else:
            url_path = 'sightings/restSearch'
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
        normalized_response = self._check_response(response, expect_json=True)
        if not pythonify or 'errors' in normalized_response:
            return normalized_response
        elif pythonify:
            to_return = []
            for s in normalized_response:
                entries = {}
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
        else:
            return normalized_response

    def search_logs(self, limit: Optional[int]=None, page: Optional[int]=None,
                    log_id: Optional[int]=None, title: Optional[str]=None,
                    created: Optional[DateTypes]=None, model: Optional[str]=None,
                    action: Optional[str]=None, user_id: Optional[int]=None,
                    change: Optional[str]=None, email: Optional[str]=None,
                    org: Optional[str]=None, description: Optional[str]=None,
                    ip: Optional[str]=None, pythonify: Optional[bool]=False):
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
        :param pythonify: Returns a list of PyMISP Objects instead or the plain json output. Warning: it might use a lot of RAM
        '''
        query = locals()
        query.pop('self')
        query.pop('pythonify')
        if log_id is not None:
            query['id'] = query.pop('log_id')

        response = self._prepare_request('POST', 'admin/logs/index', data=query)
        normalized_response = self._check_response(response, expect_json=True)
        if not pythonify or 'errors' in normalized_response:
            return normalized_response

        to_return = []
        for l in normalized_response:
            ml = MISPLog()
            ml.from_dict(**l)
            to_return.append(ml)
        return to_return

    # ## END Search methods ###

    # ## BEGIN Others ###

    def push_event_to_ZMQ(self, event: Union[MISPEvent, int, str, UUID]):
        """Force push an event on ZMQ"""
        event_id = self.__get_uuid_or_id_from_abstract_misp(event)
        response = self._prepare_request('POST', f'events/pushEventToZMQ/{event_id}.json')
        return self._check_response(response, expect_json=True)

    def direct_call(self, url: str, data: dict=None, params: dict={}):
        '''Very lightweight call that posts a data blob (python dictionary or json string) on the URL'''
        if data is None:
            response = self._prepare_request('GET', url, params=params)
        else:
            response = self._prepare_request('POST', url, data=data, params=params)
        return self._check_response(response, lenient_response_type=True)

    def freetext(self, event: Union[MISPEvent, int, str, UUID], string: str, adhereToWarninglists: Union[bool, str]=False,
                 distribution: int=None, returnMetaAttributes: bool=False, pythonify=False):
        """Pass a text to the freetext importer"""
        event_id = self.__get_uuid_or_id_from_abstract_misp(event)
        query = {"value": string}
        wl_params = [False, True, 'soft']
        if adhereToWarninglists in wl_params:
            query['adhereToWarninglists'] = adhereToWarninglists
        else:
            raise Exception('Invalid parameter, adhereToWarninglists Can only be {}'.format(', '.join(wl_params)))
        if distribution is not None:
            query['distribution'] = distribution
        if returnMetaAttributes:
            query['returnMetaAttributes'] = returnMetaAttributes
        attributes = self._prepare_request('POST', f'events/freeTextImport/{event_id}', data=query)
        attributes = self._check_response(attributes, expect_json=True)
        if returnMetaAttributes or not pythonify or 'errors' in attributes:
            return attributes
        to_return = []
        for attribute in attributes:
            a = MISPAttribute()
            a.from_dict(**attribute)
            to_return.append(a)
        return to_return

    def upload_stix(self, path, version: str='2'):
        """Upload a STIX file to MISP.
        :param path: Path to the STIX on the disk (can be a path-like object, or a pseudofile)
        :param version: Can be 1 or 2
        """
        if isinstance(path, (str, Path)):
            with open(path, 'rb') as f:
                to_post = f.read()
        else:
            to_post = path.read()

        if isinstance(to_post, bytes):
            to_post = to_post.decode()

        if str(version) == '1':
            url = urljoin(self.root_url, '/events/upload_stix')
            response = self._prepare_request('POST', url, data=to_post, output_type='xml')
        else:
            url = urljoin(self.root_url, '/events/upload_stix/2')
            response = self._prepare_request('POST', url, data=to_post)

        return response

    # ## END Others ###

    # ## BEGIN Statistics ###

    def attributes_statistics(self, context: str='type', percentage: bool=False):
        """Get attributes statistics from the MISP instance."""
        # FIXME: https://github.com/MISP/MISP/issues/4874
        if context not in ['type', 'category']:
            raise PyMISPError('context can only be "type" or "category"')
        if percentage:
            path = f'attributes/attributeStatistics/{context}/true'
        else:
            path = f'attributes/attributeStatistics/{context}'
        response = self._prepare_request('GET', path)
        return self._check_response(response, expect_json=True)

    def tags_statistics(self, percentage: bool=False, name_sort: bool=False):
        """Get tags statistics from the MISP instance"""
        # FIXME: https://github.com/MISP/MISP/issues/4874
        # NOTE: https://github.com/MISP/MISP/issues/4879
        if percentage:
            percentage = 'true'
        else:
            percentage = 'false'
        if name_sort:
            name_sort = 'true'
        else:
            name_sort = 'false'
        response = self._prepare_request('GET', f'tags/tagStatistics/{percentage}/{name_sort}')
        return self._check_response(response)

    def users_statistics(self, context: str='data'):
        """Get users statistics from the MISP instance"""
        # FIXME: https://github.com/MISP/MISP/issues/4874
        availables_contexts = ['data', 'orgs', 'users', 'tags', 'attributehistogram', 'sightings', 'galaxyMatrix']
        if context not in availables_contexts:
            raise PyMISPError("context can only be {','.join(availables_contexts)}")
        response = self._prepare_request('GET', f'users/statistics/{context}.json')
        return self._check_response(response)

    # ## END Statistics ###

    # ## BEGIN Global helpers ###

    def change_sharing_group_on_entity(self, misp_entity: AbstractMISP, sharing_group_id):
        """Change the sharing group of an event, an attribute, or an object"""
        misp_entity.distribution = 4      # Needs to be 'Sharing group'
        if 'SharingGroup' in misp_entity:  # Delete former SharingGroup information
            del misp_entity.SharingGroup
        misp_entity.sharing_group_id = sharing_group_id  # Set new sharing group id
        if isinstance(misp_entity, MISPEvent):
            return self.update_event(misp_entity)
        elif isinstance(misp_entity, MISPObject):
            return self.update_object(misp_entity)
        elif isinstance(misp_entity, MISPAttribute):
            return self.update_attribute(misp_entity)
        else:
            raise PyMISPError('The misp_entity must be MISPEvent, MISPObject or MISPAttribute')

    def tag(self, misp_entity: Union[AbstractMISP, str], tag: str):
        """Tag an event or an attribute. misp_entity can be a UUID"""
        if 'uuid' in misp_entity:
            uuid = misp_entity.uuid
        else:
            uuid = misp_entity
        to_post = {'uuid': uuid, 'tag': tag}
        response = self._prepare_request('POST', 'tags/attachTagToObject', data=to_post)
        return self._check_response(response, expect_json=True)

    def untag(self, misp_entity: Union[AbstractMISP, str], tag: str):
        """Untag an event or an attribute. misp_entity can be a UUID"""
        if 'uuid' in misp_entity:
            uuid = misp_entity.uuid
        else:
            uuid = misp_entity
        to_post = {'uuid': uuid, 'tag': tag}
        response = self._prepare_request('POST', 'tags/removeTagFromObject', data=to_post)
        return self._check_response(response, expect_json=True)

    def build_complex_query(self, or_parameters: Optional[List[SearchType]]=None,
                            and_parameters: Optional[List[SearchType]]=None,
                            not_parameters: Optional[List[SearchType]]=None):
        '''Build a complex search query. MISP expects a dictionary with AND, OR and NOT keys.'''
        to_return = {}
        if and_parameters:
            to_return['AND'] = and_parameters
        if not_parameters:
            to_return['NOT'] = not_parameters
        if or_parameters:
            to_return['OR'] = or_parameters
        return to_return

    # ## END Global helpers ###

    # ## Internal methods ###

    def __get_uuid_or_id_from_abstract_misp(self, obj: Union[AbstractMISP, int, str, UUID]):
        if isinstance(obj, UUID):
            return str(obj)
        if isinstance(obj, (int, str)):
            return obj
        elif 'id' in obj:
            return obj['id']
        return obj['uuid']

    def _make_timestamp(self, value: DateTypes):
        '''Catch-all method to normalize anything that can be converted to a timestamp'''
        if isinstance(value, datetime):
            return datetime.timestamp()
        elif isinstance(value, date):
            return datetime.combine(value, datetime.max.time()).timestamp()
        elif isinstance(value, str):
            if value.isdigit():
                return value
            else:
                try:
                    float(value)
                    return value
                except ValueError:
                    # The value can also be '1d', '10h', ...
                    return value
        else:
            return value

    def _check_response(self, response, lenient_response_type=False, expect_json=False):
        """Check if the response from the server is not an unexpected error"""
        if response.status_code >= 500:
            logger.critical(everything_broken.format(response.request.headers, response.request.body, response.text))
            raise MISPServerError(f'Error code 500:\n{response.text}')
        elif 400 <= response.status_code < 500:
            # The server returns a json message with the error details
            error_message = response.json()
            logger.error(f'Something went wrong ({response.status_code}): {error_message}')
            return {'errors': (response.status_code, error_message)}

        # At this point, we had no error.

        try:
            response = response.json()
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(response)
            if isinstance(response, dict) and response.get('response') is not None:
                # Cleanup.
                response = response['response']
            return response
        except Exception:
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(response.text)
            if expect_json:
                raise PyMISPUnexpectedResponse(f'Unexpected response from server: {response.text}')
            if lenient_response_type and not response.headers.get('content-type').startswith('application/json'):
                return response.text
            if not len(response.content):
                # Empty response
                logger.error('Got an empty response.')
                return {'errors': 'The response is empty.'}
            return response.text

    def __repr__(self):
        return f'<{self.__class__.__name__}(url={self.root_url})'

    def _prepare_request(self, request_type: str, url: str, data: dict={}, params: dict={}, output_type: str='json'):
        '''Prepare a request for python-requests'''
        url = urljoin(self.root_url, url)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f'{request_type} - {url}')
            if data is not None:
                logger.debug(data)
        if data:
            if not isinstance(data, str):  # Else, we already have a text blob to send
                if isinstance(data, dict):  # Else, we can directly json encode.
                    # Remove None values.
                    data = {k: v for k, v in data.items() if v is not None}
                data = json.dumps(data, cls=MISPEncode)

        req = requests.Request(request_type, url, data=data, params=params)
        with requests.Session() as s:
            user_agent = 'PyMISP {__version__} - Python {".".join(str(x) for x in sys.version_info[:2])}'
            if self.tool:
                user_agent = f'{user_agent} - {self.tool}'
            req.auth = self.auth
            prepped = s.prepare_request(req)
            prepped.headers.update(
                {'Authorization': self.key,
                 'Accept': f'application/{output_type}',
                 'content-type': f'application/{output_type}',
                 'User-Agent': user_agent})
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(prepped.headers)
            settings = s.merge_environment_settings(req.url, proxies=self.proxies or {}, stream=None, verify=self.ssl, cert=self.cert)
            return s.send(prepped, **settings)

    def _csv_to_dict(self, csv_content: str):
        '''Makes a list of dict out of a csv file (requires headers)'''
        fieldnames, lines = csv_content.split('\n', 1)
        fieldnames = fieldnames.split(',')
        to_return = []
        for line in csv.reader(lines.split('\n')):
            if line:
                to_return.append({fname: value for fname, value in zip(fieldnames, line)})
        return to_return
