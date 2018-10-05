#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .exceptions import MISPServerError, NewEventError, UpdateEventError, UpdateAttributeError, PyMISPNotImplementedYet, PyMISPUnexpectedResponse
from .api import PyMISP, everything_broken, MISPEvent, MISPAttribute
from typing import TypeVar, Optional, Tuple, List, Dict
from datetime import date, datetime
import json
import csv

import logging
from urllib.parse import urljoin

SearchType = TypeVar('SearchType', str, int)
# str: string to search / list: values to search (OR) / dict: {'OR': [list], 'NOT': [list], 'AND': [list]}
SearchParameterTypes = TypeVar('SearchParameterTypes', str, List[SearchType], Dict[str, SearchType])
DateTypes = TypeVar('DateTypes', datetime, date, SearchType, float)
DateInterval = TypeVar('DateInterval', DateTypes, Tuple[DateTypes, DateTypes])


logger = logging.getLogger('pymisp')


class ExpandedPyMISP(PyMISP):

    def build_complex_query(self, or_parameters: Optional[List[SearchType]]=None,
                            and_parameters: Optional[List[SearchType]]=None,
                            not_parameters: Optional[List[SearchType]]=None):
        to_return = {}
        if and_parameters:
            to_return['AND'] = and_parameters
        if not_parameters:
            to_return['NOT'] = not_parameters
        if or_parameters:
            to_return['OR'] = or_parameters
        return to_return

    def toggle_warninglist(self, warninglist_id: List[int]=None, warninglist_name: List[str]=None, force_enable: bool=None):
        '''Toggle (enable/disable) the status of a warninglist by ID.
        :param warninglist_id: ID of the WarningList
        :param force_enable: Force the warning list in the enabled state (does nothing is already enabled)
        '''
        return super().toggle_warninglist(warninglist_id, warninglist_name, force_enable)

    def make_timestamp(self, value: DateTypes):
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

    def _check_response(self, response):
        """Check if the response from the server is not an unexpected error"""
        if response.status_code >= 500:
            logger.critical(everything_broken.format(response.request.headers, response.request.body, response.text))
            raise MISPServerError('Error code 500:\n{}'.format(response.text))
        elif 400 <= response.status_code < 500:
            # The server returns a json message with the error details
            error_message = response.json()
            logger.error(f'Something went wrong ({response.status_code}): {error_message}')
            return {'errors': [(response.status_code, error_message)]}

        # At this point, we had no error.

        try:
            response = response.json()
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(response)
            if isinstance(response, dict) and response.get('response') is not None:
                # Cleanup.
                return response.get('response')
            return response
        except Exception:
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(response.text)
            return response.text

    def get_event(self, event_id: int):
        event = super().get_event(event_id)
        e = MISPEvent()
        e.load(event)
        return e

    def add_event(self, event: MISPEvent):
        created_event = super().add_event(event)
        if isinstance(created_event, str):
            raise NewEventError(f'Unexpected response from server: {created_event}')
        e = MISPEvent()
        e.load(created_event)
        return e

    def update_event(self, event: MISPEvent):
        updated_event = super().update_event(event.uuid, event)
        if isinstance(updated_event, str):
            raise UpdateEventError(f'Unexpected response from server: {updated_event}')
        e = MISPEvent()
        e.load(updated_event)
        return e

    def update_attribute(self, attribute: MISPAttribute):
        updated_attribute = super().update_attribute(attribute.uuid, attribute)
        if isinstance(updated_attribute, str):
            raise UpdateAttributeError(f'Unexpected response from server: {updated_attribute}')
        a = MISPAttribute()
        a.from_dict(**updated_attribute)
        return a

    # TODO: Make that thing async & test it.
    def search(self, controller: str='events', return_format: str='json',
               value: Optional[SearchParameterTypes]=None,
               type_attribute: Optional[SearchParameterTypes]=None,
               category: Optional[SearchParameterTypes]=None,
               org: Optional[SearchParameterTypes]=None,
               tags: Optional[SearchParameterTypes]=None,
               quickfilter: Optional[bool]=None,
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
               to_ids: Optional[str]=None,
               deleted: Optional[str]=None,
               include_event_uuid: Optional[str]=None, includeEventUuid: Optional[str]=None,
               event_timestamp: Optional[DateTypes]=None,
               sg_reference_only: Optional[bool]=None,
               eventinfo: Optional[str]=None,
               searchall: Optional[bool]=None,
               pythonify: Optional[bool]=False,
               **kwargs):
        '''
        Search in the MISP instance

        :param returnFormat: Set the return format of the search (Currently supported: json, xml, openioc, suricata, snort - more formats are being moved to restSearch with the goal being that all searches happen through this API). Can be passed as the first parameter after restSearch or via the JSON payload.
        :param value: Search for the given value in the attributes' value field.
        :param type_attribute: The attribute type, any valid MISP attribute type is accepted.
        :param category: The attribute category, any valid MISP attribute category is accepted.
        :param org: Search by the creator organisation by supplying the organisation identifier.
        :param tags: Tags to search or to exclude. You can pass a list, or the output of `build_complex_query`
        :param quickfilter: If set it makes the search ignore all of the other arguments, except for the auth key and value. MISP will return all events that have a sub-string match on value in the event info, event orgc, or any of the attribute value fields, or in the attribute comment.
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
        :param to_ids: By default (0) all attributes are returned that match the other filter parameters, irregardless of their to_ids setting. To restrict the returned data set to to_ids only attributes set this parameter to 1. You can only use the special "exclude" setting to only return attributes that have the to_ids flag disabled.
        :param deleted: If this parameter is set to 1, it will return soft-deleted attributes along with active ones. By using "only" as a parameter it will limit the returned data set to soft-deleted data only.
        :param include_event_uuid: Instead of just including the event ID, also include the event UUID in each of the attributes.
        :param event_timestamp: Only return attributes from events that have received a modification after the given timestamp.
        :param sg_reference_only: If this flag is set, sharing group objects will not be included, instead only the sharing group ID is set.
        :param eventinfo: Filter on the event's info field.
        :param searchall: Search for a full or a substring (delimited by % for substrings) in the event info, event tags, attribute tags, attribute values or attribute comment fields.
        :param pythonify: Returns a list of PyMISP Objects the the plain json output. Warning: it might use a lot of RAM

        Deprecated:

        :param withAttachments: synonym for with_attachments
        :param last: synonym for publish_timestamp
        :param enforceWarninglist: synonym for enforce_warninglist
        :param includeEventUuid: synonym for include_event_uuid

        '''

        if controller not in ['events', 'attributes', 'objects']:
            raise ValueError('controller has to be in {}'.format(', '.join(['events', 'attributes', 'objects'])))

        # Deprecated stuff / synonyms
        if withAttachments is not None:
            with_attachments = withAttachments
        if last is not None:
            publish_timestamp = last
        if enforceWarninglist is not None:
            enforce_warninglist = enforceWarninglist
        if includeEventUuid is not None:
            include_event_uuid = includeEventUuid

        # Add all the parameters in kwargs are aimed at modules, or other 3rd party components, and cannot be sanitized.
        # They are passed as-is.
        query = kwargs
        if return_format is not None:
            if return_format not in ['json', 'xml', 'openioc', 'suricata', 'snort']:
                raise ValueError('return_format has to be in {}'.format(', '.join(['json', 'xml', 'openioc', 'suricata', 'snort'])))
            query['returnFormat'] = return_format
        if value is not None:
            query['value'] = value
        if type_attribute is not None:
            query['type'] = type_attribute
        if category is not None:
            query['category'] = category
        if org is not None:
            query['org'] = org
        if tags is not None:
            query['tags'] = tags
        if quickfilter is not None:
            query['quickfilter'] = quickfilter
        if date_from is not None:
            query['from'] = self.make_timestamp(date_from)
        if date_to is not None:
            query['to'] = self.make_timestamp(date_to)
        if eventid is not None:
            query['eventid'] = eventid
        if with_attachments is not None:
            query['withAttachments'] = with_attachments
        if metadata is not None:
            query['metadata'] = metadata
        if uuid is not None:
            query['uuid'] = uuid
        if publish_timestamp is not None:
            if isinstance(publish_timestamp, (list, tuple)):
                query['publish_timestamp'] = (self.make_timestamp(publish_timestamp[0]), self.make_timestamp(publish_timestamp[1]))
            else:
                query['publish_timestamp'] = self.make_timestamp(publish_timestamp)
        if timestamp is not None:
            if isinstance(timestamp, (list, tuple)):
                query['timestamp'] = (self.make_timestamp(timestamp[0]), self.make_timestamp(timestamp[1]))
            else:
                query['timestamp'] = self.make_timestamp(timestamp)
        if published is not None:
            query['published'] = published
        if enforce_warninglist is not None:
            query['enforceWarninglist'] = enforce_warninglist
        if to_ids is not None:
            if str(to_ids) not in ['0', '1', 'exclude']:
                raise ValueError('to_ids has to be in {}'.format(', '.join(['0', '1', 'exclude'])))
            query['to_ids'] = to_ids
        if deleted is not None:
            query['deleted'] = deleted
        if include_event_uuid is not None:
            query['includeEventUuid'] = include_event_uuid
        if event_timestamp is not None:
            if isinstance(event_timestamp, (list, tuple)):
                query['event_timestamp'] = (self.make_timestamp(event_timestamp[0]), self.make_timestamp(event_timestamp[1]))
            else:
                query['event_timestamp'] = self.make_timestamp(event_timestamp)
        if sg_reference_only is not None:
            query['sgReferenceOnly'] = sg_reference_only
        if eventinfo is not None:
            query['eventinfo'] = eventinfo
        if searchall is not None:
            query['searchall'] = searchall

        url = urljoin(self.root_url, f'{controller}/restSearch')
        response = self._prepare_request('POST', url, data=json.dumps(query))
        normalized_response = self._check_response(response)
        if isinstance(normalized_response, str) or (isinstance(normalized_response, dict) and
                                                    normalized_response.get('errors')):
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

    def get_csv(self,
                eventid: Optional[SearchType]=None,
                ignore: Optional[bool]=None,
                tags: Optional[SearchParameterTypes]=None,
                category: Optional[SearchParameterTypes]=None,
                type_attribute: Optional[SearchParameterTypes]=None,
                include_context: Optional[bool]=None, includeContext: Optional[bool]=None,
                date_from: Optional[DateTypes]=None, date_to: Optional[DateTypes]=None,
                publish_timestamp: Optional[DateInterval]=None,  # converted internally to last (consistent with search)
                headerless: Optional[bool]=None,
                enforce_warninglist: Optional[bool]=None, enforceWarninglist: Optional[bool]=None,
                pythonify: Optional[bool]=False,
                **kwargs):
        '''
        Get MISP data in CSV format.

        :param eventid: Restrict the download to a single event
        :param ignore: If true, the response includes attributes without the to_ids flag
        :param tags: Tags to search or to exclude. You can pass a list, or the output of `build_complex_query`
        :param category: The attribute category, any valid MISP attribute category is accepted.
        :param type_attribute: The attribute type, any valid MISP attribute type is accepted.
        :param include_context: Include the event data with each attribute.
        :param date_from: Events with the date set to a date after the one specified. This filter will use the date of the event.
        :param date_to: Events with the date set to a date before the one specified. This filter will use the date of the event.
        :param publish_timestamp: Events published within the last x amount of time. This filter will use the published timestamp of the event.
        :param headerless: The CSV created when this setting is set to true will not contain the header row.
        :param enforceWarninglist: All attributes that have a hit on a warninglist will be excluded.
        :param pythonify: Returns a list of dictionaries instead of the plain CSV
        '''

        # Deprecated stuff / synonyms
        if includeContext is not None:
            include_context = includeContext
        if enforceWarninglist is not None:
            enforce_warninglist = enforceWarninglist

        # Add all the parameters in kwargs are aimed at modules, or other 3rd party components, and cannot be sanitized.
        # They are passed as-is.
        query = kwargs
        if eventid is not None:
            query['eventid'] = eventid
        if ignore is not None:
            query['ignore'] = ignore
        if tags is not None:
            query['tags'] = tags
        if category is not None:
            query['category'] = category
        if type_attribute is not None:
            query['type'] = type_attribute
        if include_context is not None:
            query['includeContext'] = include_context
        if date_from is not None:
            query['from'] = self.make_timestamp(date_from)
        if date_to is not None:
            query['to'] = self.make_timestamp(date_to)
        if publish_timestamp is not None:
            if isinstance(publish_timestamp, (list, tuple)):
                query['last'] = (self.make_timestamp(publish_timestamp[0]), self.make_timestamp(publish_timestamp[1]))
            else:
                query['last'] = self.make_timestamp(publish_timestamp)
        if headerless is not None:
            query['headerless'] = headerless
        if enforce_warninglist is not None:
            query['enforceWarninglist'] = enforce_warninglist

        url = urljoin(self.root_url, '/events/csv/download/')
        response = self._prepare_request('POST', url, data=json.dumps(query))
        normalized_response = self._check_response(response)
        if isinstance(normalized_response, str):
            if pythonify and not headerless:
                # Make it a list of dict
                fieldnames, lines = normalized_response.split('\n', 1)
                fieldnames = fieldnames.split(',')
                to_return = []
                for line in csv.reader(lines.split('\n')):
                    if line:
                        to_return.append({fname: value for fname, value in zip(fieldnames, line)})
                return to_return

            return normalized_response
        elif isinstance(normalized_response, dict):
            # The server returned a dictionary, it contains the error message.
            logger.critical(f'The server should have returned a CSV file as text. instead it returned an error message:\n{normalized_response}')
            return normalized_response
        else:
            # Should not happen...
            raise PyMISPUnexpectedResponse(f'The server should have returned a CSV file as text. instead it returned:\n{normalized_response}')
