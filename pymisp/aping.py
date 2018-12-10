#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .exceptions import MISPServerError, NewEventError, UpdateEventError, UpdateAttributeError, PyMISPNotImplementedYet
from .api import PyMISP, everything_broken
from .mispevent import MISPEvent, MISPAttribute, MISPSighting, MISPLog
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
        elif 'errors' in created_event:
            return created_event
        e = MISPEvent()
        e.load(created_event)
        return e

    def update_event(self, event: MISPEvent):
        updated_event = super().update_event(event.uuid, event)
        if isinstance(updated_event, str):
            raise UpdateEventError(f'Unexpected response from server: {updated_event}')
        elif 'errors' in updated_event:
            return updated_event
        e = MISPEvent()
        e.load(updated_event)
        return e

    def update_attribute(self, attribute: MISPAttribute):
        updated_attribute = super().update_attribute(attribute.uuid, attribute)
        if isinstance(updated_attribute, str):
            raise UpdateAttributeError(f'Unexpected response from server: {updated_attribute}')
        elif 'errors' in updated_attribute:
            return updated_attribute
        a = MISPAttribute()
        a.from_dict(**updated_attribute)
        return a

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
        # Remove None values.
        # TODO: put that in self._prepare_request
        query = {k: v for k, v in query.items() if v is not None}
        response = self._prepare_request('POST', url, data=json.dumps(query))
        normalized_response = self._check_response(response)
        if isinstance(normalized_response, str) or (isinstance(normalized_response, dict) and
                                                    normalized_response.get('errors')):
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
               to_ids: Optional[str]=None,
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
        :param to_ids: By default (0) all attributes are returned that match the other filter parameters, irregardless of their to_ids setting. To restrict the returned data set to to_ids only attributes set this parameter to 1. You can only use the special "exclude" setting to only return attributes that have the to_ids flag disabled.
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

        return_formats = ['openioc', 'json', 'xml', 'suricata', 'snort', 'text', 'rpz', 'csv', 'cache']

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
        query['from'] = self.make_timestamp(date_from)
        query['to'] = self.make_timestamp(date_to)
        query['eventid'] = eventid
        query['withAttachments'] = with_attachments
        query['metadata'] = metadata
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
        query['published'] = published
        query['enforceWarninglist'] = enforce_warninglist
        if to_ids is not None:
            if str(to_ids) not in ['0', '1', 'exclude']:
                raise ValueError('to_ids has to be in {}'.format(', '.join(['0', '1', 'exclude'])))
            query['to_ids'] = to_ids
        query['deleted'] = deleted
        query['includeEventUuid'] = include_event_uuid
        if event_timestamp is not None:
            if isinstance(event_timestamp, (list, tuple)):
                query['event_timestamp'] = (self.make_timestamp(event_timestamp[0]), self.make_timestamp(event_timestamp[1]))
            else:
                query['event_timestamp'] = self.make_timestamp(event_timestamp)
        query['sgReferenceOnly'] = sg_reference_only
        query['eventinfo'] = eventinfo
        query['searchall'] = searchall
        query['requested_attributes'] = requested_attributes
        query['includeContext'] = include_context
        query['headerless'] = headerless
        url = urljoin(self.root_url, f'{controller}/restSearch')
        # Remove None values.
        # TODO: put that in self._prepare_request
        query = {k: v for k, v in query.items() if v is not None}
        response = self._prepare_request('POST', url, data=json.dumps(query))
        normalized_response = self._check_response(response)
        if return_format == 'csv' and pythonify and not headerless:
            return self._csv_to_dict(normalized_response)
        elif isinstance(normalized_response, str) or (isinstance(normalized_response, dict) and
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

    def _csv_to_dict(self, csv_content):
        '''Makes a list of dict out of a csv file (requires headers)'''
        fieldnames, lines = csv_content.split('\n', 1)
        fieldnames = fieldnames.split(',')
        to_return = []
        for line in csv.reader(lines.split('\n')):
            if line:
                to_return.append({fname: value for fname, value in zip(fieldnames, line)})
        return to_return

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

        url = urljoin(self.root_url, 'admin/logs/index')
        # Remove None values.
        # TODO: put that in self._prepare_request
        query = {k: v for k, v in query.items() if v is not None}
        response = self._prepare_request('POST', url, data=json.dumps(query))
        normalized_response = self._check_response(response)
        if not pythonify:
            return normalized_response

        to_return = []
        for l in normalized_response:
            ml = MISPLog()
            ml.from_dict(**l['Log'])
            to_return.append(ml)
        return to_return

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
            query['datefrom'] = self.make_timestamp(query.pop('date_from'))
        if query.get('date_to'):
            query['dateuntil'] = self.make_timestamp(query.pop('date_to'))

        if query.get('timestamp') is not None:
            timestamp = query.pop('timestamp')
            if isinstance(timestamp, (list, tuple)):
                query['timestamp'] = (self.make_timestamp(timestamp[0]), self.make_timestamp(timestamp[1]))
            else:
                query['timestamp'] = self.make_timestamp(timestamp)

        url = urljoin(self.root_url, 'events/index')
        # Remove None values.
        # TODO: put that in self._prepare_request
        query = {k: v for k, v in query.items() if v is not None}
        response = self._prepare_request('POST', url, data=json.dumps(query))
        normalized_response = self._check_response(response)

        if not pythonify:
            return normalized_response
        to_return = []
        for e_meta in normalized_response:
            me = MISPEvent()
            me.from_dict(**e_meta)
            to_return.append(me)
        return to_return
