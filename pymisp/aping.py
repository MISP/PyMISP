#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .exceptions import MISPServerError, NewEventError, UpdateEventError, UpdateAttributeError
from .api import PyMISP, everything_broken, MISPEvent, MISPAttribute
from typing import TypeVar, Optional, Tuple, List, Dict
from datetime import date, datetime
import json

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
            if response.get('response') is not None:
                # Cleanup.
                return response.get('response')
            return response
        except Exception:
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(response.text)
            return response.text

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
               eventinfo: Optional[str]=None,
               type_attribute: Optional[SearchParameterTypes]=None,
               category: Optional[SearchParameterTypes]=None,
               org: Optional[SearchParameterTypes]=None,
               tags: Optional[SearchParameterTypes]=None,
               date_from: Optional[DateTypes]=None, date_to: Optional[DateTypes]=None,
               eventid: Optional[SearchType]=None,
               with_attachment: Optional[bool]=None,
               metadata: Optional[bool]=None,
               uuid: Optional[str]=None,
               published: Optional[bool]=None,
               searchall: Optional[bool]=None,
               enforce_warninglist: Optional[bool]=None, enforceWarninglist: Optional[bool]=None,
               sg_reference_only: Optional[bool]=None,
               publish_timestamp: Optional[DateInterval]=None,
               timestamp: Optional[DateInterval]=None,
               **kwargs):

        if controller not in ['events', 'attributes', 'objects']:
            raise ValueError('controller has to be in {}'.format(', '.join(['events', 'attributes', 'objects'])))

        # Add all the parameters in kwargs are aimed at modules, or other 3rd party components, and cannot be sanitized.
        # They are passed as-is.
        query = kwargs
        if return_format is not None:
            query['returnFormat'] = return_format
        if value is not None:
            query['value'] = value
        if eventinfo is not None:
            query['eventinfo'] = eventinfo
        if type_attribute is not None:
            query['type'] = type_attribute
        if category is not None:
            query['category'] = category
        if org is not None:
            query['org'] = org
        if tags is not None:
            query['tags'] = tags
        if date_from is not None:
            query['from'] = self.make_timestamp(date_from)
        if date_to is not None:
            query['to'] = self.make_timestamp(date_to)
        if eventid is not None:
            query['eventid'] = eventid
        if with_attachment is not None:
            query['withAttachments'] = with_attachment
        if metadata is not None:
            query['metadata'] = metadata
        if uuid is not None:
            query['uuid'] = uuid
        if published is not None:
            query['published'] = published
        if enforce_warninglist is not None:
            query['enforceWarninglist'] = enforce_warninglist
        if enforceWarninglist is not None:
            # Alias for enforce_warninglist
            query['enforceWarninglist'] = enforceWarninglist
        if sg_reference_only is not None:
            query['sgReferenceOnly'] = sg_reference_only
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

        url = urljoin(self.root_url, f'{controller}/restSearch')
        response = self._prepare_request('POST', url, data=json.dumps(query))
        normalized_response = self._check_response(response)
        if isinstance(normalized_response, str) or (isinstance(normalized_response, dict) and
                                                    normalized_response.get('errors')):
            return normalized_response
        # The response is in json, we can confert it to a list of pythonic MISP objects
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
            raise Exception('Not implemented yet')
        return to_return
