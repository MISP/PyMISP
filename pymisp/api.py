#!/usr/bin/env python
# -*- coding: utf-8 -*-


""" Python API for MISP """

import requests

from apikey import key

URL = 'https://misp.circl.lu/events'
URL_TMPL = URL + '/{}'
URL_XML_DOWNLOAD = URL + '/xml/download'
URL_XML_DOWNLOAD_TMPL = URL_XML_DOWNLOAD + '/{}'

OUTPUT_TYPE = 'json'

def __prepare_session(output_type=OUTPUT_TYPE):
    """
        Prepare the headers of the session
    """
    session = requests.Session()
    session.headers.update({'Authorization': key,
        'Accept': 'application/' + output_type})
    return session

################ REST API ################

# supports JSON and XML output

def get_index():
    """
        Return the index.

        Warning, there's a limit on the number of results
    """
    session = __prepare_session()
    return session.get(URL, verify=False)

def get_event(event_id):
    """
        Get an event
    """
    session = __prepare_session()
    return session.get(URL_TMPL.format(event_id), verify=False)

def add_event(event):
    """
        Add a new event
    """
    session = __prepare_session()
    return session.post(URL, data=event, verify=False)

def update_event(event_id, event):
    """
        Update an event
    """
    session = __prepare_session()
    return session.post(URL_TMPL.format(event_id), data=event, verify=False)

def delete_event(event_id):
    """
        Delete an event
    """
    session = __prepare_session()
    return session.delete(URL_TMPL.format(event_id), verify=False)

##########################################

############### XML Export ###############

# Only XML,


def download_all():
    """
        Download all event from the instance
    """
    session = __prepare_session('xml')
    return session.get(URL_XML_DOWNLOAD, verify=False)

def download(event_id):
    """
        Download one event in XML
    """
    session = __prepare_session('xml')
    return session.get(URL_XML_DOWNLOAD_TMPL.format(event_id), verify=False)

######### REST Search #########

def __prepare_rest_search(values, not_values):
    """
        Prepare a search
    """
    to_return = ''
    if values is not None:
        if type(values) != type([]):
            to_return += values
        else:
            to_return += '&&'.join(values)
    if not_values is not None:
        if len(to_return) > 0 :
            to_return += '&&!'
        else:
            to_return += '!'
        if type(values) != type([]):
            to_return += not_values
        else:
            to_return += '&&!'.join(not_values)
    return to_return

URL_SEARCH_TMPL = 'https://misp.circl.lu/events/restSearch/download/{}/{}/{}/{}/{}'


# NOTE: searching by tags works, not the other options
def search(values=None, not_values=None, type_attribute=None,
        category=None, org=None, tags=None, not_tags=None):
    v = __prepare_rest_search(values, not_values).replace('/', '|')
    t = __prepare_rest_search(tags, not_tags).replace(':', ';')
    if len(v) == 0:
        v = 'null'
    if len(t) == 0:
        t = 'null'
    if type_attribute is None:
        type_attribute = 'null'
    if category is None:
        category = 'null'
    if org is None:
        org = 'null'

    session = __prepare_session('xml')
    return session.get(URL_SEARCH_TMPL.format(v, type_attribute,
        category, org, t), verify=False)

##########################################

if __name__ == '__main__':
    r = search(values='77.67.80.31', tags='OSINT')
    print unicode(r.text)
    #r = get_index()
    #print r.text
