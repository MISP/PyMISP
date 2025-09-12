#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Koen Van Impe

Cytomic Automation
Put this script in crontab to run every /15 or /60
    */15 *    * * *   mispuser   /usr/bin/python3 /home/mispuser/PyMISP/examples/cytomic_orion.py


Fetches the configuration set in the Cytomic Orion enrichment module
- events : upload events tagged with the 'upload' tag, all the attributes supported by Cytomic Orion
- upload : upload attributes flagged with the 'upload' tag (only attributes supported by Cytomic Orion)
- delete : delete attributes flagged with the 'upload' tag (only attributes supported by Cytomic Orion)

'''

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse
import os
import re
import sys
import requests
import json
import urllib3


def get_token(token_url, clientid, clientsecret, scope, grant_type, username, password):
    '''
    Get oAuth2 token
    Configuration settings are fetched first from the MISP module configu
    '''

    try:
        if scope and grant_type and username and password:
            data = {'scope': scope, 'grant_type': grant_type, 'username': username, 'password': password}

            if token_url and clientid and clientsecret:
                access_token_response = requests.post(token_url, data=data, verify=False, allow_redirects=False, auth=(clientid, clientsecret))
                tokens = json.loads(access_token_response.text)
                if 'access_token' in tokens:
                    access_token = tokens['access_token']
                    return access_token
                else:
                    sys.exit('No token received')
            else:
                sys.exit('No token_url, clientid or clientsecret supplied')
        else:
            sys.exit('No scope, grant_type, username or password supplied')
    except Exception:
        sys.exit('Unable to connect to token_url')


def get_config(url, key, misp_verifycert):
    '''
    Get the module config and the settings needed to access the API
    Also contains the settings to do the query
    '''
    try:
        misp_headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': key}
        req = requests.get(url + 'servers/serverSettings.json', verify=misp_verifycert, headers=misp_headers)
        if req.status_code == 200:
            req_json = req.json()
            if 'finalSettings' in req_json:
                finalSettings = req_json['finalSettings']

                clientid = clientsecret = scope = username = password = grant_type = api_url = token_url = ''
                module_enabled = False
                scope = 'orion.api'
                grant_type = 'password'
                limit_upload_events = 50
                limit_upload_attributes = 50
                ttlDays = "1"
                last_attributes = '5d'
                post_threat_level_id = 2
                for el in finalSettings:
                    # Is the module enabled?
                    if el['setting'] == 'Plugin.Enrichment_cytomic_orion_enabled':
                        module_enabled = el['value']
                        if module_enabled is False:
                            break
                    elif el['setting'] == 'Plugin.Enrichment_cytomic_orion_clientid':
                        clientid = el['value']
                    elif el['setting'] == 'Plugin.Enrichment_cytomic_orion_clientsecret':
                        clientsecret = el['value']
                    elif el['setting'] == 'Plugin.Enrichment_cytomic_orion_username':
                        username = el['value']
                    elif el['setting'] == 'Plugin.Enrichment_cytomic_orion_password':
                        password = el['value']
                    elif el['setting'] == 'Plugin.Enrichment_cytomic_orion_api_url':
                        api_url = el['value'].replace('\\/', '/')
                    elif el['setting'] == 'Plugin.Enrichment_cytomic_orion_token_url':
                        token_url = el['value'].replace('\\/', '/')
                    elif el['setting'] == 'MISP.baseurl':
                        misp_baseurl = el['value']
                    elif el['setting'] == 'Plugin.Enrichment_cytomic_orion_upload_threat_level_id':
                        if el['value']:
                            try:
                                post_threat_level_id = int(el['value'])
                            except:
                                continue
                    elif el['setting'] == 'Plugin.Enrichment_cytomic_orion_upload_ttlDays':
                        if el['value']:
                            try:
                                ttlDays = "{last_days}".format(last_days=int(el['value']))
                            except:
                                continue
                    elif el['setting'] == 'Plugin.Enrichment_cytomic_orion_upload_timeframe':
                        if el['value']:
                            try:
                                last_attributes = "{last_days}d".format(last_days=int(el['value']))
                            except:
                                continue
                    elif el['setting'] == 'Plugin.Enrichment_cytomic_orion_upload_tag':
                        upload_tag = el['value']
                    elif el['setting'] == 'Plugin.Enrichment_cytomic_orion_delete_tag':
                        delete_tag = el['value']
                    elif el['setting'] == 'Plugin.Enrichment_limit_upload_events':
                        if el['value']:
                            try:
                                limit_upload_events = "{limit_upload_events}".format(limit_upload_events=int(el['value']))
                            except:
                                continue
                    elif el['setting'] == 'Plugin.Enrichment_limit_upload_attributes':
                        if el['value']:
                            try:
                                limit_upload_attributes = "{limit_upload_attributes}".format(limit_upload_attributes=int(el['value']))
                            except:
                                continue
        else:
            sys.exit('Did not receive a 200 code from MISP')

        if module_enabled and api_url and token_url and clientid and clientsecret and username and password and grant_type:

            return {'cytomic_policy': 'Detect',
                    'upload_timeframe': last_attributes,
                    'upload_tag': upload_tag,
                    'delete_tag': delete_tag,
                    'upload_ttlDays': ttlDays,
                    'post_threat_level_id': post_threat_level_id,
                    'clientid': clientid,
                    'clientsecret': clientsecret,
                    'scope': scope,
                    'username': username,
                    'password': password,
                    'grant_type': grant_type,
                    'api_url': api_url,
                    'token_url': token_url,
                    'misp_baseurl': misp_baseurl,
                    'limit_upload_events': limit_upload_events,
                    'limit_upload_attributes': limit_upload_attributes}
        else:
            sys.exit('Did not receive all the necessary configuration information from MISP')

    except Exception as e:
        sys.exit('Unable to get module config from MISP')


class cytomicobject:
    misp = None
    lst_evtid = None
    lst_attuuid = None
    lst_attuuid_error = None
    endpoint_ioc = None
    api_call_headers = None
    post_data = None
    args = None
    tag = None
    limit_events = None
    limit_attributes = None
    atttype_misp = None
    atttype_cytomic = None
    attlabel_cytomic = None
    att_types = {
       "ip-dst": {"ip": "ipioc"},
       "ip-src": {"ip": "ipioc"},
       "url": {"url": "urlioc"},
       "md5": {"hash": "filehashioc"},
       "domain": {"domain": "domainioc"},
       "hostname": {"domain": "domainioc"},
       "domain|ip": {"domain": "domainioc"},
       "hostname|port": {"domain": "domainioc"}
    }
    debug = True
    error = False
    res = False
    res_msg = None


def collect_events_ids(cytomicobj, moduleconfig):
    # Get events that contain Cytomic tag.
    try:
        evt_result = cytomicobj.misp.search(controller='events', limit=cytomicobj.limit_events, tags=cytomicobj.tag, last=moduleconfig['upload_timeframe'], published=True, deleted=False, pythonify=True)
        cytomicobj.lst_evtid = ['x', 'y']
        for evt in evt_result:
            evt = cytomicobj.misp.get_event(event=evt['id'], pythonify=True)
            if len(evt.tags) > 0:
                for tg in evt.tags:
                    if tg.name == cytomicobj.tag:
                        if not cytomicobj.lst_evtid:
                            cytomicobj.lst_evtid = str(evt['id'])
                        else:
                            if not evt['id'] in cytomicobj.lst_evtid:
                                cytomicobj.lst_evtid.append(str(evt['id']))
                        break
        cytomicobj.lst_evtid.remove('x')
        cytomicobj.lst_evtid.remove('y')
    except Exception:
        cytomicobj.error = True
        if cytomicobj.debug:
            sys.exit('Unable to collect events ids')


def find_eventid(cytomicobj, evtid):
    # Get events that contain Cytomic tag.
    try:
        cytomicobj.res = False
        for id in cytomicobj.lst_evtid:
            if id == evtid:
                cytomicobj.res = True
                break
    except Exception:
        cytomicobj.error = True
        if cytomicobj.debug:
            sys.exit('Unable to collect events ids')


def print_result_events(cytomicobj):
    try:
        if cytomicobj.res_msg is not None:
            for key, msg in cytomicobj.res_msg.items():
                if msg is not None:
                    print(key, msg)
    except Exception:
        cytomicobj.error = True
        if cytomicobj.debug:
            sys.exit('Unable to print result')


def set_postdata(cytomicobj, moduleconfig, attribute):
    # Set JSON to send to the API.
    try:

        if cytomicobj.args.upload or cytomicobj.args.events:
            event = attribute['Event']
            event_title = event['info']
            event_id = event['id']
            threat_level_id = int(event['threat_level_id'])
            if moduleconfig['post_threat_level_id'] <= threat_level_id:

                if cytomicobj.atttype_misp == 'domain|ip' or cytomicobj.atttype_misp == 'hostname|port':
                    post_value = attribute['value'].split('|')[0]
                else:
                    post_value = attribute['value']

                if cytomicobj.atttype_misp == 'url' and 'http' not in post_value:
                    pass
                else:
                    if cytomicobj.post_data is None:
                        cytomicobj.post_data = [{cytomicobj.attlabel_cytomic: post_value, 'AdditionalData': '{} {}'.format(cytomicobj.atttype_misp, attribute['comment']).strip(), 'Source': 'Uploaded from MISP', 'Policy': moduleconfig['cytomic_policy'], 'Description': '{} - {}'.format(event_id, event_title).strip()}]
                    else:
                        if post_value not in str(cytomicobj.post_data):
                            cytomicobj.post_data.append({cytomicobj.attlabel_cytomic: post_value, 'AdditionalData': '{} {}'.format(cytomicobj.atttype_misp, attribute['comment']).strip(), 'Source': 'Uploaded from MISP', 'Policy': moduleconfig['cytomic_policy'], 'Description': '{} - {}'.format(event_id, event_title).strip()})
            else:
                if cytomicobject.debug:
                    print('Event %s skipped because of lower threat level' % event_id)
        else:
            event = attribute['Event']
            threat_level_id = int(event['threat_level_id'])
            if moduleconfig['post_threat_level_id'] <= threat_level_id:
                if cytomicobj.atttype_misp == 'domain|ip' or cytomicobj.atttype_misp == 'hostname|port':
                    post_value = attribute['value'].split('|')[0]
                else:
                    post_value = attribute['value']

                if cytomicobj.atttype_misp == 'url' and 'http' not in post_value:
                    pass
                else:
                    if cytomicobj.post_data is None:
                        cytomicobj.post_data = [{cytomicobj.attlabel_cytomic: post_value}]
                    else:
                        cytomicobj.post_data.append({cytomicobj.attlabel_cytomic: post_value})
            else:
                if cytomicobject.debug:
                    print('Event %s skipped because of lower threat level' % event_id)
    except Exception:
        cytomicobj.error = True
        if cytomicobj.debug:
            sys.exit('Unable to process post-data')


def send_postdata(cytomicobj, evtid=None):
    # Batch post to upload event attributes.
    try:
        if cytomicobj.post_data is not None:
            if cytomicobj.debug:
                print('POST: {} {}'.format(cytomicobj.endpoint_ioc, cytomicobj.post_data))
            result_post_endpoint_ioc = requests.post(cytomicobj.endpoint_ioc, headers=cytomicobj.api_call_headers, json=cytomicobj.post_data, verify=False)
            json_result_post_endpoint_ioc = json.loads(result_post_endpoint_ioc.text)
            print(result_post_endpoint_ioc)
            if 'true' not in (result_post_endpoint_ioc.text):
                cytomicobj.error = True
                if evtid is not None:
                    if cytomicobj.res_msg['Event: ' + str(evtid)] is None:
                        cytomicobj.res_msg['Event: ' + str(evtid)] = '(Send POST data: errors uploading attributes, event NOT untagged). If the problem persists, please review the format of the value of the attributes is correct.'
                    else:
                        cytomicobj.res_msg['Event: ' + str(evtid)] = cytomicobj.res_msg['Event: ' + str(evtid)] + ' (Send POST data -else: errors uploading attributes, event NOT untagged). If the problem persists, please review the format of the value of the attributes is correct.'
            if cytomicobj.debug:
                print('RESULT: {}'.format(json_result_post_endpoint_ioc))
        else:
            if evtid is None:
                cytomicobj.error = True
    except Exception:
        cytomicobj.error = True
        if cytomicobj.debug:
            sys.exit('Unable to post attributes')


def process_attributes(cytomicobj, moduleconfig, evtid=None):
    # Get attributes to process.
    try:
        for misptype, cytomictypes in cytomicobject.att_types.items():
            cytomicobj.atttype_misp = misptype
            for cytomiclabel, cytomictype in cytomictypes.items():
                cytomicobj.attlabel_cytomic = cytomiclabel
                cytomicobj.atttype_cytomic = cytomictype
                cytomicobj.post_data = None
                icont = 0
                if cytomicobj.args.upload or cytomicobj.args.events:
                    cytomicobj.endpoint_ioc = moduleconfig['api_url'] + '/iocs/' + cytomicobj.atttype_cytomic + '?ttlDays=' + str(moduleconfig['upload_ttlDays'])
                else:
                    cytomicobj.endpoint_ioc = moduleconfig['api_url'] + '/iocs/eraser/' + cytomicobj.atttype_cytomic

                # Get attributes to upload/delete and prepare JSON
                # If evtid is set; we're called from --events
                if cytomicobject.debug:
                    print("\nSearching for attributes of type %s" % cytomicobj.atttype_misp)

                if evtid is None:
                    cytomicobj.error = False
                    attr_result = cytomicobj.misp.search(controller='attributes', last=moduleconfig['upload_timeframe'], limit=cytomicobj.limit_attributes, type_attribute=cytomicobj.atttype_misp, tag=cytomicobj.tag, published=True, deleted=False, includeProposals=False, include_context=True, to_ids=True)
                else:
                    if cytomicobj.error:
                        break
                    # We don't search with tags; we have an event for which we want to upload all events
                    attr_result = cytomicobj.misp.search(controller='attributes', eventid=evtid, last=moduleconfig['upload_timeframe'], limit=cytomicobj.limit_attributes, type_attribute=cytomicobj.atttype_misp, published=True, deleted=False, includeProposals=False, include_context=True, to_ids=True)

                cytomicobj.lst_attuuid = ['x', 'y']

                if len(attr_result['Attribute']) > 0:
                    for attribute in attr_result['Attribute']:
                        if evtid is not None:
                            if cytomicobj.error:
                                cytomicobj.res_msg['Event: ' + str(evtid)] = cytomicobj.res_msg['Event: ' + str(evtid)] + ' (errors uploading attributes, event NOT untagged). If the problem persists, please review the format of the value of the attributes is correct.'
                                break
                        if icont >= cytomicobj.limit_attributes:
                            if not cytomicobj.error and cytomicobj.post_data is not None:
                                # Send data to Cytomic
                                send_postdata(cytomicobj, evtid)
                            if not cytomicobj.error:
                                if 'Event: ' + str(evtid) in cytomicobj.res_msg:
                                    if cytomicobj.res_msg['Event: ' + str(evtid)] is None:
                                        cytomicobj.res_msg['Event: ' + str(evtid)] = cytomicobj.attlabel_cytomic + 's: ' + str(icont)
                                    else:
                                        cytomicobj.res_msg['Event: ' + str(evtid)] += ' | ' + cytomicobj.attlabel_cytomic + 's: ' + str(icont)
                                else:
                                    if cytomicobject.debug:
                                        print('Data sent (' + cytomicobj.attlabel_cytomic + '): ' + str(icont))

                                cytomicobj.post_data = None
                            if cytomicobj.error:
                                if evtid is not None:
                                    cytomicobj.res_msg['Event: ' + str(evtid)] = cytomicobj.res_msg['Event: ' + str(evtid)] + ' (errors uploading attributes, event NOT untagged). If the problem persists, please review the format of the value of the attributes is correct.'
                                break
                            icont = 0

                        if evtid is None:
                            event = attribute['Event']
                            event_id = event['id']
                            find_eventid(cytomicobj, str(event_id))
                            if not cytomicobj.res:
                                if not cytomicobj.lst_attuuid:
                                    cytomicobj.lst_attuuid = attribute['uuid']
                                else:
                                    if not attribute['uuid'] in cytomicobj.lst_attuuid:
                                        cytomicobj.lst_attuuid.append(attribute['uuid'])
                                icont += 1
                                # Prepare data to send
                                set_postdata(cytomicobj, moduleconfig, attribute)
                        else:
                            icont += 1
                            # Prepare data to send
                            set_postdata(cytomicobj, moduleconfig, attribute)

                    if not cytomicobj.error:
                        # Send data to Cytomic
                        send_postdata(cytomicobj, evtid)

                    if not cytomicobj.error and cytomicobj.post_data is not None and icont > 0:
                        # Data sent; process response
                        if cytomicobj.res_msg is not None and 'Event: ' + str(evtid) in cytomicobj.res_msg:
                            if cytomicobj.res_msg['Event: ' + str(evtid)] is None:
                                cytomicobj.res_msg['Event: ' + str(evtid)] = cytomicobj.attlabel_cytomic + 's: ' + str(icont)
                            else:
                                cytomicobj.res_msg['Event: ' + str(evtid)] += ' | ' + cytomicobj.attlabel_cytomic + 's: ' + str(icont)
                        else:
                            if cytomicobject.debug:
                                print('Data sent (' + cytomicobj.attlabel_cytomic + '): ' + str(icont))

                    if not cytomicobj.error:
                        cytomicobj.lst_attuuid.remove('x')
                        cytomicobj.lst_attuuid.remove('y')
                        # Untag attributes
                        untag_attributes(cytomicobj)
    except Exception:
        cytomicobj.error = True
        if cytomicobj.debug:
            sys.exit('Unable to get attributes')


def untag_event(evtid):
    # Remove tag of the event being processed.
    try:
        cytomicobj.records = 0
        evt = cytomicobj.misp.get_event(event=evtid, pythonify=True)
        if len(evt.tags) > 0:
            for tg in evt.tags:
                if tg.name == cytomicobj.tag:
                    cytomicobj.misp.untag(evt['uuid'], cytomicobj.tag)
                    cytomicobj.records += 1
                    cytomicobj.res_msg['Event: ' + str(evtid)] = cytomicobj.res_msg['Event: ' + str(evtid)] + ' (event untagged)'
                    break
    except Exception:
        cytomicobj.error = True
        if cytomicobj.debug:
            sys.exit('Unable to untag events')


def process_events(cytomicobj, moduleconfig):
    # Get events that contain Cytomic tag.
    try:
        collect_events_ids(cytomicobj, moduleconfig)
        total_attributes_sent = 0
        for evtid in cytomicobj.lst_evtid:
            cytomicobj.error = False
            if cytomicobj.res_msg is None:
                cytomicobj.res_msg = {'Event: ' + str(evtid): None}
            else:
                cytomicobj.res_msg['Event: ' + str(evtid)] = None
            if cytomicobject.debug:
                print('Event id: ' + str(evtid))

            # get attributes of each known type of the event / prepare data to send / send data to Cytomic
            process_attributes(cytomicobj, moduleconfig, evtid)
            if not cytomicobj.error:
                untag_event(evtid)
    except Exception:
        cytomicobj.error = True
        if cytomicobj.debug:
            sys.exit('Unable to process events ids')


def untag_attributes(cytomicobj):
    # Remove tag of attributes sent.
    try:
        icont = 0
        if len(cytomicobj.lst_attuuid) > 0:
            for uuid in cytomicobj.lst_attuuid:
                attr = cytomicobj.misp.get_attribute(attribute=uuid, pythonify=True)
                if len(attr.tags) > 0:
                    for tg in attr.tags:
                        if tg.name == cytomicobj.tag:
                            cytomicobj.misp.untag(uuid, cytomicobj.tag)
                            icont += 1
                            break
            print('Attributes untagged (' + str(icont) + ')')
    except Exception:
        cytomicobj.error = True
        if cytomicobj.debug:
            sys.exit('Unable to untag attributes')


def process_attributes_upload(cytomicobj, moduleconfig):
    # get attributes of each known type / prepare data to send / send data to Cytomic
    try:
        collect_events_ids(cytomicobj, moduleconfig)
        process_attributes(cytomicobj, moduleconfig)
    except Exception:
        cytomicobj.error = True
        if cytomicobj.debug:
            sys.exit('Unable to upload attributes to Cytomic')


def process_attributes_delete(cytomicobj, moduleconfig):
    # get attributes of each known type / prepare data to send / send data to Cytomic
    try:
        collect_events_ids(cytomicobj, moduleconfig)
        process_attributes(cytomicobj, moduleconfig)
    except Exception:
        cytomicobj.error = True
        if cytomicobj.debug:
            sys.exit('Unable to delete attributes in Cytomic')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Upload or delete indicators to Cytomic API')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--events', action='store_true', help='Upload events indicators')
    group.add_argument('--upload', action='store_true', help='Upload indicators')
    group.add_argument('--delete', action='store_true', help='Delete indicators')
    args = parser.parse_args()
    if not args.upload and not args.delete and not args.events:
        sys.exit("No valid action for the API")

    if misp_verifycert is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    module_config = get_config(misp_url, misp_key, misp_verifycert)
    cytomicobj = cytomicobject
    misp = PyMISP(misp_url, misp_key, misp_verifycert, debug=cytomicobject.debug)

    cytomicobj.misp = misp
    cytomicobj.args = args

    access_token = get_token(module_config['token_url'], module_config['clientid'], module_config['clientsecret'], module_config['scope'], module_config['grant_type'], module_config['username'], module_config['password'])
    cytomicobj.api_call_headers = {'Authorization': 'Bearer ' + access_token}
    if cytomicobj.debug:
        print('Received access token')

    if cytomicobj.args.events:
        cytomicobj.tag = module_config['upload_tag']
        cytomicobj.limit_events = module_config['limit_upload_events']
        cytomicobj.limit_attributes = module_config['limit_upload_attributes']
        process_events(cytomicobj, module_config)
        print_result_events(cytomicobj)

    elif cytomicobj.args.upload:
        cytomicobj.tag = module_config['upload_tag']
        cytomicobj.limit_events = 0
        cytomicobj.limit_attributes = module_config['limit_upload_attributes']
        process_attributes_upload(cytomicobj, module_config)

    else:
        cytomicobj.tag = module_config['delete_tag']
        cytomicobj.limit_events = 0
        cytomicobj.limit_attributes = module_config['limit_upload_attributes']
        process_attributes_delete(cytomicobj, module_config)
