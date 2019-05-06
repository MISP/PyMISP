#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Koen Van Impe

VMRay automatic import
Put this script in crontab to run every /15 or /60
    */5 *    * * *   mispuser   /usr/bin/python3 /home/mispuser/PyMISP/examples/vmray_automation.py

Calls "vmray_import" for all events that have an 'incomplete' VMray analysis

Do inline config in "main"

'''

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse
import os
import json
import datetime
import time

import requests
import sys

# Suppress those "Unverified HTTPS request is being made"
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def init(url, key):
    '''
        Template to get MISP module started
    '''
    return PyMISP(url, key, misp_verifycert, 'json')


def get_vmray_config(url, key, misp_verifycert, default_wait_period):
    '''
        Fetch configuration settings from MISP
        Includes VMRay API and modules URL
    '''

    try:
        misp_headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': key}
        req = requests.get(url + 'servers/serverSettings.json', verify=misp_verifycert, headers=misp_headers)

        if req.status_code == 200:
            req_json = req.json()
            if 'finalSettings' in req_json:
                finalSettings = req_json['finalSettings']
                vmray_api = ''
                vmray_url = ''
                vmray_wait_period = 0

                for el in finalSettings:
                    # Is the vmray import module enabled?
                    if el['setting'] == 'Plugin.Import_vmray_import_enabled':
                        vmray_import_enabled = el['value']
                        if vmray_import_enabled is False:
                            break
                    # Get the VMRay API key from the MISP settings
                    elif el['setting'] == 'Plugin.Import_vmray_import_apikey':
                        vmray_api = el['value']
                    # The VMRay URL to query
                    elif el['setting'] == 'Plugin.Import_vmray_import_url':
                        vmray_url = el['value'].replace('/', '\\/')
                    # MISP modules - Port?
                    elif el['setting'] == 'Plugin.Import_services_port':
                        module_import_port = el['value']
                    # MISP modules - URL
                    elif el['setting'] == 'Plugin.Import_services_url':
                        module_import_url = el['value'].replace('\/\/', '//')
                    # Wait period
                    elif el['setting'] == 'Plugin.Import_vmray_import_wait_period':
                        vmray_wait_period = abs(int(el['value']))

                if vmray_wait_period < 1:
                    vmray_wait_period = default_wait_period
        else:
            sys.exit('Did not receive a 200 code from MISP')

        if vmray_import_enabled and vmray_api and vmray_url and module_import_port and module_import_url:
            return {'vmray_wait_period': vmray_wait_period, 'vmray_api': vmray_api, 'vmray_url': vmray_url, 'module_import_port': module_import_port, 'module_import_url': module_import_url}
        else:
            sys.exit('Did not receive all the necessary configuration information from MISP')

    except Exception as e:
        sys.exit('Unable to get VMRay config from MISP')


def search_vmray_incomplete(m, url, wait_period, module_import_url, module_import_port, vmray_url, vmray_api, vmray_attribute_category, vmray_include_analysisid, vmray_include_imphash_ssdeep, vmray_include_extracted_files, vmray_include_analysisdetails, vmray_include_vtidetails, custom_tags_incomplete, custom_tags_complete):
    '''
       Search for the events with VMRay samples that are marked incomplete
       and then update these events
    '''

    controller = 'attributes'
    vmray_value = 'VMRay Sample ID:'  # How sample IDs are stored in MISP
    req = None

    # Search for the events
    try:
        result = m.search(controller, tags=custom_tags_incomplete)
        response = result['response']

        if len(response) == 0:
            sys.exit("No VMRay attributes found that match %s" % custom_tags_incomplete)

        attribute = response['Attribute']

        if len(attribute) == 0:
            sys.exit("No VMRay attributes found that match %s" % custom_tags_incomplete)

        timestamp = int(attribute[0]["timestamp"])
        # Not enough time has gone by to lookup the analysis jobs
        if int((time.time() - timestamp) / 60) < int(wait_period):
            if module_DEBUG:
                r_timestamp = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                print("Attribute to recent for wait_period (%s minutes) - timestamp attribute: %s (%s minutes old)" % (wait_period, r_timestamp, round((int(time.time() - timestamp) / 60), 2)))
            return False

        if module_DEBUG:
            print("All attributes older than %s" % int(wait_period))

        for att in attribute:
            value = att['value']

            if vmray_value in value:        # We found a sample ID
                att_id = att['id']
                att_uuid = att['uuid']

                # VMRay Sample IDs are stored as VMRay Sample ID: 2796577
                vmray_sample_id = value.split(vmray_value)[1].strip()
                if vmray_sample_id.isdigit():
                    event_id = att['event_id']
                    if module_DEBUG:
                        print("Found event %s with matching tags %s for sample id %s " % (event_id, custom_tags_incomplete, vmray_sample_id))

                    # Prepare request to send to vmray_import via misp modules
                    misp_modules_url = module_import_url + ':' + module_import_port + '/query'
                    misp_modules_headers = {'Content-Type': 'application/json'}
                    misp_modules_body = '{ "sample_id":"' + vmray_sample_id + '","module":"vmray_import","event_id":"' + event_id + '","config":{"apikey":"' + vmray_api + '","url":"' + vmray_url + '","include_analysisid":"' + vmray_include_analysisid + '","include_analysisdetails":"' + vmray_include_analysisdetails + '","include_extracted_files":"' + vmray_include_extracted_files + '","include_imphash_ssdeep":"' + vmray_include_imphash_ssdeep + '","include_vtidetails":"' + vmray_include_vtidetails + '","sample_id":"' + vmray_sample_id + '"},"data":""}'
                    req = requests.post(misp_modules_url, data=misp_modules_body, headers=misp_modules_headers)
                    if module_DEBUG and req is not None:
                        print("Response code from submitting to MISP modules %s" % (req.status_code))

                    # Succesful response from the misp modules?
                    if req.status_code == 200:
                        req_json = req.json()
                        if "error" in req_json:
                            print("Error code in reply %s " % req_json["error"])
                            continue
                        else:
                            results = req_json["results"]

                            # Walk through all results in the misp-module reply
                            for el in results:
                                to_ids = True
                                values = el['values']
                                types = el['types']
                                if "to_ids" in el:
                                    to_ids = el['to_ids']
                                if "text" in types:
                                    to_ids = False
                                comment = el['comment']
                                if len(comment) < 1:
                                    comment = "Enriched via the vmray_import module"

                                # Attribute can belong in different types
                                for type in types:
                                    try:
                                        r = m.add_named_attribute(event_id, type, values, vmray_attribute_category, to_ids, comment)
                                        if module_DEBUG:
                                            print("Add event %s: %s as %s (%s) (toids: %s)" % (event_id, values, type, comment, to_ids))
                                    except Exception as e:
                                        continue
                                        if module_DEBUG:
                                            print("Unable to add attribute %s as type %s for event %s" % (values, type, event_id))

                            # Remove 'incomplete' state tags
                            m.untag(att_uuid, custom_tags_incomplete)
                            # Update tags to 'complete' state
                            m.tag(att_uuid, custom_tags_complete)
                            if module_DEBUG:
                                print("Updated event %s" % event_id)

                    else:
                        sys.exit('MISP modules did not return HTTP 200 code (event %s ; sampleid %s)' % (event_id, vmray_sample_id))

    except Exception as e:
        sys.exit("Invalid response received from MISP : %s", e)


if __name__ == '__main__':

    module_DEBUG = True

    # Set some defaults to be used in this module
    vmray_attribute_category = 'External analysis'
    vmray_include_analysisid = '0'
    vmray_include_imphash_ssdeep = '0'
    vmray_include_extracted_files = '0'
    vmray_include_analysisdetails = '0'
    vmray_include_vtidetails = '0'
    custom_tags_incomplete = 'workflow:state="incomplete"'
    custom_tags_complete = 'workflow:state="complete"'
    default_wait_period = 30

    misp = init(misp_url, misp_key)
    vmray_config = get_vmray_config(misp_url, misp_key, misp_verifycert, default_wait_period)
    search_vmray_incomplete(misp, misp_url, vmray_config['vmray_wait_period'], vmray_config['module_import_url'], vmray_config['module_import_port'], vmray_config['vmray_url'], vmray_config['vmray_api'], vmray_attribute_category, vmray_include_analysisid, vmray_include_imphash_ssdeep, vmray_include_extracted_files, vmray_include_analysisdetails, vmray_include_vtidetails, custom_tags_incomplete, custom_tags_complete)
