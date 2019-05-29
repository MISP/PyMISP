#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Koen Van Impe

Sync sightings between MISP instances

Put this script in crontab to run every /15 or /60
    */5 *    * * *   mispuser   /usr/bin/python3 /home/mispuser/PyMISP/examples/sync_sighting.py

Uses a drift file to keep track of latest timestamp synced (config)
Install on "clients", these push the sightings back to authoritative MISP instance

'''

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
from keys import misp_authoritive_url, misp_authoritive_key, misp_authoritive_verifycert

import sys
import time


def init(url, key, verifycert):
    '''
        Template to get MISP module started
    '''
    return PyMISP(url, key, verifycert, 'json')


def search_sightings(misp, timestamp, timestamp_now):
    '''
        Search all the local sightings
        Extend the sighting with the attribute UUID
    '''
    completed_sightings = []

    try:
        found_sightings = misp.search_sightings(date_from=timestamp, date_to=timestamp_now)
    except Exception as e:
        sys.exit("Unable to search for sightings")

    if found_sightings is not None and 'response' in found_sightings:
        for s in found_sightings['response']:
            if 'Sighting' in s:
                sighting = s['Sighting']
                if 'attribute_id' in sighting:
                    attribute_id = sighting['attribute_id']

                    # Query the attribute to get the uuid
                    # We need this to update the sighting on the other instance
                    try:
                        attribute = misp.get_attribute(attribute_id)
                    except Exception as e:
                        if module_DEBUG:
                            print("Unable to fetch attribute UUID for ID %s " % attribute_id)
                        continue

                    if 'Attribute' in attribute and 'uuid' in attribute['Attribute']:
                        attribute_uuid = attribute['Attribute']['uuid']
                        completed_sightings.append({'attribute_uuid': attribute_uuid, 'date_sighting': sighting['date_sighting'], 'source': sighting['source'], 'type': sighting['type'], 'uuid': sighting['uuid']})
                    else:
                        if module_DEBUG:
                            print("No information returned for attribute ID %s " % attribute_id)
                        continue

    return completed_sightings


def sync_sightings(misp, misp_authoritive, found_sightings, verify_before_push, custom_sighting_text):
    '''
        Walk through all the sightings
    '''
    if found_sightings is not None:
        for sighting in found_sightings:
            attribute_uuid = sighting['attribute_uuid']
            date_sighting = sighting['date_sighting']
            source = sighting['source']
            if not source:
                source = custom_sighting_text
            type = sighting['type']

            # Fail safe
            if verify_before_push:
                if sighting_exists(misp_authoritive, sighting):
                    continue
                else:
                    continue
            else:
                push_sighting(misp_authoritive, attribute_uuid, date_sighting, source, type)
                continue
        return True
    return False


def push_sighting(misp_authoritive, attribute_uuid, date_sighting, source, type):
    '''
        Push sighting to the authoritative server
    '''
    if attribute_uuid:
        try:
            misp_authoritive.sighting(uuid=attribute_uuid, source=source, type=type, timestamp=date_sighting)
            if module_DEBUG:
                print("Pushed sighting for %s on %s" % (attribute_uuid, date_sighting))
            return True
        except Exception as e:
            if module_DEBUG:
                print("Unable to update attribute %s " % (attribute_uuid))
            return False


def sighting_exists(misp_authoritive, sighting):
    '''
        Check if the sighting exists on the authoritative server
            sightings/restSearch/attribute for uuid is not supported in MISP

            optionally to implement
    '''
    return False


def set_drift_timestamp(drift_timestamp, drift_timestamp_path):
    '''
        Save the timestamp in a (local) file
    '''
    try:
        with open(drift_timestamp_path, 'w+') as f:
            f.write(str(drift_timestamp))
        return True
    except IOError:
        sys.exit("Unable to write drift_timestamp %s to %s" % (drift_timestamp, drift_timestamp_path))
        return False


def get_drift_timestamp(drift_timestamp_path):
    '''
        From when do we start with the sightings?
    '''
    try:
        with open(drift_timestamp_path) as f:
            drift = f.read()
            if drift:
                drift = int(float(drift))
            else:
                drift = 0
    except IOError:
        drift = 0

    return drift


if __name__ == '__main__':
    misp = init(misp_url, misp_key, misp_verifycert)
    misp_authoritive = init(misp_authoritive_url, misp_authoritive_key, misp_authoritive_verifycert)
    drift_timestamp_path = '/home/mispuser/PyMISP/examples/sync_sighting.drift'

    drift_timestamp = get_drift_timestamp(drift_timestamp_path=drift_timestamp_path)
    timestamp_now = time.time()
    module_DEBUG = True

    # Get all attribute sightings
    found_sightings = search_sightings(misp, drift_timestamp, timestamp_now)
    if found_sightings is not None and len(found_sightings) > 0:
        if sync_sightings(misp, misp_authoritive, found_sightings, verify_before_push=False, custom_sighting_text="Custom Sighting"):
            set_drift_timestamp(timestamp_now, drift_timestamp_path)
            if module_DEBUG:
                print("Sighting drift file updated to %s " % (timestamp_now))
        else:
            sys.exit("Unable to sync sync_sightings")
    else:
        sys.exit("No sightings found")
