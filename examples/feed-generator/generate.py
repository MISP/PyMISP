#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import json
import os
from pymisp import PyMISP
from settings import url, key, ssl, outputdir, filters


def init():
    return PyMISP(url, key, ssl, 'json')


def saveEvent(misp, uuid):
    try:
        event = misp.get_event(uuid)
        eventFile = open(os.path.join(outputdir, uuid + '.json'), 'w')
        eventFile.write(event.text)
        eventFile.close()
    except:
        sys.exit('Could not create the manifest file.')


def saveManifest(manifest):
    try:
        manifestFile = open(os.path.join(outputdir, 'manifest.json'), 'w')
        manifestFile.write(json.dumps(manifest))
        manifestFile.close()
    except:
        sys.exit('Could not create the manifest file.')

if __name__ == '__main__':
    misp = init()
    result = misp.get_index(None, filters)
    try:
        events = result.json()
    except:
        sys.exit("Invalid response received from MISP.")
    if len(events) == 0:
        sys.exit("No events returned.")
    manifest = {}
    for event in events:
        manifest[event['uuid']] = event['timestamp']
        saveEvent(misp, event['uuid'])
    saveManifest(manifest)
    print str(len(manifest)) + ' events exported.'

