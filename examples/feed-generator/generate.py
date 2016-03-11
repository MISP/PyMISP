#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import json
import os
from pymisp import PyMISP
from settings import url, key, ssl, outputdir, filters


objectsToSave = {
               'Orgc': {
                       'fields': ['name', 'uuid'],
                       'multiple': False,
                       },
               'Tag': {
                      'fields': ['name', 'colour', 'exportable'],
                      'multiple': True,
                      },
               'Attribute': {
                            'fields': ['uuid', 'value', 'category', 'type',
                                       'comment', 'data', 'timestamp',
                                       'to_ids'],
                            'multiple': True,
                            },
               }

fieldsToSave = ['uuid', 'info', 'threat_level_id', 'analysis',
                'timestamp', 'publish_timestamp', 'published',
                'date']


def init():
    return PyMISP(url, key, ssl, 'json')


def saveEvent(misp, uuid):
    try:
        event = misp.get_event(uuid)
        event = __cleanUpEvent(event)
        event = json.dumps(event)
        eventFile = open(os.path.join(outputdir, uuid + '.json'), 'w')
        eventFile.write(event)
        eventFile.close()
    except:
        sys.exit('Could not create file for event ' + uuid + '.')


def __cleanUpEvent(event):
        temp = event.json()
        event = {'Event': {}}
        __cleanupEventFields(event, temp)
        __cleanupEventObjects(event, temp)
        return event


def __cleanupEventFields(event, temp):
    for field in fieldsToSave:
        if field in temp['Event'].keys():
            event['Event'][field] = temp['Event'][field]
    return event


def __cleanupEventObjects(event, temp):
    for objectType in objectsToSave.keys():
        if objectsToSave[objectType]['multiple'] is True:
            if objectType in temp['Event']:
                for objectInstance in temp['Event'][objectType]:
                    tempObject = {}
                    for field in objectsToSave[objectType]['fields']:
                        if field in objectInstance.keys():
                            tempObject[field] = objectInstance[field]
                    if objectType not in event['Event']:
                        event['Event'][objectType] = []
                    event['Event'][objectType].append(tempObject)
        else:
            tempObject = {}
            for field in objectsToSave[objectType]['fields']:
                tempObject[field] = temp['Event'][objectType][field]
            event['Event'][objectType] = tempObject
    return event


def saveManifest(manifest):
    try:
        manifestFile = open(os.path.join(outputdir, 'manifest.json'), 'w')
        manifestFile.write(json.dumps(manifest))
        manifestFile.close()
    except:
        sys.exit('Could not create the manifest file.')


def __addEventToManifest(event):
    tags = []
    for eventTag in event['EventTag']:
        tags.append({'name': eventTag['Tag']['name'],
                     'colour': eventTag['Tag']['colour']})
    return {
            'Orgc': event['Orgc'],
            'Tag': tags,
            'info': event['info'],
            'date': event['date'],
            'analysis': event['analysis'],
            'threat_level_id': event['threat_level_id'],
            'timestamp': event['timestamp']
            }


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
    counter = 1
    total = len(events)
    for event in events:
        saveEvent(misp, event['uuid'])
        manifest[event['uuid']] = __addEventToManifest(event)
        print "Event " + str(counter) + "/" + str(total) + " exported."
        counter += 1
    saveManifest(manifest)
    print 'Manifest saved. Feed creation completed.'

