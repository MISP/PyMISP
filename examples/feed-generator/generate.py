#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import os
import hashlib
from pymisp import PyMISP
from settings import url, key, ssl, outputdir, filters, valid_attribute_distribution_levels

objectsFields = {
    'Attribute': {
        'uuid',
        'value',
        'category',
        'type',
        'comment',
        'data',
        'timestamp',
        'to_ids',
        'object_relation'
    },
    'Event': {
        'uuid',
        'info',
        'threat_level_id',
        'analysis',
        'timestamp',
        'publish_timestamp',
        'published',
        'date'
    },
    'Object': {
        'name',
        'meta-category',
        'description',
        'template_uuid',
        'template_version',
        'uuid',
        'timestamp',
        'distribution',
        'sharing_group_id',
        'comment'
    },
    'ObjectReference': {
        'uuid',
        'timestamp',
        'relationship_type',
        'comment',
        'object_uuid',
        'referenced_uuid'
    },
    'Orgc': {
        'name',
        'uuid'
    },
    'Tag': {
        'name',
        'colour',
        'exportable'
    }
}

objectsToSave = {
    'Orgc': {},
    'Tag': {},
    'Attribute': {
        'Tag': {}
    },
    'Object': {
        'Attribute': {
            'Tag': {}
        },
        'ObjectReference': {}
    }
}

valid_attribute_distributions = []

attributeHashes = []


def init():
    # If we have an old settings.py file then this variable won't exist
    global valid_attribute_distributions
    try:
        valid_attribute_distributions = valid_attribute_distribution_levels
    except Exception:
        valid_attribute_distributions = ['0', '1', '2', '3', '4', '5']
    return PyMISP(url, key, ssl)


def recursiveExtract(container, containerType, leaf, eventUuid):
    temp = {}
    if containerType in ['Attribute', 'Object']:
        if (__blockByDistribution(container)):
            return False
    for field in objectsFields[containerType]:
        if field in container:
            temp[field] = container[field]
    if (containerType == 'Attribute'):
        global attributeHashes
        if ('|' in container['type'] or container['type'] == 'malware-sample'):
            split = container['value'].split('|')
            attributeHashes.append([hashlib.md5(split[0].encode("utf-8")).hexdigest(), eventUuid])
            attributeHashes.append([hashlib.md5(split[1].encode("utf-8")).hexdigest(), eventUuid])
        else:
            attributeHashes.append([hashlib.md5(container['value'].encode("utf-8")).hexdigest(), eventUuid])
    children = leaf.keys()
    for childType in children:
        childContainer = container.get(childType)
        if (childContainer):
            if (type(childContainer) is dict):
                temp[childType] = recursiveExtract(childContainer, childType, leaf[childType], eventUuid)
            else:
                temp[childType] = []
                for element in childContainer:
                    processed = recursiveExtract(element, childType, leaf[childType], eventUuid)
                    if (processed):
                        temp[childType].append(processed)
    return temp


def saveEvent(misp, uuid):
    event = misp.get_event(uuid)
    if not event.get('Event'):
        print('Error while fetching event: {}'.format(event['message']))
        sys.exit('Could not create file for event ' + uuid + '.')
    event['Event'] = recursiveExtract(event['Event'], 'Event', objectsToSave, event['Event']['uuid'])
    event = json.dumps(event)
    eventFile = open(os.path.join(outputdir, uuid + '.json'), 'w')
    eventFile.write(event)
    eventFile.close()


def __blockByDistribution(element):
    if element['distribution'] not in valid_attribute_distributions:
        return True
    return False


def saveHashes():
    if not attributeHashes:
        return False
    try:
        hashFile = open(os.path.join(outputdir, 'hashes.csv'), 'w')
        for element in attributeHashes:
            hashFile.write('{},{}\n'.format(element[0], element[1]))
        hashFile.close()
    except Exception as e:
        print(e)
        sys.exit('Could not create the quick hash lookup file.')


def saveManifest(manifest):
    try:
        manifestFile = open(os.path.join(outputdir, 'manifest.json'), 'w')
        manifestFile.write(json.dumps(manifest))
        manifestFile.close()
    except Exception as e:
        print(e)
        sys.exit('Could not create the manifest file.')


def __addEventToManifest(event):
    tags = []
    for eventTag in event['EventTag']:
        tags.append({'name': eventTag['Tag']['name'],
                     'colour': eventTag['Tag']['colour']})
    return {'Orgc': event['Orgc'],
            'Tag': tags,
            'info': event['info'],
            'date': event['date'],
            'analysis': event['analysis'],
            'threat_level_id': event['threat_level_id'],
            'timestamp': event['timestamp']
            }


if __name__ == '__main__':
    misp = init()
    try:
        r = misp.get_index(filters)
        events = r['response']
        print(events[0])
    except Exception as e:
        print(e)
        sys.exit("Invalid response received from MISP.")
    if len(events) == 0:
        sys.exit("No events returned.")
    manifest = {}
    counter = 1
    total = len(events)
    for event in events:
        saveEvent(misp, event['uuid'])
        manifest[event['uuid']] = __addEventToManifest(event)
        print("Event " + str(counter) + "/" + str(total) + " exported.")
        counter += 1
    saveManifest(manifest)
    print('Manifest saved.')
    saveHashes()
    print('Hashes saved. Feed creation completed.')
