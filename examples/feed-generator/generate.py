#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import os
from pymisp import ExpandedPyMISP
from settings import url, key, ssl, outputdir, filters, valid_attribute_distribution_levels

valid_attribute_distributions = []


def init():
    # If we have an old settings.py file then this variable won't exist
    global valid_attribute_distributions
    try:
        valid_attribute_distributions = [int(v) for v in valid_attribute_distribution_levels]
    except Exception:
        valid_attribute_distributions = [0, 1, 2, 3, 4, 5]
    return ExpandedPyMISP(url, key, ssl)


def saveEvent(event):
    try:
        with open(os.path.join(outputdir, f'{event["uuid"]}.json'), 'w') as f:
            json.dump(event, f, indent=2)
    except Exception as e:
        print(e)
        sys.exit('Could not create the event dump.')


def saveHashes(hashes):
    try:
        with open(os.path.join(outputdir, 'hashes.csv'), 'w') as hashFile:
            for element in hashes:
                hashFile.write('{},{}\n'.format(element[0], element[1]))
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


if __name__ == '__main__':
    misp = init()
    try:
        events = misp.search(metadata=True, limit=200, **filters, pythonify=True)
    except Exception as e:
        print(e)
        sys.exit("Invalid response received from MISP.")
    if len(events) == 0:
        sys.exit("No events returned.")
    manifest = {}
    hashes = []
    counter = 1
    total = len(events)
    for event in events:
        e = misp.get_event(event.uuid, pythonify=True)
        e_feed = e.to_feed(valid_distributions=valid_attribute_distributions, with_meta=True)
        if not e_feed:
            print(f'Invalid distribution {e.distribution}, skipping')
            continue
        hashes += [[h, e.uuid] for h in e_feed.pop('_hashes')]
        manifest.update(e_feed.pop('_manifest'))
        saveEvent(e_feed)
        print("Event " + str(counter) + "/" + str(total) + " exported.")
        counter += 1
    saveManifest(manifest)
    print('Manifest saved.')
    saveHashes(hashes)
    print('Hashes saved. Feed creation completed.')
