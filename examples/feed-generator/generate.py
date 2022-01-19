#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import os
from pymisp import ExpandedPyMISP
from settings import url, key, ssl, outputdir, filters, valid_attribute_distribution_levels
try:
    from settings import with_distribution
except ImportError:
    with_distribution = False

try:
    from settings import with_local_tags
except ImportError:
    with_local_tags = True

try:
    from settings import include_deleted
except ImportError:
    include_deleted = False

try:
    from settings import exclude_attribute_types
except ImportError:
    exclude_attribute_types = []

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
        with open(os.path.join(outputdir, f'{event["Event"]["uuid"]}.json'), 'w') as f:
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
        events = misp.search_index(minimal=True, **filters, pythonify=False)
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
        try:
            e = misp.get_event(event['uuid'], deleted=include_deleted, pythonify=True)
            if exclude_attribute_types:
                for i, attribute in enumerate(e.attributes):
                    if attribute.type in exclude_attribute_types:
                        e.attributes.pop(i)
            e_feed = e.to_feed(valid_distributions=valid_attribute_distributions, with_meta=True, with_distribution=with_distribution, with_local_tags=with_local_tags)
        except Exception as err:
            print(err, event['uuid'])
            continue
        if not e_feed:
            print(f'Invalid distribution {e.distribution}, skipping')
            continue
        hashes += [[h, e.uuid] for h in e_feed['Event'].pop('_hashes')]
        manifest.update(e_feed['Event'].pop('_manifest'))
        saveEvent(e_feed)
        print("Event " + str(counter) + "/" + str(total) + " exported.")
        counter += 1
    saveManifest(manifest)
    print('Manifest saved.')
    saveHashes(hashes)
    print('Hashes saved. Feed creation completed.')
