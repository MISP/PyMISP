#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse
import os

SILENT = False


def getTagToApplyToEvent(event):
    tags_to_apply = set()

    event_tags = { tag.name for tag in event.tags }
    for galaxy in event.galaxies:
        for cluster in galaxy.clusters:
            event_tags.add(cluster.tag_name)

    for attribute in event.attributes:
        for attribute_tag in attribute.tags:
            if attribute_tag.name not in event_tags:
                tags_to_apply.add(attribute_tag.name)

    return tags_to_apply


def TagEvent(event, tags_to_apply):
    for tag in tags_to_apply:
        event.add_tag(tag)
    return event


def condPrint(text):
    if not SILENT:
        print(text)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get an event from a MISP instance.')
    parser.add_argument("-e", "--event", required=True, help="Event ID to get.")
    parser.add_argument("-y", "--yes", required=False, default=False, action='store_true',  help="Automatically accept prompt.")
    parser.add_argument("-s", "--silent", required=False, default=False, action='store_true', help="No output to stdin.")

    args = parser.parse_args()
    SILENT = args.silent

    misp = PyMISP(misp_url, misp_key, misp_verifycert)

    event = misp.get_event(args.event, pythonify=True)
    tags_to_apply = getTagToApplyToEvent(event)
    condPrint('Tag to apply at event level:')
    for tag in tags_to_apply:
        condPrint(f'- {tag}')

    confirmed = False
    if args.yes:
        confirmed = True
    else:
        confirm = input('Confirm [Y/n]: ')
        confirmed = len(confirm) == 0 or confirm == 'Y' or confirm == 'y'
    if confirmed:
        event = TagEvent(event, tags_to_apply)
        condPrint(f'Updating event {args.event}')
        misp.update_event(event)
        condPrint(f'Event {args.event} tagged with {len(tags_to_apply)} tags')
    else:
        condPrint('Operation cancelled')
