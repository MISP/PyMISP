#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse
import os
import json


def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json')

    result = m.get_event(event)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get an event from a MISP instance.')
    parser.add_argument("-e", "--event", required=True, help="Event ID to get.")
    parser.add_argument("-a", "--attribute", help="Attribute ID to modify. A little dirty for now, argument need to be included in event")
    parser.add_argument("-t", "--tag", required=True, type=int, help="Attribute ID to modify.")
    parser.add_argument("-m", "--modify_attribute", action='store_true', help="If set, the tag will be add to the attribute, otherwise to the event.")

    args = parser.parse_args()

    misp = init(misp_url, misp_key)

    event = misp.get_event(args.event)
    if args.modify_attribute:
        for temp in event['Event']['Attribute']:
            if temp['id'] == args.attribute:
                attribute = temp
                break

        misp.add_tag(attribute, args.tag, attribute=True)
    else:
        misp.add_tag(event['Event'], args.tag)
