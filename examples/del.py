#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key,misp_verifycert
import argparse


# Usage for pipe masters: ./last.py -l 5h | jq .


def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json', debug=True)


def del_event(m, eventid):
    result = m.delete_event(eventid)
    print(result)

def del_attr(m, attrid):
    result = m.delete_attribute(attrid)
    print(result)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Delete an event from a MISP instance.')
    parser.add_argument("-e", "--event", help="Event ID to delete.")
    parser.add_argument("-a", "--attribute", help="Attribute ID to delete.")

    args = parser.parse_args()

    misp = init(misp_url, misp_key)

    if args.event:
        del_event(misp, args.event)
    else:
        del_attr(misp, args.attribute)
