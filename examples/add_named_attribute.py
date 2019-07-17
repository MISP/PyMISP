#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import ExpandedPyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse

# For python2 & 3 compat, a bit dirty, but it seems to be the least bad one
try:
    input = raw_input
except NameError:
    pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Add an attribute to an event')
    parser.add_argument("-e", "--event", help="The id, uuid or json of the event to update.")
    parser.add_argument("-t", "--type", help="The type of the added attribute")
    parser.add_argument("-v", "--value", help="The value of the attribute")
    args = parser.parse_args()

    misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)

    event = misp.add_attribute(args.event, {'type': args.type, 'value': args.value}, pythonify=True)
    print(event)
