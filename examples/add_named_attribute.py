#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key
import argparse

# For python2 & 3 compat, a bit dirty, but it seems to be the least bad one
try:
    input = raw_input
except NameError:
    pass


def init(url, key):
    return PyMISP(url, key, True, 'json', debug=True)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create an event on MISP.')
    parser.add_argument("-e", "--event", type=int, help="The id of the event to update.")
    parser.add_argument("-t", "--type", help="The type of the added attribute")
    parser.add_argument("-v", "--value", help="The value of the attribute")
    args = parser.parse_args()

    misp = init(misp_url, misp_key)

    event = misp.get_event(args.event)
    event = misp.add_named_attribute(event, args.type, args.value)
    print(event)
