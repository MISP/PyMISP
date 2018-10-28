#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse

# For python2 & 3 compat, a bit dirty, but it seems to be the least bad one
try:
    input = raw_input
except NameError:
    pass


def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json', debug=True)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Add an attribute to an event')
    parser.add_argument("-e", "--event", help="The id, uuid or json of the event to update.")
    parser.add_argument("-t", "--type", help="The type of the added attribute")
    parser.add_argument("-v", "--value", help="The value of the attribute")
    args = parser.parse_args()

    misp = init(misp_url, misp_key)

    event = misp.add_named_attribute(args.event, args.type, args.value)
    print(event)
