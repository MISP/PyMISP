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
    parser = argparse.ArgumentParser(description='Create an event on MISP.')
    parser.add_argument("-d", "--distrib", type=int, help="The distribution setting used for the attributes and for the newly created event, if relevant. [0-3].")
    parser.add_argument("-i", "--info", help="Used to populate the event info field if no event ID supplied.")
    parser.add_argument("-a", "--analysis", type=int, help="The analysis level of the newly created event, if applicable. [0-2]")
    parser.add_argument("-t", "--threat", type=int, help="The threat level ID of the newly created event, if applicable. [1-4]")
    args = parser.parse_args()

    misp = init(misp_url, misp_key)

    event = misp.new_event(args.distrib, args.threat, args.analysis, args.info)
    print(event)
