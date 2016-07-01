#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse
import tools

def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create a given number of event containing a given number of attributes eachh.')
    parser.add_argument("-l", "--limit", type=int, help="Number of events to create (default 1)")
    parser.add_argument("-a", "--attribute", type=int, help="Number of attributes per event (default 3000)")
    args = parser.parse_args()

    misp = init(misp_url, misp_key)

    if args.limit is None:
        args.limit = 1
    if args.attribute is None:
        args.attribute = 3000

    for i in range(args.limit):
        tools.create_massive_dummy_events(misp, args.attribute)
