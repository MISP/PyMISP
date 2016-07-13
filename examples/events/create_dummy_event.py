#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse
import tools

def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create a given number of event containing an domain|ip attribute and an attachment each.')
    parser.add_argument("-l", "--limit", type=int, help="Number of events to create (default 1)")
    args = parser.parse_args()

    misp = init(misp_url, misp_key)

    if args.limit is None:
        args.limit = 1

    for i in range(args.limit):
        tools.create_dummy_event(misp)
