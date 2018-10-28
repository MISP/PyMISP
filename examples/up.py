#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse

from io import open

def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json', debug=True)

def up_event(m, event, content):
    with open(content, 'r') as f:
        result = m.update_event(event, f.read())
    print(result)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Update a MISP event.")
    parser.add_argument("-e", "--event", required=True, help="Event ID to update.")
    parser.add_argument("-i", "--input", required=True, help="Input file")

    args = parser.parse_args()

    misp = init(misp_url, misp_key)

    up_event(misp, args.event, args.input)
