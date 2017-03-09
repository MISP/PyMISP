#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key
import argparse

from io import open

# Usage for pipe masters: ./last.py -l 5h | jq .


def init(url, key):
    return PyMISP(url, key, True, 'json', debug=True)


def up_event(m, event, content):
    with open(content, 'r') as f:
        result = m.update_event(event, f.read())
    print(result)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get an event from a MISP instance.')
    parser.add_argument("-e", "--event", required=True, help="Event ID to get.")
    parser.add_argument("-i", "--input", required=True, help="Input file")

    args = parser.parse_args()

    misp = init(misp_url, misp_key)

    up_event(misp, args.event, args.input)
