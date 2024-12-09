#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import ExpandedPyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse
import os


proxies = {
    'http': 'http://127.0.0.1:8123',
    'https': 'http://127.0.0.1:8123',
}

proxies = None


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Get an event from a MISP instance.')
    parser.add_argument("-e", "--event", required=True, help="Event ID to get.")
    parser.add_argument("-o", "--output", help="Output file")

    args = parser.parse_args()

    if args.output is not None and os.path.exists(args.output):
        print('Output file already exists, abort.')
        exit(0)

    misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert, proxies=proxies)

    event = misp.get_event(args.event, pythonify=True)
    if args.output:
        with open(args.output, 'w') as f:
            f.write(event.to_json())
    else:
        print(event.to_json())
