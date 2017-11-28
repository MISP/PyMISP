#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
from pymisp.tools import load_openioc_file


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Convert an OpenIOC file to a MISPEvent. Optionnaly send it to MISP.')
    parser.add_argument("-i", "--input", required=True, help="Input file")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-o", "--output", help="Output file")
    group.add_argument("-m", "--misp", action='store_true', help="Create new event on MISP")

    args = parser.parse_args()

    misp_event = load_openioc_file(args.input)

    if args.misp:
        pymisp = PyMISP(misp_url, misp_key, misp_verifycert, debug=True)
        pymisp.add_event(misp_event)
    else:
        with open(args.output, 'w') as f:
            f.write(misp_event.to_json())
