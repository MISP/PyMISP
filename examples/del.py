#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import ExpandedPyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Delete an event from a MISP instance.')
    parser.add_argument("-e", "--event", help="Event ID to delete.")
    parser.add_argument("-a", "--attribute", help="Attribute ID to delete.")

    args = parser.parse_args()

    misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)

    if args.event:
        result = misp.delete_event(args.event)
    else:
        result = misp.delete_attribute(args.attribute)
    print(result)
