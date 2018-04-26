#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Add a feed')
    parser.add_argument("-f", "--format", required=True, choices=['misp', 'csv', 'freetext'], help="Feed source format")
    parser.add_argument("-u", "--url", required=True, help="URL, or local path")
    parser.add_argument("-n", "--name", required=True, help="Name of the feed")
    parser.add_argument("-i", "--input", required=True, choices=['local', 'network'], help="URL, or local path")
    parser.add_argument("-p", "--provider", required=True, help="Provider name")
    args = parser.parse_args()

    pm = PyMISP(misp_url, misp_key, misp_verifycert, debug=True)
    response = pm.add_feed(args.format, args.url, args.name, args.input, args.provider)
    print(response)
