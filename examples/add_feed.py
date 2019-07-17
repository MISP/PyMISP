#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import ExpandedPyMISP, MISPFeed
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

    pm = ExpandedPyMISP(misp_url, misp_key, misp_verifycert, debug=True)
    feed = MISPFeed()
    feed.format = args.format
    feed.url = args.url
    feed.name = args.name
    feed.input = args.input
    feed.provider = args.provider
    response = pm.add_feed(feed, pythonify=True)
    print(response.to_json())
