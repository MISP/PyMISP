#!/usr/bin/env python
# -*- coding: utf-8 -*-

from keys import misp_url, misp_key, misp_verifycert
import argparse
from pymisp import PyMISP

# For python2 & 3 compat, a bit dirty, but it seems to be the least bad one
try:
    input = raw_input
except NameError:
    pass
    
def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json', debug=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Fetch all events from a feed.')
    parser.add_argument("-f", "--feed", required=True, help="feed's ID to be fetched.")
    args = parser.parse_args()
    
    misp = init(misp_url, misp_key)
    misp.fetch_feed(args.feed)
