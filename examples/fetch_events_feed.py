#!/usr/bin/env python
# -*- coding: utf-8 -*-

from keys import misp_url, misp_key, misp_verifycert
import argparse
from pymisp import ExpandedPyMISP


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Fetch all events from a feed.')
    parser.add_argument("-f", "--feed", required=True, help="feed's ID to be fetched.")
    args = parser.parse_args()

    misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)
    misp.fetch_feed(args.feed)
