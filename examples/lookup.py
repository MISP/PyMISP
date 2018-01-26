#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp.tools import ext_lookups
import argparse


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Search is galaxies or taxonomies.')
    parser.add_argument("-q", "--query", help="Query.")

    args = parser.parse_args()

    tag_gal = ext_lookups.revert_tag_from_galaxies(args.query)
    tag_tax = ext_lookups.revert_tag_from_taxonomies(args.query)

    found_tax = ext_lookups.search_taxonomies(args.query)
    found_gal = ext_lookups.search_galaxies(args.query)

    if tag_gal:
        print(tag_gal)
    if tag_tax:
        print(tag_tax)
    if found_tax:
        print(found_tax)
    if found_gal:
        print(found_gal)
