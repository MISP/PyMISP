#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import ExpandedPyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse
import json


def get_tags(m):
    result = m.get_all_tags(True)
    r = result
    print(json.dumps(r) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get tags from MISP instance.')

    args = parser.parse_args()

    misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)

    tags = misp.tags(pythonify=True)
    for tag in tags:
        print(tag.to_json())
