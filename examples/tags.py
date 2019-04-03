#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse
import json


def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json', True)


def get_tags(m):
    result = m.get_all_tags(True)
    r = result
    print(json.dumps(r) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get tags from MISP instance.')

    args = parser.parse_args()

    misp = init(misp_url, misp_key)

    get_tags(misp)
