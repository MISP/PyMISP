#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse


def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Output attributes statistics from a MISP instance.')
    args = parser.parse_args()

    misp = init(misp_url, misp_key)

    print (misp.get_attributes_statistics(misp, percentage=True))
    print (misp.get_attributes_statistics(context='category', percentage=True))
