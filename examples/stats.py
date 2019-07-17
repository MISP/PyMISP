#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import ExpandedPyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Output attributes statistics from a MISP instance.')
    args = parser.parse_args()

    misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)

    print(misp.get_attributes_statistics(misp, percentage=True))
    print(misp.get_attributes_statistics(context='category', percentage=True))
