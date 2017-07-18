#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse


def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get an attachment.')
    parser.add_argument("-a", "--attribute", type=int, help="Attribute ID to download.")
    args = parser.parse_args()

    misp = init(misp_url, misp_key)

    with open('foo', 'wb') as f:
        out = misp.get_attachment(args.attribute)
        if isinstance(out, dict):
            # Fails
            print(out)
        else:
            f.write(out)
