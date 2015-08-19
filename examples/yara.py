#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import url_priv, key_priv
# from keys import url_cert, key_cert
import argparse
import os


def init(url, key):
    return PyMISP(url, key, True, 'json')


def get_yara(m, event_id, out=None):
    ok, rules = m.get_yara(event_id)
    if not ok:
        print(rules)
    elif out is None:
        print(rules)
    else:
        with open(out, 'w') as f:
            f.write(rules)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get yara rules from an event.')
    parser.add_argument("-e", "--event", required=True, help="Event ID.")
    parser.add_argument("-o", "--output", help="Output file")

    args = parser.parse_args()

    if args.output is not None and os.path.exists(args.output):
        print('Output file already exists, abord.')
        exit(0)

    misp = init(url_priv, key_priv)
    # misp = init(url_cert, key_cert)

    get_yara(misp, args.event, args.output)
