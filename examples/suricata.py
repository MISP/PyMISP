#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import url_priv, key_priv
# from keys import url_cert, key_cert
import argparse


def init(url, key):
    return PyMISP(url, key, True, 'json')


def fetch(m, all_events, event):
    if all_events:
        print(misp.download_all_suricata().text)
    else:
        print(misp.download_suricata_rule_event(event).text)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Download Suricata events.')
    parser.add_argument("-a", "--all", action='store_true', help="Download all suricata rules available.")
    parser.add_argument("-e", "--event", help="Download suricata rules from one event.")

    args = parser.parse_args()

    misp = init(url_priv, key_priv)
    # misp = init(url_cert, key_cert)

    fetch(misp, args.all, args.event)
