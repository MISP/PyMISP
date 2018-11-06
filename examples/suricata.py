#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse


def init(url, key):
    return PyMISP(url, key, misp_verifycert)


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

    misp = init(misp_url, misp_key)

    fetch(misp, args.all, args.event)
