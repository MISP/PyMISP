#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

from pymisp import PyMISP

from keys import cert, priv

url_cert = 'https://misp.circl.lu'
url_priv = 'https://misppriv.circl.lu'
cert_cert = 'misp.circl.lu.crt'
cert_priv = 'misppriv.circl.lu.crt'
source = None
destination = None


def init(cert_to_priv=True):
    global source
    global destination
    print(cert_to_priv)
    if cert_to_priv:
        source = PyMISP(url_cert, cert, cert_cert, 'xml')
        destination = PyMISP(url_priv, priv, cert_priv, 'xml')
    else:
        source = PyMISP(url_priv, priv, cert_priv, 'xml')
        destination = PyMISP(url_cert, cert, cert_cert, 'xml')


def copy_event(event_id):
    e = source.get_event(event_id)
    return destination.add_event(e)


def update_event(event_id, event_to_update):
    e = source.get_event(event_id)
    return destination.update_event(event_to_update, e)


def list_copy(filename):
    with open(filename, 'r') as f:
        for l in f:
            copy(l)


def loop_copy():
    while True:
        line = sys.stdin.readline()
        copy(line)


def copy(eventid):
    eventid = eventid.strip()
    if len(eventid) == 0 or not eventid.isdigit():
        print('empty line or NaN.')
        return
    eventid = int(eventid)
    print(eventid, 'copying...')
    r = copy_event(eventid)
    if r.status_code >= 400:
        loc = r.headers['location']
        if loc is not None:
            event_to_update = loc.split('/')[-1]
            print('updating', event_to_update)
            r = update_event(eventid, event_to_update)
            if r.status_code >= 400:
                print(r.status_code, r.headers)
        else:
            print(r.status_code, r.headers)
    print(eventid, 'done.')


def export_our_org():
    circl = source.search(org='CIRCL')
    return circl

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(
        description='Copy the events from one MISP instance to an other.')
    parser.add_argument('-f', '--filename', type=str,
                        help='File containing a list of event id.')
    parser.add_argument(
        '-l', '--loop', action='store_true',
        help='Endless loop: eventid in the terminal and it will be copied.')
    parser.add_argument('--priv_to_cert', action='store_false', default=True,
                        help='Copy from MISP priv to MISP CERT.')
    args = parser.parse_args()
    init(args.priv_to_cert)
    if args.filename is not None:
        list_copy(args.filename)
    else:
        loop_copy()
