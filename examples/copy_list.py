#!/usr/bin/python
# -*- coding: utf-8 -*-


from pymisp import PyMISP

from keys import src, dest

url_source = 'https://misp.circl.lu'
url_dest = 'https://misppriv.circl.lu'
cert_source = 'misp.circl.lu.crt'
cert_dest = 'misppriv.circl.lu.crt'
source = None
destination = None


def init():
    global source
    global destination
    source = PyMISP(url_source, src, cert_source, 'xml')
    destination = PyMISP(url_dest, dest, cert_dest, 'xml')


def _to_utf8(request):
    to_return = None
    if 'json' in request.headers['content-type']:
        to_return = request.json()
    else:
        to_return = request.text.encode('utf-8')
    return to_return


def copy_event(event_id):
    r_src = source.get_event(event_id)
    to_send = _to_utf8(r_src)
    return destination.add_event(to_send)


def list_copy(filename):
    with open(filename, 'r') as f:
        for l in f:
            l = int(l.strip())
            print l
            copy_event(l)


def export_our_org():
    circl = source.search(org='CIRCL')
    return _to_utf8(circl)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(
        description='Copy the events from one MISP instance to an other.')
    parser.add_argument('-f', '--filename', type=str, required=True,
                        help='File containing a list of event id.')
    args = parser.parse_args()
    init()
    list_copy(args.filename)
