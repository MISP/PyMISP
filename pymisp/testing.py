#!/usr/bin/python
# -*- coding: utf-8 -*-

from api import PyMISP

from keys import src, dest

url_source = 'https://misp.circl.lu'
url_dest = 'https://misppriv.circl.lu'
source = None
destination = None


def init():
    global source
    global destination
    source = PyMISP(url_source, src, 'xml')
    destination = PyMISP(url_dest, dest, 'xml')


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


def export_osint():
    # Warning: does not exports the samples/attachements
    osint = source.search(tags='OSINT')
    return _to_utf8(osint)


def list_copy(filename):
    with open(filename, 'r') as f:
        for l in f:
            l = int(l.strip())
            copy_event(l)

if __name__ == '__main__':
    init()
    list_copy('list')
