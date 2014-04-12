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

def copy_event(event_id):
    r_src = source.get_event(event_id)
    if 'json' in r_src.headers['content-type']:
        to_send = r_src.json()
    else:
        to_send = r_src.text.encode('utf-8')
    r_dst = destination.add_event(to_send)
    #print r_dst.text

if __name__ == '__main__':
    init()
    copy_event(0000)

