#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 expandtab
# 
# Export file hashes from MISP to ClamAV hdb file

import sys
from pymisp import PyMISP
from keys import misp_url, misp_key

def init_misp():
    global mymisp
    mymisp = PyMISP(misp_url, misp_key)

def echeck(r):
    if r.get('errors'):
        if r.get('message') == 'No matches.':
            return
        else:
            print(r['errors'])
            sys.exit(1)

def find_hashes(htype):
    r = mymisp.search(type_attribute = htype)
    echeck(r)
    if r.get('response'):
        c = ''
        v = ''
        for e in r['response']:
            for a in e['Event']['Attribute']:
                if a['type'] == htype:
                    if '|' in htype and '|' in v:
                        s = v.split('|')
                        c = s[0]
                        v = s[1]
                    else:
                        c = a['comment']
                        v = a['value']
                    mhash = v.replace(':',';')
                    mfile = 'MISP event ' + e['Event']['id'] + ' ' + c.replace(':',';').replace('\r', '').replace('\n', '')
                    print('{}:*:{}:73'.format(mhash, mfile))

if __name__ == '__main__':
    init_misp()
    find_hashes('md5')
    find_hashes('sha1')
    find_hashes('sha256')
    find_hashes('filename|md5')
    find_hashes('filename|sha1')
    find_hashes('filename|sha256')
