#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 expandtab
#
# Export file hashes from MISP to ClamAV hdb file

import sys
from pymisp import PyMISP, MISPAttribute
from keys import misp_url, misp_key, misp_verifycert


def init_misp():
    global mymisp
    mymisp = PyMISP(misp_url, misp_key, misp_verifycert)


def echeck(r):
    if r.get('errors'):
        if r.get('message') == 'No matches.':
            return
        else:
            print(r['errors'])
            sys.exit(1)


def find_hashes(htype):
    r = mymisp.search(controller='attributes', type_attribute=htype)
    echeck(r)
    if not r.get('response'):
        return
    for a in r['response']['Attribute']:
        attribute = MISPAttribute(mymisp.describe_types)
        attribute.from_dict(**a)
        if '|' in attribute.type and '|' in attribute.value:
            c, value = attribute.value.split('|')
            comment = '{} - {}'.format(attribute.comment, c)
        else:
            comment = attribute.comment
            value = attribute.value
        mhash = value.replace(':', ';')
        mfile = 'MISP event {} {}'.format(a['event_id'], comment.replace(':', ';').replace('\r', '').replace('\n', ''))
        print('{}:*:{}:73'.format(mhash, mfile))


if __name__ == '__main__':
    init_misp()
    find_hashes('md5')
    find_hashes('sha1')
    find_hashes('sha256')
    find_hashes('filename|md5')
    find_hashes('filename|sha1')
    find_hashes('filename|sha256')
