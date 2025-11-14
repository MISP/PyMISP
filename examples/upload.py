#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pymisp import PyMISP, MISPEvent, MISPAttribute
from keys import misp_url, misp_key, misp_verifycert
import argparse
from pathlib import Path

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Send malware sample to MISP.')
    parser.add_argument("-u", "--upload", type=str, required=True, help="File or directory of files to upload.")
    parser.add_argument("-d", "--distrib", type=int, help="The distribution setting used for the attributes and for the newly created event, if relevant. [0-3].")
    parser.add_argument("-c", "--comment", type=str, help="Comment for the uploaded file(s).")
    parser.add_argument('-m', '--is-malware', action='store_true', help='The file(s) to upload are malwares')
    parser.add_argument('--expand', action='store_true', help='(Only if the file is a malware) Run lief expansion (creates objects)')
    parser.add_argument("-e", "--event", type=int, default=None, help="Not supplying an event ID will cause MISP to create a single new event for all of the POSTed malware samples.")
    parser.add_argument("-i", "--info", help="Used to populate the event info field if no event ID supplied.")
    args = parser.parse_args()

    misp = PyMISP(misp_url, misp_key, misp_verifycert)

    files = []
    p = Path(args.upload)
    if p.is_file():
        files = [p]
    elif p.is_dir():
        files = [f for f in p.glob('**/*') if f.is_file()]
    else:
        print('invalid upload path (must be file or dir)')
        exit(0)

    if args.is_malware:
        arg_type = 'malware-sample'
    else:
        arg_type = 'attachment'

    # Create attributes
    attributes = []
    for f in files:
        a = MISPAttribute()
        a.type = arg_type
        a.value = f.name
        a.data = f
        a.comment = args.comment
        a.distribution = args.distrib
        if args.expand and arg_type == 'malware-sample':
            a.expand = 'binary'
        attributes.append(a)

    if args.event:
        for a in attributes:
            misp.add_attribute(args.event, a)
    else:
        m = MISPEvent()
        m.info = args.info
        m.distribution = args.distrib
        m.attributes = attributes
        if args.expand and arg_type == 'malware-sample':
            m.run_expansions()
        misp.add_event(m)
