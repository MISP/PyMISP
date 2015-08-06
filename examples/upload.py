#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import url_priv, key_priv
# from keys import url_cert, key_cert
import argparse
import os
import glob


def init(url, key):
    return PyMISP(url, key, True, 'json')


def upload_files(m, eid, paths, distrib, ids, categ, info, analysis, threat):
    out = m.upload_samplelist(paths, eid, distrib, ids, categ, info, analysis, threat)
    if out.status_code == 200:
        print("Files uploaded sucessfully")
    else:
        print("Something failed: {}".format(out.text))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Send malware sample to MISP.')
    parser.add_argument("-u", "--upload", type=str, required=True, help="File or directory of files to upload.")
    parser.add_argument("-e", "--event", type=int, help="Not supplying an event ID will cause MISP to create a single new event for all of the POSTed malware samples.")
    parser.add_argument("-d", "--distrib", type=int, help="The distribution setting used for the attributes and for the newly created event, if relevant. [0-3].")
    parser.add_argument("-ids", action='store_true', help="You can flag all attributes created during the transaction to be marked as \"to_ids\" or not.")
    parser.add_argument("-c", "--categ", help="The category that will be assigned to the uploaded samples. Valid options are: Payload delivery, Artifacts dropped, Payload Installation, External Analysis.")
    parser.add_argument("-i", "--info", help="Used to populate the event info field if no event ID supplied.")
    parser.add_argument("-a", "--analysis", type=int, help="The analysis level of the newly created event, if applicatble. [0-2]")
    parser.add_argument("-t", "--threat", type=int, help="The threat level ID of the newly created event, if applicatble. [0-3]")
    args = parser.parse_args()

    misp = init(url_priv, key_priv)
    # misp = init(url_cert, key_cert)

    files = []
    if os.path.isfile(args.upload):
        files = [args.upload]
    elif os.path.isdir(args.upload):
        files = [f for f in glob.iglob(os.path.join(args.upload + '*'))]
    else:
        print('invalid file')
        exit(0)

    upload_files(misp, args.event, files, args.distrib, args.ids, args.categ, args.info, args.analysis, args.threat)
