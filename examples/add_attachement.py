#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import priv
import argparse
import os
import glob
import base64
import json
import time

url = 'https://misppriv.circl.lu'


def init(url, key):
    return PyMISP(url, key, True, 'json')


def upload_file(m, eid, path):
    curevent = misp.get_event(eid)
    j = curevent.json()
    if j.get("Event"):
        with open(path, "rb") as curfile:
            j["Event"].update({"data": base64.b64encode(curfile.read())})
            j["Event"]["timestamp"] = int(time.time())
        out = misp.update_event(args.event, json.dumps(j))
    print out, out.text


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Send malware sample to MISP.')
    parser.add_argument("-u", "--upload", type=str, required=True, help="File or directory of files to upload.")
    parser.add_argument("-e", "--event", type=int, help="Event to update with a sample (if none, create a new event).")
    args = parser.parse_args()

    misp = init(url, priv)

    if os.path.isfile(args.upload):
        upload_file(misp, args.event, args.upload)
    elif os.path.isdir(args.upload):
        for filename in glob.iglob(os.path.join(args.upload + '*')):
            upload_file(misp, args.event, filename)
