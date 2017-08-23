#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from pymisp.tools import make_binary_objects
import traceback
from keys import misp_url, misp_key, misp_verifycert
import glob
import argparse
import json

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract indicators out of binaries and add MISP objects to a MISP instance.')
    parser.add_argument("-e", "--event", required=True, help="Event ID to update.")
    parser.add_argument("-p", "--path", required=True, help="Path to process (expanded using glob).")
    args = parser.parse_args()

    pymisp = PyMISP(misp_url, misp_key, misp_verifycert)

    for f in glob.glob(args.path):
        try:
            fo, peo, seos = make_binary_objects(f)
        except Exception as e:
            traceback.print_exc()

        if seos:
            for s in seos:
                obj, refs = s
                template_id = pymisp.get_object_template_id(obj['name'])
                r = pymisp.add_object(args.event, template_id, obj)

        if peo:
            obj, refs = peo
            template_id = pymisp.get_object_template_id(obj['name'])
            r = pymisp.add_object(args.event, template_id, obj)
            for ref in refs:
                r = pymisp.add_object_reference(obj['uuid'], ref)

        if fo:
            obj, refs = fo
            template_id = pymisp.get_object_template_id(obj['name'])
            response = pymisp.add_object(args.event, template_id, obj)
            for ref in refs:
                r = pymisp.add_object_reference(obj['uuid'], ref)
