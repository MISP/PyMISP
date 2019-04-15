#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from pymisp.tools.mimetypeobject import MIMETypeObject

import traceback
from keys import misp_url, misp_key, misp_verifycert
import glob
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract metadata out of file and add MISP object to a MISP instance.')
    parser.add_argument("-e", "--event", required=True, help="Event ID to update.")
    parser.add_argument("-p", "--path", required=True, help="Path to file (expanded using glob).")
    args = parser.parse_args()

    pymisp = PyMISP(misp_url, misp_key, misp_verifycert)

    for f in glob.glob(args.path):
        try:
            mispObject = MIMETypeObject(filepath=f)
        except Exception as e:
            traceback.print_exc()
            continue

        if mispObject:
            r = pymisp.add_object(args.event, mispObject)

