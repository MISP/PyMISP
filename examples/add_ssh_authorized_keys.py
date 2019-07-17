#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pymisp import ExpandedPyMISP
from pymisp.tools import SSHAuthorizedKeysObject
import traceback
from keys import misp_url, misp_key, misp_verifycert
import glob
import argparse


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract indicators out of authorized_keys file.')
    parser.add_argument("-e", "--event", required=True, help="Event ID to update.")
    parser.add_argument("-p", "--path", required=True, help="Path to process (expanded using glob).")
    args = parser.parse_args()

    pymisp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert, debug=True)

    for f in glob.glob(args.path):
        try:
            auth_keys = SSHAuthorizedKeysObject(f)
        except Exception:
            traceback.print_exc()
            continue

        response = pymisp.add_object(args.event, auth_keys)
        for ref in auth_keys.ObjectReference:
            r = pymisp.add_object_reference(ref)
