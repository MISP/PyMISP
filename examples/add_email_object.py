#!/usr/bin/env python3

from pymisp import PyMISP
from pymisp.tools import EMailObject
import traceback
from keys import misp_url, misp_key, misp_verifycert  # type: ignore
import glob
import argparse


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract indicators out of binaries and add MISP objects to a MISP instance.')
    parser.add_argument("-e", "--event", required=True, help="Event ID to update.")
    parser.add_argument("-p", "--path", required=True, help="Path to process (expanded using glob).")
    args = parser.parse_args()

    pymisp = PyMISP(misp_url, misp_key, misp_verifycert, debug=True)

    for f in glob.glob(args.path):
        try:
            eo = EMailObject(f)
        except Exception:
            traceback.print_exc()
            continue

        if eo:
            response = pymisp.add_object(args.event, eo, pythonify=True)
            for ref in eo.ObjectReference:
                r = pymisp.add_object_reference(ref)
