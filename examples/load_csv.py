#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from pathlib import Path

from pymisp.tools import CSVLoader

from pymisp import MISPEvent

try:
    from keys import misp_url, misp_key, misp_verifycert
    from pymisp import ExpandedPyMISP
    offline = False
except ImportError as e:
    offline = True
    print(f'Unable to import MISP parameters, unable to POST on MISP: {e}')

'''
Example:
* If the CSV file has fieldnames matching the object-relation:

    load_csv.py -n file -p /tmp/foo.csv

* If you want to force the fieldnames:

    load_csv.py -n file -p /tmp/foo.csv -f SHA1 fileName size-in-bytes
'''


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Load a CSV file as MISP objects')
    parser.add_argument("-n", "--object_name", type=str, required=True, help="Template name of the objects in the CSV.")
    parser.add_argument("-p", "--path", required=True, type=Path, help="Path to the CSV file.")
    parser.add_argument("-f", "--fieldnames", nargs='*', default=[], help="Fieldnames of the CSV, have to match the object-relation allowed in the template. If empty, the fieldnames of the CSV have to match the template.")
    parser.add_argument("-s", "--skip_fieldnames", action='store_true', help="Skip fieldnames in the CSV.")
    parser.add_argument("-d", "--dump", action='store_true', help="(Debug) Dump the object in the terminal.")

    # Interact with MISP
    misp_group = parser.add_mutually_exclusive_group()
    misp_group.add_argument('-i', '--new_event', type=str, help="Info field of the new event")
    misp_group.add_argument('-u', '--update_event', type=int, help="ID of the existing event to update")

    args = parser.parse_args()

    if not args.fieldnames:
        has_fieldnames = True
    else:
        has_fieldnames = args.skip_fieldnames
    csv_loader = CSVLoader(template_name=args.object_name, csv_path=args.path,
                           fieldnames=args.fieldnames, has_fieldnames=has_fieldnames)

    objects = csv_loader.load()
    if args.dump:
        for o in objects:
            print(o.to_json())
    else:
        if offline:
            print('You are in offline mode, quitting.')
        else:
            misp = ExpandedPyMISP(url=misp_url, key=misp_key, ssl=misp_verifycert)
            if args.new_event:
                event = MISPEvent()
                event.info = args.new_event
                for o in objects:
                    event.add_object(**o)
                new_event = misp.add_event(event)
                if isinstance(new_event, str):
                    print(new_event)
                elif 'id' in new_event:
                    print(f'Created new event {new_event.id}')
                else:
                    print('Something went wrong:')
                    print(new_event)
            else:
                for o in objects:
                    new_object = misp.add_object(args.update_event, o)
                    if isinstance(new_object, str):
                        print(new_object)
                    elif new_object.attributes:
                        print(f'New {new_object.name} object added to {args.update_event}')
                    else:
                        print('Something went wrong:')
                        print(new_event)
