#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
https://github.com/raw-data/pymisp-suricata_search

    2017.06.28  start
    2017.07.03  fixed args.quiet and status msgs

"""

import argparse
import os
import queue
import sys
from threading import Thread, enumerate
from keys import misp_url, misp_key, misp_verifycert

try:
    from pymisp import PyMISP
except ImportError as err:
    sys.stderr.write("ERROR: {}\n".format(err))
    sys.stderr.write("\t[try] with pip install pymisp\n")
    sys.stderr.write("\t[try] with pip3 install pymisp\n")
    sys.exit(1)

HEADER = """
#This part might still contain bugs, use and your own risk and report any issues.
#
# MISP export of IDS rules - optimized for suricata
#
# These NIDS rules contain some variables that need to exist in your configuration.
# Make sure you have set:
#
# $HOME_NET	- Your internal network range
# $EXTERNAL_NET - The network considered as outside
# $SMTP_SERVERS - All your internal SMTP servers
# $HTTP_PORTS   - The ports used to contain HTTP traffic (not required with suricata export)
# 
"""

# queue for events matching searched term/s
IDS_EVENTS = queue.Queue()

# queue for downloaded Suricata rules
DOWNLOADED_RULES = queue.Queue()

# Default number of threads to use
THREAD = 4

try:
    input = raw_input
except NameError:
    pass


def init():
    """ init connection to MISP """
    return PyMISP(misp_url, misp_key, misp_verifycert, 'json')


def search(misp, quiet, noevent, **kwargs):
    """ Start search in MISP """

    result = misp.search(**kwargs)

    # fetch all events matching **kwargs
    track_events = 0
    skip_events = list()
    for event in result['response']:
        event_id = event["Event"].get("id")
        track_events += 1

        to_ids = False
        for attribute in event["Event"]["Attribute"]:
            to_ids_event = attribute["to_ids"]
            if to_ids_event:
                to_ids = True
                break

        # if there is at least one eligible event to_ids, add event_id
        if to_ids:
            # check if the event_id is not blacklisted by the user
            if isinstance(noevent, list):
                if event_id not in noevent[0]:
                    to_ids_event = (event_id, misp)
                    IDS_EVENTS.put(to_ids_event)
                else:
                    skip_events.append(event_id)
            else:
                to_ids_event = (event_id, misp)
                IDS_EVENTS.put(to_ids_event)

    if not quiet:
        print ("\t[i] matching events: {}".format(track_events))
        if len(skip_events) > 0:
            print ("\t[i] skipped {0} events -> {1}".format(len(skip_events),skip_events))
        print ("\t[i] events selected for IDS export: {}".format(IDS_EVENTS.qsize()))


def collect_rules(thread):
    """ Dispatch tasks to Suricata_processor worker """

    for x in range(int(thread)):
        th = Thread(target=suricata_processor, args=(IDS_EVENTS, ))
        th.start()

    for x in enumerate():
        if x.name == "MainThread":
            continue
        x.join()


def suricata_processor(ids_events):
    """ Trigger misp.download_suricata_rule_event """

    while not ids_events.empty():
        event_id, misp = ids_events.get()
        ids_rules = misp.download_suricata_rule_event(event_id).text

        for r in ids_rules.split("\n"):
            # skip header
            if not r.startswith("#"):
                if len(r) > 0: DOWNLOADED_RULES.put(r)


def return_rules(output, quiet):
    """ Return downloaded rules to user """

    rules = set()
    while not DOWNLOADED_RULES.empty():
        rules.add(DOWNLOADED_RULES.get())

    if output is None:

        if not quiet:
            print ("[+] Displaying rules")

        print (HEADER)
        for r in rules: print (r)
        print ("#")

    else:

        if not quiet:
            print ("[+] Writing rules to {}".format(output))
            print ("[+] Generated {} rules".format(len(rules)))

        with open(output, 'w') as f:
            f.write(HEADER)
            f.write("\n".join(r for r in rules))
            f.write("\n"+"#")


def format_request(param, term, misp, quiet, output, thread, noevent):
    """ Format request and start search """

    kwargs = {param: term}

    if not quiet:
        print ("[+] Searching for: {}".format(kwargs))

    search(misp, quiet, noevent, **kwargs)

    # collect Suricata rules
    collect_rules(thread)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description='Get all attributes that can be converted into Suricata rules, given a parameter and a term to '
                    'search.',
        epilog='''
        EXAMPLES:
            suricata_search.py -p tags -s 'APT' -o misp_ids.rules -t 5
            suricata_search.py -p tags -s 'APT' -o misp_ids.rules -ne 411 357 343
            suricata_search.py -p tags -s 'tlp:green, OSINT' -o misp_ids.rules
            suricata_search.py -p tags -s 'circl:incident-classification="malware", tlp:green' -o misp_ids.rules
            suricata_search.py -p categories -s 'Artifacts dropped' -t 20 -o artifacts_dropped.rules
        ''')
    parser.add_argument("-p", "--param", required=True, help="Parameter to search (e.g. categories, tags, org, etc.).")
    parser.add_argument("-s", "--search", required=True, help="Term/s to search.")
    parser.add_argument("-q", "--quiet", action='store_true', help="No status messages")
    parser.add_argument("-t", "--thread", required=False, help="Number of threads to use", default=THREAD)
    parser.add_argument("-ne", "--noevent", nargs='*', required=False, dest='noevent', action='append',
                        help="Event/s ID to exclude during the search")
    parser.add_argument("-o", "--output", help="Output file",required=False)

    args = parser.parse_args()

    if args.output is not None and os.path.exists(args.output) and not args.quiet:
        try:
            check = input("[!] Output file {} exists, do you want to continue [Y/n]? ".format(args.output))
            if check not in ["Y","y"]:
                exit(0)
        except KeyboardInterrupt:
            sys.exit(0)

    if not args.quiet:
        print ("[i] Connecting to MISP instance: {}".format(misp_url))
        print ("[i] Note: duplicated IDS rules will be removed")

    # Based on # of terms, format request
    if "," in args.search:
        for term in args.search.split(","):
            term = term.strip()
            misp = init()
            format_request(args.param, term, misp, args.quiet, args.output, args.thread, args.noevent)
    else:
        misp = init()
        format_request(args.param, args.search, misp, args.quiet, args.output, args.thread, args.noevent)

    # return collected rules
    return_rules(args.output, args.quiet)
