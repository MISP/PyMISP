#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    Python script to extract network activity from MISP database

    Koen Van Impe       20141116
        netflow         20150804
    Feed it a list of event_id's (1 id per line) with the option "-f".
    Use --no-comment to get a flat list of entries without event id and title information

    Usage
        ./get_network_activity.py --netflow --event 8
            get netflow filter for event 8

        ./get_network_activity.py -f get_network_activity.event_id --netflow
            get netflow filter for events in id file

        ./get_network_activity.py -f get_network_activity.event_id
            get output with comments
"""

from pymisp import PyMISP

from keys import misp_key
from keys import misp_url
from keys import misp_verifycert

source = None


def init():
    """
    Initialize PyMISP
    Get configuration settings from config file
    """
    global source
    source = PyMISP(misp_url, misp_key, misp_verifycert, 'json')


def get_event(event_id):
    """
    Get details of an event and add it to the result arrays
    :event_id   the id of the event
    """
    global network_ip_src, network_ip_dst, network_hostname, network_domain
    global app_hostname, app_domain, app_ip_src, app_ip_dst, app_ids_only, app_printcomment, app_netflow

    event_id = int(event_id)
    if event_id > 0:
        event_json = source.get_event(event_id)
        event_core = event_json["Event"]
        # event_threatlevel_id = event_core["threat_level_id"]

        # attribute_count = event_core["attribute_count"]
        attribute = event_core["Attribute"]

        for attribute in event_core["Attribute"]:
            if app_ids_only and not attribute["to_ids"]:
                continue

            value = attribute["value"]
            title = event_core["info"]
            if app_netflow:
                app_printcomment = False
                if attribute["type"] == "ip-dst" and app_ip_dst:
                    network_ip_dst.append([build_entry(value, event_id, title, "ip-dst")])
            else:
                if attribute["type"] == "ip-src" and app_ip_src:
                    network_ip_src.append([build_entry(value, event_id, title, "ip-src")])
                elif attribute["type"] == "ip-dst" and app_ip_dst:
                    network_ip_dst.append([build_entry(value, event_id, title, "ip-dst")])
                elif attribute["type"] == "domain" and app_domain:
                    network_domain.append([build_entry(value, event_id, title, "domain")])
                elif attribute["type"] == "hostname" and app_hostname:
                    network_hostname.append([build_entry(value, event_id, title, "hostname")])
                else:
                    continue
    else:
        print("Not a valid ID")
        return


def build_entry(value, event_id, title, source):
    """
    Build the line containing the entry

        :value      the datavalue of the entry
        :event_id   id of the event
        :title      name of the event
        :source     from which set was the entry retrieved
    """
    global app_printcomment

    if app_printcomment:
        if app_printtitle:
            return "%s # Event: %s / %s (from %s) " % (value, event_id, title, source)
        else:
            return "%s # Event: %s (from %s) " % (value, event_id, source)
    else:
        return value


def print_events():
    """
    Print the events from the result arrays
    """
    global network_ip_src, network_ip_dst, network_domain, network_hostname
    global app_hostname, app_domain, app_ip_src, app_ip_dst, app_ids_only, app_printcomment, app_printtitle, app_netflow

    if app_netflow:
        firsthost = True
        for ip in network_ip_dst:
            if firsthost:
                firsthost = False
            else:
                print(" or ")
            print("host %s" % ip[0])
    else:
        if app_ip_src:
            for ip in network_ip_src:
                print(ip[0])
        if app_ip_dst:
            for ip in network_ip_dst:
                print(ip[0])
        if app_domain:
            for ip in network_domain:
                print(ip[0])
        if app_hostname:
            for ip in network_hostname:
                print(ip[0])


if __name__ == '__main__':
    import argparse

    network_ip_src = []
    network_ip_dst = []
    network_domain = []
    network_hostname = []

    parser = argparse.ArgumentParser(
        description='Download network activity information from MISP.')
    parser.add_argument('-f', '--filename', type=str,
                        help='File containing a list of event id.')
    parser.add_argument('--hostname', action='store_true', default=False,
                        help='Include hostnames.')
    parser.add_argument('--no-ip-src', action='store_true', default=False,
                        help='Do not include ip-src.')
    parser.add_argument('--no-ip-dst', action='store_true', default=False,
                        help='Do not include ip-dst.')
    parser.add_argument('--domain', action='store_true', default=False,
                        help='Include domains.')
    parser.add_argument('--no-comment', action='store_false', default=True,
                        help='Do not include comment in the output.')
    parser.add_argument('--no-ids-only', action='store_true', default=False,
                        help='Include IDS and non-IDS attribures.')
    parser.add_argument('--no-titles', action='store_true', default=False,
                        help='Do not include titles')
    parser.add_argument('--netflow', action='store_true', default=False,
                        help='Netflow (nfdump) output')
    parser.add_argument('--event', type=int, default=0,
                        help='EventID to parse (not using filename)')
    args = parser.parse_args()

    init()
    app_printcomment = args.no_comment
    app_hostname = args.hostname
    app_domain = args.domain
    app_ip_src = not(args.no_ip_src)
    app_ip_dst = not(args.no_ip_dst)
    app_ids_only = args.no_ids_only
    app_printtitle = not(args.no_titles)
    app_netflow = args.netflow
    app_event = args.event

    if app_event > 0:
        get_event(app_event)
        print_events()
    elif args.filename is not None:
        # print "app_printcomment %s app_hostname %s app_domain %s app_ip_src %s app_ip_dst %s app_ids_only %s app_printtitle %s" % (app_printcomment,app_hostname, app_domain, app_ip_src, app_ip_dst, app_ids_only, app_printtitle)
        with open(args.filename, 'r') as line:
            for event_id in line:
                get_event(event_id.strip())
        print_events()
    else:
        print("No filename given, stopping.")
