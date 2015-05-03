#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
    Python script to extract network activity from MISP database

    Koen Van Impe       20141116

    Feed it a list of event_id's (1 id per line) with the option "-f".
    Use --no-comment to get a flat list of entries without event id and title information
    
"""    

import sys
import json
from pymisp import PyMISP

from cudeso import misp_key
from cudeso import misp_url
from cudeso import misp_verifycert


"""
    Initialize PyMISP

        Get configuration settings from config file

"""
def init():
    global source    
    source = PyMISP(misp_url, misp_key, misp_verifycert, 'json')


"""
    Get details of an event and add it to the result arrays

        :event_id   the id of the event

"""
def get_event(event_id):
    global network_ip_src, network_ip_dst, network_hostname, network_domain
    global app_hostname, app_domain, app_ip_src, app_ip_dst, app_ids_only

    event_id = int(event_id)
    if event_id > 0:
        event = source.get_event(event_id)
        if event.status_code == 200:

            try:
                event_json = event.json()
            except:
                return False

            event_core = event_json["Event"]
            event_threatlevel_id = event_core["threat_level_id"] 

            attribute_count = event_core["attribute_count"]
            attribute = event_core["Attribute"]

            for attribute in event_core["Attribute"]:
                if app_ids_only == True and attribute["to_ids"] == False:
                    continue
                
                value = attribute["value"]
                title = event_core["info"]
                if attribute["type"] == "ip-src" and app_ip_src == True:
                    network_ip_src.append( [ build_entry(value, event_id, title, "ip-src") ])
                elif attribute["type"] == "ip-dst" and app_ip_dst == True:
                    network_ip_dst.append( [ build_entry(value, event_id, title, "ip-dst") ])
                elif attribute["type"] == "domain" and app_domain == True:
                    network_domain.append( [ build_entry(value, event_id, title, "domain") ])
                elif attribute["type"] == "hostname" and app_hostname == True:
                    network_hostname.append( [ build_entry( value, event_id, title, "hostname") ])
                else:
                    continue
    else:
        print("Not a valid ID")
        return        


"""
    Build the line containing the entry

        :value      the datavalue of the entry
        :event_id   id of the event 
        :title      name of the event 
        :source     from which set was the entry retrieved

"""        
def build_entry( value, event_id , title, source ):
    global app_printcomment

    if app_printcomment == True:
        if app_printtitle == True:
            return "%s # Event: %s / %s (from %s) " % ( value, event_id , title, source )
        else:
            return "%s # Event: %s (from %s) " % ( value, event_id , source )
    else:
        return value


"""
    Print the events from the result arrays

"""    
def print_events():
    global network_ip_src, network_ip_dst, network_domain, network_hostname
    global app_hostname, app_domain, app_ip_src, app_ip_dst, app_ids_only, app_printcomment, app_printtitle

    if app_ip_src == True:
        for ip in network_ip_src:
            print(ip[0])
    if app_ip_dst == True:
        for ip in network_ip_dst:
            print(ip[0])
    if app_domain == True:
        for ip in network_domain:
            print(ip[0])
    if app_hostname == True:
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
    args = parser.parse_args()
    
    if args.filename is not None:
        init()
        app_printcomment = args.no_comment
        app_hostname = args.hostname
        app_domain = args.domain
        app_ip_src = not(args.no_ip_src)
        app_ip_dst = not(args.no_ip_dst)
        app_ids_only = args.no_ids_only
        app_printtitle = not(args.no_titles)
        # print "app_printcomment %s app_hostname %s app_domain %s app_ip_src %s app_ip_dst %s app_ids_only %s app_printtitle %s" % (app_printcomment,app_hostname, app_domain, app_ip_src, app_ip_dst, app_ids_only, app_printtitle)
        with open(args.filename, 'r') as line:
            for event_id in line:
                get_event( event_id.strip() )
        print_events()
    else:
        print("No filename given, stopping.")

